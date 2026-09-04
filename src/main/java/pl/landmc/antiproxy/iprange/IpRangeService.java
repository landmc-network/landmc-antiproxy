package pl.landmc.antiproxy.iprange;

import com.velocitypowered.api.plugin.PluginContainer;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import pl.landmc.antiproxy.config.AntiProxyConfig;

/**
 * Blocks addresses that appear on published proxy, Tor or hosting lists.
 *
 * <p>Answers from local data, so it runs before any paid API call - which is the point of
 * having it. It is also on the login path, and that shapes the whole class.
 *
 * <p>The blocks are kept in one array sorted by where each begins, and a lookup is a binary
 * search. These lists run to tens of thousands of entries; walking them per connection is work
 * proportional to the size of the list on every single login, which is exactly the shape this
 * network's rules say to index away.
 *
 * <p>Refreshing uses the proxy's own scheduler rather than a thread of its own. One list that
 * reloads every few hours does not justify a dedicated thread, and a plugin that starts its
 * own pools is how a process ends up with a dozen of them.
 */
public final class IpRangeService {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /** Below five minutes a refresh is pointless: these lists are published hourly at best. */
    private static final long MINIMUM_REFRESH_MINUTES = 5L;

    private final ProxyServer proxy;
    private final PluginContainer plugin;
    private final Logger logger;
    private final AntiProxyConfig.IpRange config;
    private final boolean enabled;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(REQUEST_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    /** Per source, so one list failing to load does not drop the others. */
    private final Map<String, List<IpCidrRange>> bySource = new ConcurrentHashMap<>();

    /** Every block from every source, sorted; replaced wholesale, never mutated in place. */
    private volatile IpCidrRange[] sorted = new IpCidrRange[0];

    private final List<ScheduledTask> tasks = new ArrayList<>();

    public IpRangeService(
            ProxyServer proxy,
            PluginContainer plugin,
            Logger logger,
            AntiProxyConfig.IpRange config) {

        this.proxy = Objects.requireNonNull(proxy, "proxy");
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.config = Objects.requireNonNull(config, "config");
        this.enabled = config.enabled && !config.sources.isEmpty();
    }

    /** Schedules the first load and the periodic refresh of every configured source. */
    public void start() {
        if (!this.enabled) {
            return;
        }

        for (AntiProxyConfig.IpRange.Source source : this.config.sources) {
            long minutes = Math.max(MINIMUM_REFRESH_MINUTES, source.refreshMinutes);

            this.tasks.add(this.proxy.getScheduler()
                    .buildTask(this.plugin.getInstance().orElseThrow(), () -> this.refresh(source))
                    .repeat(minutes, TimeUnit.MINUTES)
                    .schedule());
        }

        this.logger.info("IP range blocking enabled with {} source(s).", this.config.sources.size());
    }

    /**
     * Whether the address falls in any blocked range.
     *
     * <p>Binary search over a sorted array: the candidate is the last block that starts at or
     * before the address, and blocks do not overlap in practice - a list that does contain
     * overlaps costs at most a miss on the outer one.
     */
    public boolean contains(InetAddress address) {
        IpCidrRange[] ranges = this.sorted;
        if (ranges.length == 0) {
            return false;
        }

        BigInteger value = new BigInteger(1, address.getAddress());
        int index = Arrays.binarySearch(
                ranges, new IpCidrRange(value, value), IpCidrRange::compareTo);

        // An exact hit means a block begins at this address; otherwise the insertion point is
        // one past the block that could contain it.
        int candidate = index >= 0 ? index : -index - 2;
        return candidate >= 0 && ranges[candidate].contains(value);
    }

    public void shutdown() {
        this.tasks.forEach(ScheduledTask::cancel);
        this.tasks.clear();
    }

    /** How many blocks are loaded, for the startup log and {@code /antiproxy}. */
    public int size() {
        return this.sorted.length;
    }

    /**
     * Re-reads one source.
     *
     * <p>Runs on a scheduler thread and blocks on the HTTP call deliberately: that thread
     * exists to wait, and an asynchronous client here would only add a callback to a task that
     * has nothing else to do.
     */
    private void refresh(AntiProxyConfig.IpRange.Source source) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(source.url))
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();

            HttpResponse<String> response =
                    this.httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() != 200) {
                this.logger.warn("IP range source '{}' returned HTTP {}.", source.name, response.statusCode());
                return;
            }

            List<IpCidrRange> parsed = parse(response.body(), source.name, this.logger);
            this.bySource.put(source.name, parsed);
            this.rebuild();

            this.logger.info("Loaded {} range(s) from '{}'.", parsed.size(), source.name);
        }
        catch (IOException | IllegalArgumentException exception) {
            this.logger.warn("Could not refresh IP range source '{}'", source.name, exception);
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    /** Parses one list, skipping what it cannot read rather than losing the whole file. */
    private static List<IpCidrRange> parse(String body, String sourceName, Logger logger) {
        List<IpCidrRange> ranges = new ArrayList<>();
        int skipped = 0;

        for (String line : body.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }

            try {
                ranges.add(IpCidrRange.parse(trimmed));
            }
            catch (Exception exception) {
                skipped++;
            }
        }

        if (skipped > 0) {
            logger.debug("Skipped {} unreadable line(s) in '{}'.", skipped, sourceName);
        }
        return ranges;
    }

    /**
     * Rebuilds the sorted array from every source.
     *
     * <p>A new array replaces the old one in a single assignment, so a lookup running at the
     * same time sees either the whole previous list or the whole new one - never a half-sorted
     * array being written under it.
     */
    private void rebuild() {
        List<IpCidrRange> all = new ArrayList<>();
        this.bySource.values().forEach(all::addAll);
        Collections.sort(all);

        this.sorted = all.toArray(IpCidrRange[]::new);
    }
}
