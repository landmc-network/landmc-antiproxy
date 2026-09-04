package pl.landmc.antiproxy.iprange;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import pl.landmc.antiproxy.config.AntiProxyConfig;

public final class IpRangeService {

    private final Logger logger;
    private final boolean enabled;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ScheduledExecutorService scheduler;
    private final Map<String, List<IpCidrRange>> perSourceRanges = new ConcurrentHashMap<>();
    private volatile List<IpCidrRange> allRanges = List.of();

    public IpRangeService(Logger logger, AntiProxyConfig.IpRange config) {
        this.logger = logger;
        this.enabled = config.enabled && !config.sources.isEmpty();
        if (!this.enabled) {
            this.scheduler = null;
            return;
        }

        this.scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "skytop-antiproxy-iprange");
            thread.setDaemon(true);
            return thread;
        });
        for (AntiProxyConfig.IpRange.Source source : config.sources) {
            long periodMinutes = Math.max(5, source.refreshMinutes);
            this.scheduler.scheduleWithFixedDelay(() -> this.refresh(source), 0, periodMinutes, TimeUnit.MINUTES);
        }
    }

    public boolean contains(InetAddress address) {
        if (!this.enabled) {
            return false;
        }
        BigInteger value = new BigInteger(1, address.getAddress());
        for (IpCidrRange range : this.allRanges) {
            if (range.contains(value)) {
                return true;
            }
        }
        return false;
    }

    public void shutdown() {
        if (this.scheduler != null) {
            this.scheduler.shutdownNow();
        }
    }

    private void refresh(AntiProxyConfig.IpRange.Source source) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(source.url))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();
            HttpResponse<String> response =
                    this.httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                this.logger.warn("IpRange source '{}' returned HTTP {}.", source.name, response.statusCode());
                return;
            }

            List<IpCidrRange> parsed = new ArrayList<>();
            for (String line : response.body().split("\\R")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                try {
                    parsed.add(IpCidrRange.parse(trimmed));
                }
                catch (RuntimeException | java.net.UnknownHostException exception) {
                    // Malformed line in a third-party list; skip it.
                }
            }
            this.perSourceRanges.put(source.name, parsed);
            this.rebuildRanges();
            this.logger.info("IpRange source '{}' loaded {} ranges.", source.name, parsed.size());
        }
        catch (Exception exception) {
            this.logger.warn(
                    "Could not refresh IpRange source '{}' ({}).",
                    source.name,
                    exception.getClass().getSimpleName());
        }
    }

    private void rebuildRanges() {
        List<IpCidrRange> merged = new ArrayList<>();
        for (List<IpCidrRange> ranges : this.perSourceRanges.values()) {
            merged.addAll(ranges);
        }
        this.allRanges = List.copyOf(merged);
    }
}
