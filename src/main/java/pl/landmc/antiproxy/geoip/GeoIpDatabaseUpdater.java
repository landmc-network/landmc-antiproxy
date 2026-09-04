package pl.landmc.antiproxy.geoip;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import com.velocitypowered.api.plugin.PluginContainer;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import pl.landmc.antiproxy.config.AntiProxyConfig;

/**
 * Downloads and periodically refreshes the GeoLite2-ASN/Country .mmdb files from MaxMind using a
 * license key, so the databases GeoIpLookupService reads never need to be updated by hand. MaxMind
 * only serves them as a .tar.gz containing a dated folder - this pulls out just the .mmdb entry.
 */
public final class GeoIpDatabaseUpdater {

    private static final String DOWNLOAD_URL_TEMPLATE =
            "https://download.maxmind.com/app/geoip_download?edition_id={EDITION}&license_key={KEY}&suffix=tar.gz";
    private static final String ASN_EDITION = "GeoLite2-ASN";
    private static final String COUNTRY_EDITION = "GeoLite2-Country";
    private static final int TAR_BLOCK_SIZE = 512;

    private final Logger logger;
    private final String licenseKey;
    private final File dataDirectory;
    private final AntiProxyConfig.GeoIp config;
    private final Runnable onUpdated;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    private final ProxyServer proxy;
    private final PluginContainer plugin;

    private @Nullable ScheduledTask task;

    public GeoIpDatabaseUpdater(
            ProxyServer proxy,
            PluginContainer plugin,
            Logger logger,
            String licenseKey,
            File dataDirectory,
            AntiProxyConfig.GeoIp config,
            Runnable onUpdated) {

        this.proxy = Objects.requireNonNull(proxy, "proxy");
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.licenseKey = Objects.requireNonNull(licenseKey, "licenseKey");
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory");
        this.config = Objects.requireNonNull(config, "config");
        this.onUpdated = Objects.requireNonNull(onUpdated, "onUpdated");
    }

    /**
     * Downloads now, then every configured number of hours.
     *
     * <p>Runs on the proxy's scheduler rather than a thread of its own. A download every day or
     * two does not justify a dedicated thread, and the proxy already stops its scheduler
     * cleanly on shutdown - which a plugin's own executor has to be remembered to do.
     *
     * <p>GeoLite2 is published about twice a week, so checking much more often than daily only
     * costs MaxMind bandwidth and gets nothing back.
     */
    public void start() {
        long hours = Math.max(1, this.config.autoUpdate.refreshHours);

        this.task = this.proxy.getScheduler()
                .buildTask(this.plugin.getInstance().orElseThrow(), this::refreshAll)
                .repeat(hours, TimeUnit.HOURS)
                .schedule();
    }

    public void shutdown() {
        if (this.task != null) {
            this.task.cancel();
            this.task = null;
        }
    }

    /**
     * Fetches both databases and tells the lookup service when either changed.
     *
     * <p>Blocks on the HTTP calls on purpose: this runs on a scheduler thread whose whole job
     * is to wait for them, and an asynchronous client would only add callbacks to a task with
     * nothing else to do.
     */
    private void refreshAll() {
        boolean asnUpdated =
                this.downloadEdition(ASN_EDITION, new File(this.dataDirectory, this.config.asnDatabasePath));
        boolean countryUpdated =
                this.downloadEdition(COUNTRY_EDITION, new File(this.dataDirectory, this.config.countryDatabasePath));
        if (asnUpdated || countryUpdated) {
            this.onUpdated.run();
        }
    }

    private boolean downloadEdition(String editionId, File targetFile) {
        String url = DOWNLOAD_URL_TEMPLATE.replace("{EDITION}", editionId).replace("{KEY}", this.licenseKey);
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(60))
                    .GET()
                    .build();
            HttpResponse<InputStream> response =
                    this.httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                this.logger.warn("MaxMind download for {} returned HTTP {}.", editionId, response.statusCode());
                return false;
            }

            byte[] mmdbContent;
            try (GZIPInputStream gzipStream = new GZIPInputStream(response.body())) {
                mmdbContent = extractMmdbEntry(gzipStream);
            }
            if (mmdbContent == null) {
                this.logger.warn("MaxMind archive for {} did not contain an .mmdb file.", editionId);
                return false;
            }

            File temporaryFile = new File(targetFile.getParentFile(), targetFile.getName() + ".tmp");
            Files.write(temporaryFile.toPath(), mmdbContent);
            Files.move(
                    temporaryFile.toPath(),
                    targetFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            this.logger.info("Updated MaxMind {} database ({} bytes).", editionId, mmdbContent.length);
            return true;
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return false;
        }
        catch (IOException | RuntimeException exception) {
            this.logger.warn(
                    "Could not update MaxMind {} database: {}", editionId, exception.getMessage());
            return false;
        }
    }

    static byte[] extractMmdbEntry(InputStream tarStream) throws IOException {
        byte[] header = new byte[TAR_BLOCK_SIZE];
        while (readFully(tarStream, header) == TAR_BLOCK_SIZE && !isAllZero(header)) {
            String name = tarEntryName(header);
            long size = parseOctal(header, 124, 12);
            long paddedSize = ((size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;

            if (name.endsWith(".mmdb")) {
                byte[] content = new byte[(int) size];
                readFully(tarStream, content);
                skipFully(tarStream, paddedSize - size);
                return content;
            }

            skipFully(tarStream, paddedSize);
        }
        return null;
    }

    private static String tarEntryName(byte[] header) {
        String raw = new String(header, 0, 100, StandardCharsets.US_ASCII);
        int nullIndex = raw.indexOf('\0');
        return (nullIndex >= 0 ? raw.substring(0, nullIndex) : raw).trim();
    }

    private static long parseOctal(byte[] header, int offset, int length) {
        String raw = new String(header, offset, length, StandardCharsets.US_ASCII).replace("\0", "").trim();
        return raw.isEmpty() ? 0L : Long.parseLong(raw, 8);
    }

    private static boolean isAllZero(byte[] block) {
        for (byte value : block) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    private static int readFully(InputStream in, byte[] buffer) throws IOException {
        int total = 0;
        while (total < buffer.length) {
            int read = in.read(buffer, total, buffer.length - total);
            if (read < 0) {
                break;
            }
            total += read;
        }
        return total;
    }

    private static void skipFully(InputStream in, long bytes) throws IOException {
        long remaining = bytes;
        byte[] buffer = new byte[8192];
        while (remaining > 0) {
            int toRead = (int) Math.min(buffer.length, remaining);
            int read = in.read(buffer, 0, toRead);
            if (read < 0) {
                break;
            }
            remaining -= read;
        }
    }
}
