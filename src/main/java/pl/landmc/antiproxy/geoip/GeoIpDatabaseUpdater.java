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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
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
    private ScheduledExecutorService scheduler;

    public GeoIpDatabaseUpdater(
            Logger logger,
            String licenseKey,
            File dataDirectory,
            AntiProxyConfig.GeoIp config,
            Runnable onUpdated
    ) {
        this.logger = logger;
        this.licenseKey = licenseKey;
        this.dataDirectory = dataDirectory;
        this.config = config;
        this.onUpdated = onUpdated;
    }

    public void start() {
        long periodHours = Math.max(1, this.config.autoUpdate.refreshHours);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "skytop-antiproxy-geoip-updater");
            thread.setDaemon(true);
            return thread;
        });
        this.scheduler.scheduleWithFixedDelay(this::refreshAll, 0, periodHours, TimeUnit.HOURS);
    }

    public void shutdown() {
        if (this.scheduler != null) {
            this.scheduler.shutdownNow();
            this.scheduler = null;
        }
    }

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
