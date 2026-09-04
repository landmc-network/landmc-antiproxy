package pl.landmc.antiproxy.geoip;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CountryResponse;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import pl.landmc.antiproxy.config.AntiProxyConfig;

/**
 * Resolves an address's ASN/ISP/country from local MaxMind GeoLite2 databases, so the allowlist
 * and geoBlacklist can decide without ever calling a 'services' detection entry - matching how a
 * known-good ISP should never even be sent to a third party.
 */
/**
 * Reads the local GeoLite2 databases.
 *
 * <p>On the login path, so it does no network I/O: MaxMind's reader keeps the database mapped
 * in memory and a lookup is a read from it. That is the whole reason the ASN and country checks
 * run before any call to a paid API.
 *
 * <p>{@link #reload()} swaps the readers when the updater has fetched a newer file, so a
 * refresh does not need a proxy restart.
 */
public final class GeoIpLookupService {

    private final Logger logger;
    private final AntiProxyConfig.GeoIp config;
    private final File dataDirectory;
    private volatile DatabaseReader asnReader;
    private volatile DatabaseReader countryReader;

    private GeoIpLookupService(
            Logger logger,
            AntiProxyConfig.GeoIp config,
            File dataDirectory,
            DatabaseReader asnReader,
            DatabaseReader countryReader
    ) {
        this.logger = logger;
        this.config = config;
        this.dataDirectory = dataDirectory;
        this.asnReader = asnReader;
        this.countryReader = countryReader;
    }

    public static GeoIpLookupService load(Logger logger, AntiProxyConfig.GeoIp config, File dataDirectory) {
        if (!config.enabled) {
            return null;
        }

        DatabaseReader asnReader = openReader(logger, dataDirectory, config.asnDatabasePath, "ASN");
        DatabaseReader countryReader = openReader(logger, dataDirectory, config.countryDatabasePath, "Country");
        if (asnReader == null && countryReader == null) {
            logger.warn("GeoIp is enabled but neither the ASN nor Country database could be loaded; "
                    + "ASN/ISP/country allowlist and geoBlacklist entries will never match.");
        }
        return new GeoIpLookupService(logger, config, dataDirectory, asnReader, countryReader);
    }

    /**
     * Re-opens both databases from disk and swaps them in - used after GeoIpDatabaseUpdater
     * downloads a fresh copy, so a running proxy picks up the update without a restart. The
     * previous readers are closed only after the new ones are in place, so a lookup racing this
     * reload always sees a valid (old or new) reader, never a closed one.
     */
    public void reload() {
        DatabaseReader newAsnReader = openReader(this.logger, this.dataDirectory, this.config.asnDatabasePath, "ASN");
        DatabaseReader newCountryReader =
                openReader(this.logger, this.dataDirectory, this.config.countryDatabasePath, "Country");

        DatabaseReader previousAsnReader = this.asnReader;
        DatabaseReader previousCountryReader = this.countryReader;
        this.asnReader = newAsnReader;
        this.countryReader = newCountryReader;
        closeQuietly(previousAsnReader);
        closeQuietly(previousCountryReader);
    }

    private static DatabaseReader openReader(Logger logger, File dataDirectory, String path, String label) {
        if (path == null || path.isBlank()) {
            return null;
        }
        File file = new File(dataDirectory, path);
        if (!file.isFile()) {
            logger.warn("GeoIp {} database not found at '{}'; {}-based rules will never match.",
                    label, file.getPath(), label);
            return null;
        }
        try {
            return new DatabaseReader.Builder(file).build();
        }
        catch (IOException exception) {
            logger.warn("Could not load GeoIp {} database at '{}': {}",
                    label, file.getPath(), exception.getMessage());
            return null;
        }
    }

    public Optional<AsnInfo> lookupAsn(InetAddress address) {
        if (this.asnReader == null) {
            return Optional.empty();
        }
        try {
            AsnResponse response = this.asnReader.asn(address);
            Long asn = response.getAutonomousSystemNumber();
            if (asn == null) {
                return Optional.empty();
            }
            String organization = response.getAutonomousSystemOrganization();
            return Optional.of(new AsnInfo("AS" + asn, organization == null ? "" : organization));
        }
        catch (AddressNotFoundException exception) {
            return Optional.empty();
        }
        catch (IOException | GeoIp2Exception exception) {
            this.logger.warn("GeoIp ASN lookup failed for {}: {}", address, exception.getMessage());
            return Optional.empty();
        }
    }

    public Optional<String> lookupCountry(InetAddress address) {
        if (this.countryReader == null) {
            return Optional.empty();
        }
        try {
            CountryResponse response = this.countryReader.country(address);
            String isoCode = response.getCountry().getIsoCode();
            return isoCode == null || isoCode.isBlank()
                    ? Optional.empty()
                    : Optional.of(isoCode.toUpperCase(Locale.ROOT));
        }
        catch (AddressNotFoundException exception) {
            return Optional.empty();
        }
        catch (IOException | GeoIp2Exception exception) {
            this.logger.warn("GeoIp country lookup failed for {}: {}", address, exception.getMessage());
            return Optional.empty();
        }
    }

    public void close() {
        closeQuietly(this.asnReader);
        closeQuietly(this.countryReader);
    }

    private static void closeQuietly(DatabaseReader reader) {
        if (reader == null) {
            return;
        }
        try {
            reader.close();
        }
        catch (IOException ignored) {
        }
    }

    public record AsnInfo(String asn, String organization) {
    }
}
