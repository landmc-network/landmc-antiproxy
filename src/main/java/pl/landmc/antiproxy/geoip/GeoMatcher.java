package pl.landmc.antiproxy.geoip;

import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Whether an address belongs to one of the listed ASNs, ISPs or countries.
 *
 * <p>Answered from the local GeoLite2 files, which is what makes it worth checking before any
 * paid API call: on a Polish network most connections match the ISP allowlist here and never
 * leave the process.
 *
 * <p>Runs on the login path, so it does no I/O of its own - the MaxMind reader keeps its
 * database mapped in memory and a lookup is a read from it.
 */
public final class GeoMatcher {

    private GeoMatcher() {
    }

    public static boolean matches(
            GeoIpLookupService lookupService,
            InetAddress address,
            List<String> asns,
            List<String> isps,
            List<String> countries
    ) {
        if (lookupService == null) {
            return false;
        }

        if (!asns.isEmpty() || !isps.isEmpty()) {
            Optional<GeoIpLookupService.AsnInfo> asnInfo = lookupService.lookupAsn(address);
            if (asnInfo.isPresent()) {
                GeoIpLookupService.AsnInfo info = asnInfo.get();
                if (matchesAsn(info.asn(), asns) || matchesIsp(info.organization(), isps)) {
                    return true;
                }
            }
        }

        if (!countries.isEmpty()) {
            Optional<String> country = lookupService.lookupCountry(address);
            if (country.isPresent() && matchesCountry(country.get(), countries)) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchesAsn(String asn, List<String> configured) {
        for (String candidate : configured) {
            if (candidate != null && candidate.equalsIgnoreCase(asn)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesIsp(String organization, List<String> configured) {
        if (organization == null || organization.isBlank()) {
            return false;
        }
        String lowerOrganization = organization.toLowerCase(Locale.ROOT);
        for (String candidate : configured) {
            if (candidate != null && !candidate.isBlank()
                    && lowerOrganization.contains(candidate.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesCountry(String countryCode, List<String> configured) {
        for (String candidate : configured) {
            if (candidate != null && candidate.equalsIgnoreCase(countryCode)) {
                return true;
            }
        }
        return false;
    }
}
