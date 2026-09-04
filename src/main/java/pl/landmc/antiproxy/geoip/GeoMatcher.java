package pl.landmc.antiproxy.geoip;

import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

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
