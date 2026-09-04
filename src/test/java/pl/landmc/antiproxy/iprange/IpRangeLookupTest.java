package pl.landmc.antiproxy.iprange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The lookup went from walking every block to a binary search over a sorted array, because it
 * runs for every connection and these lists hold tens of thousands of blocks.
 *
 * <p>That kind of change is exactly the kind that can be subtly wrong at the edges and still
 * look fine, so these check the boundaries and compare the answer against the obvious
 * implementation over a randomised list.
 */
class IpRangeLookupTest {

    /** The search, isolated from the HTTP loading around it. */
    private static boolean contains(IpCidrRange[] sorted, String address) throws Exception {
        BigInteger value = new BigInteger(1, InetAddress.getByName(address).getAddress());
        int index = Arrays.binarySearch(sorted, new IpCidrRange(value, value), IpCidrRange::compareTo);
        int candidate = index >= 0 ? index : -index - 2;
        return candidate >= 0 && sorted[candidate].contains(value);
    }

    private static IpCidrRange[] sorted(String... cidrs) throws Exception {
        List<IpCidrRange> ranges = new ArrayList<>();
        for (String cidr : cidrs) {
            ranges.add(IpCidrRange.parse(cidr));
        }
        Collections.sort(ranges);
        return ranges.toArray(IpCidrRange[]::new);
    }

    @Test
    @DisplayName("an address inside a block is found, one outside is not")
    void findsTheObviousCases() throws Exception {
        IpCidrRange[] ranges = sorted("10.0.0.0/8", "192.168.1.0/24", "203.0.113.0/24");

        assertTrue(contains(ranges, "10.5.4.3"));
        assertTrue(contains(ranges, "192.168.1.77"));
        assertFalse(contains(ranges, "192.168.2.77"));
        assertFalse(contains(ranges, "8.8.8.8"));
    }

    @Test
    @DisplayName("the first and last address of a block count as inside it")
    void includesBothEnds() throws Exception {
        IpCidrRange[] ranges = sorted("192.168.1.0/24");

        assertTrue(contains(ranges, "192.168.1.0"), "the network address was missed");
        assertTrue(contains(ranges, "192.168.1.255"), "the broadcast address was missed");
        assertFalse(contains(ranges, "192.168.0.255"));
        assertFalse(contains(ranges, "192.168.2.0"));
    }

    @Test
    @DisplayName("an address below every block does not read past the start of the array")
    void handlesAnAddressBeforeEveryBlock() throws Exception {
        IpCidrRange[] ranges = sorted("192.168.1.0/24");

        assertFalse(contains(ranges, "1.1.1.1"));
    }

    @Test
    @DisplayName("an empty list blocks nothing")
    void handlesAnEmptyList() throws Exception {
        assertFalse(contains(new IpCidrRange[0], "1.1.1.1"));
    }

    @Test
    @DisplayName("a single address without a prefix is a block of one")
    void treatsABareAddressAsOneAddress() throws Exception {
        IpCidrRange[] ranges = sorted("203.0.113.7");

        assertTrue(contains(ranges, "203.0.113.7"));
        assertFalse(contains(ranges, "203.0.113.8"));
    }

    @Test
    @DisplayName("IPv6 goes through the same path as IPv4")
    void handlesIpv6() throws Exception {
        IpCidrRange[] ranges = sorted("2001:db8::/32");

        assertTrue(contains(ranges, "2001:db8:1234::1"));
        assertFalse(contains(ranges, "2001:db9::1"));
    }

    @Test
    @DisplayName("the binary search agrees with walking the whole list, over a thousand cases")
    void agreesWithTheObviousImplementation() throws Exception {
        // Fixed seed: a failure has to be reproducible, and a randomised test that cannot be
        // re-run is a test that gets deleted the first time it fails.
        java.util.Random random = new java.util.Random(20260904L);

        List<IpCidrRange> ranges = new ArrayList<>();
        for (int index = 0; index < 200; index++) {
            int first = random.nextInt(256);
            int second = random.nextInt(256);
            ranges.add(IpCidrRange.parse(first + "." + second + ".0.0/16"));
        }
        Collections.sort(ranges);
        IpCidrRange[] sorted = ranges.toArray(IpCidrRange[]::new);

        for (int attempt = 0; attempt < 1000; attempt++) {
            String address = random.nextInt(256) + "." + random.nextInt(256)
                    + "." + random.nextInt(256) + "." + random.nextInt(256);

            BigInteger value = new BigInteger(1, InetAddress.getByName(address).getAddress());
            boolean expected = ranges.stream().anyMatch(range -> range.contains(value));

            assertEquals(expected, contains(sorted, address), address);
        }
    }

    @Test
    @DisplayName("junk in a published list is refused rather than parsed into something wrong")
    void refusesMalformedEntries() {
        org.junit.jupiter.api.Assertions.assertThrows(
                Exception.class, () -> IpCidrRange.parse("192.168.1.0/33"));
        org.junit.jupiter.api.Assertions.assertThrows(
                Exception.class, () -> IpCidrRange.parse("192.168.1.0/abc"));
        org.junit.jupiter.api.Assertions.assertThrows(
                Exception.class, () -> IpCidrRange.parse("to nie jest adres"));
    }
}
