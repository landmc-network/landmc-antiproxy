package pl.landmc.antiproxy.iprange;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class IpCidrRangeTest {

    @Test
    void parsesBareAddressAsSingleHostRange() throws Exception {
        IpCidrRange range = IpCidrRange.parse("1.2.3.4");

        assertTrue(range.contains(addressValue("1.2.3.4")));
        assertFalse(range.contains(addressValue("1.2.3.5")));
    }

    @Test
    void parsesIpv4Cidr() throws Exception {
        IpCidrRange range = IpCidrRange.parse("192.168.1.0/24");

        assertTrue(range.contains(addressValue("192.168.1.0")));
        assertTrue(range.contains(addressValue("192.168.1.255")));
        assertFalse(range.contains(addressValue("192.168.2.0")));
    }

    @Test
    void parsesIpv6Cidr() throws Exception {
        IpCidrRange range = IpCidrRange.parse("2001:db8::/32");

        assertTrue(range.contains(addressValue("2001:db8::1")));
        assertFalse(range.contains(addressValue("2001:db9::1")));
    }

    private static BigInteger addressValue(String address) throws Exception {
        return new BigInteger(1, InetAddress.getByName(address).getAddress());
    }
}
