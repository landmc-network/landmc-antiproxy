package pl.landmc.antiproxy.iprange;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

public record IpCidrRange(BigInteger start, BigInteger end) {

    public static IpCidrRange parse(String text) throws UnknownHostException {
        String trimmed = text.trim();
        int slash = trimmed.indexOf('/');
        String addressPart = slash < 0 ? trimmed : trimmed.substring(0, slash);

        InetAddress address = InetAddress.getByName(addressPart);
        byte[] bytes = address.getAddress();
        int totalBits = bytes.length * 8;
        int prefixLength = slash < 0 ? totalBits : Integer.parseInt(trimmed.substring(slash + 1).trim());
        if (prefixLength < 0 || prefixLength > totalBits) {
            throw new IllegalArgumentException("Invalid CIDR prefix in '" + text + "'");
        }

        BigInteger base = new BigInteger(1, bytes);
        BigInteger hostMask = BigInteger.ONE.shiftLeft(totalBits - prefixLength).subtract(BigInteger.ONE);
        BigInteger start = base.andNot(hostMask);
        BigInteger end = start.or(hostMask);
        return new IpCidrRange(start, end);
    }

    public boolean contains(BigInteger address) {
        return address.compareTo(this.start) >= 0 && address.compareTo(this.end) <= 0;
    }
}
