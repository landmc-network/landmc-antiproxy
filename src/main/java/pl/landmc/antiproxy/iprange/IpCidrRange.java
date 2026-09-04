package pl.landmc.antiproxy.iprange;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;

/**
 * One CIDR block, as the range of addresses it covers.
 *
 * <p>Kept as a pair of integers rather than an address and a prefix length because that is the
 * form the lookup needs: {@link IpRangeService} keeps its blocks sorted by {@link #start()} and
 * binary-searches them, which only works on a comparable value.
 *
 * <p>{@link BigInteger} rather than {@code long} so IPv4 and IPv6 go through the same code. An
 * IPv6 address does not fit in a long, and two parallel implementations of range matching is
 * how one of them ends up subtly wrong.
 */
public record IpCidrRange(BigInteger start, BigInteger end) implements Comparable<IpCidrRange> {

    public IpCidrRange {
        Objects.requireNonNull(start, "start");
        Objects.requireNonNull(end, "end");
    }

    /**
     * Parses {@code 1.2.3.0/24}, {@code 2001:db8::/32} or a bare address.
     *
     * @throws UnknownHostException when the address part is not an address; the lists these
     *     come from are third-party files and do contain junk lines
     * @throws IllegalArgumentException when the prefix length cannot apply to that address
     */
    public static IpCidrRange parse(String text) throws UnknownHostException {
        String trimmed = text.trim();
        int slash = trimmed.indexOf('/');
        String addressPart = slash < 0 ? trimmed : trimmed.substring(0, slash);

        byte[] bytes = InetAddress.getByName(addressPart).getAddress();
        int totalBits = bytes.length * 8;

        int prefixLength;
        if (slash < 0) {
            prefixLength = totalBits;
        }
        else {
            try {
                prefixLength = Integer.parseInt(trimmed.substring(slash + 1).trim());
            }
            catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Invalid CIDR prefix in '" + text + "'", exception);
            }
        }

        if (prefixLength < 0 || prefixLength > totalBits) {
            throw new IllegalArgumentException("Invalid CIDR prefix in '" + text + "'");
        }

        BigInteger base = new BigInteger(1, bytes);
        BigInteger hostMask = BigInteger.ONE.shiftLeft(totalBits - prefixLength).subtract(BigInteger.ONE);
        BigInteger start = base.andNot(hostMask);

        return new IpCidrRange(start, start.or(hostMask));
    }

    public boolean contains(BigInteger address) {
        return address.compareTo(this.start) >= 0 && address.compareTo(this.end) <= 0;
    }

    /** Orders by where the block begins, which is what the binary search relies on. */
    @Override
    public int compareTo(IpCidrRange other) {
        return this.start.compareTo(other.start);
    }
}
