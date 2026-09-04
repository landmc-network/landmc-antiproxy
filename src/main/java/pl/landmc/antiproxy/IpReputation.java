package pl.landmc.antiproxy;

/**
 * What one detection service said about one address.
 *
 * @param provider which service answered, so a disagreement between two of them can be read
 * @param proxy whether it considers the address a proxy, VPN or datacentre
 * @param reason the service's own wording, kept for the log rather than shown to a player
 */
public record IpReputation(String ip, boolean proxy, String provider, String type) {

    public IpReputation(String ip, boolean proxy) {
        this(ip, proxy, "", "");
    }
}
