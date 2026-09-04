package pl.landmc.antiproxy;

public record IpReputation(String ip, boolean proxy, String provider, String type) {

    public IpReputation(String ip, boolean proxy) {
        this(ip, proxy, "", "");
    }
}
