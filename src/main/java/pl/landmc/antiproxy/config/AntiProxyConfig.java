package pl.landmc.antiproxy.config;

import eu.okaeri.configs.OkaeriConfig;
import eu.okaeri.configs.annotation.Comment;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import pl.landmc.platform.database.DatabaseConfig;
import pl.landmc.antiproxy.detection.CombinationMode;
import pl.landmc.antiproxy.detection.FieldType;
import pl.landmc.antiproxy.detection.ResponseModel;

public final class AntiProxyConfig extends OkaeriConfig {

    public boolean enabled = true;

    @Comment("MONITOR only logs what would happen. ENFORCE actually denies the connection.")
    public EnforcementMode mode = EnforcementMode.MONITOR;

    @Comment("Logs the raw response returned by the detection service for every check.")
    public boolean debug = false;

    @Comment("When true, the connecting player is never auto-checked on join. Use '/antiproxy check <adres>' "
            + "to check manually, or combine with another AntiVPN plugin.")
    public boolean passive = false;

    public Api api = new Api();

    @Comment("One entry per detection service that is queried for every check. The default has a single entry set "
            + "up for https://proxyradar.io/, but you can add more (each with its own url/headers/values/key) to "
            + "corroborate results instead of trusting a single provider.")
    public List<Service> services = new ArrayList<>(List.of(new Service()));

    @Comment("How multiple 'services' entries are combined into one decision (irrelevant with a single entry). "
            + "ALL: every service that answered must flag it a proxy to block (fewer false positives, needs "
            + "agreement). ANY: a single service flagging it is enough (most aggressive). MAJORITY: more than "
            + "half of the services that answered must flag it. Services that time out or error simply don't "
            + "count towards either side.")
    public CombinationMode combination = CombinationMode.ALL;

    public Cache cache = new Cache();

    @Comment("Only used when 'cache.database' is true.")
    public DatabaseConfig database = new DatabaseConfig();

    @Comment("Local MaxMind GeoLite2 databases used to resolve an address's ASN/ISP/country before (or "
            + "instead of) calling any 'services' entry - lets the allowlist/geoBlacklist below skip the "
            + "external detection call entirely for known-good ISPs, without needing a network request.")
    public GeoIp geoIp = new GeoIp();

    public Allowlist allowlist = new Allowlist();

    @Comment("Blocks or allows a connection purely by ASN/ISP/country, resolved from 'geoIp' - independent "
            + "of the 'services' proxy-detection calls. Checked before any service is queried.")
    public GeoBlacklist geoBlacklist = new GeoBlacklist();

    @Comment("Usernames that are always denied, checked before proxy detection, the allowlist, and the IP "
            + "limiter - independent of 'mode' and 'passive'. Same 'regex:' prefix syntax as 'allowlist'.")
    public Blacklist blacklist = new Blacklist();

    @Comment("Limits how many simultaneous connections are allowed from the same IP address.")
    public IpLimiter ipLimiter = new IpLimiter();

    @Comment("Blocks connections whose address matches an offline list of IP/CIDR ranges (proxy/tor/hosting "
            + "lists), without calling the detection service.")
    public IpRange ipRange = new IpRange();


    public void validate() {
        if (this.api.timeoutMillis < 500L || this.api.timeoutMillis > 10_000L) {
            throw new IllegalArgumentException("api.timeoutMillis must be between 500 and 10000");
        }
        if (this.api.maximumConcurrentRequests < 1 || this.api.maximumConcurrentRequests > 256) {
            throw new IllegalArgumentException("api.maximumConcurrentRequests must be between 1 and 256");
        }
        if (this.api.maximumRequestsPerMinute < 1) {
            throw new IllegalArgumentException("api.maximumRequestsPerMinute must be positive");
        }
        if (this.cache.maximumEntries < 100) {
            throw new IllegalArgumentException("cache.maximumEntries must be at least 100");
        }
        if (this.cache.allowedTtlMillis < 1_000L || this.cache.riskyTtlMillis < 1_000L) {
            throw new IllegalArgumentException("cache TTL values must be at least 1000 milliseconds");
        }
        if (this.ipLimiter.maximum < 1) {
            throw new IllegalArgumentException("ipLimiter.maximum must be positive");
        }
        if (this.services.isEmpty()) {
            throw new IllegalArgumentException("at least one entry in 'services' is required");
        }
    }

    public static final class Api extends OkaeriConfig {

        public long timeoutMillis = 2_000L;
        public int maximumConcurrentRequests = 16;
        public int maximumRequestsPerMinute = 120;
    }

    public static final class Service extends OkaeriConfig {

        @Comment("Only used in logs/reasons to tell services apart. Defaults to the url when left empty.")
        public String name = "";

        public boolean enabled = true;

        @Comment("Do NOT put the actual API key here - this is only the NAME of an environment variable that "
                + "must be set on the Velocity process. If that variable is not set, the key is read from "
                + "'keyFile' instead (put only the raw key there, nothing else).")
        public String keyEnvironmentVariable = "PROXYRADAR_API_KEY";

        public String keyFile = "proxyradar.key";

        @Comment("Log a warning when the response cannot be interpreted (missing field, invalid JSON, ...).")
        public boolean outputErrors = true;

        @Comment("Supported values: JSON, HTML, CONTAINS")
        public ResponseModel model = ResponseModel.JSON;

        @Comment("Placeholders: {IP} the checked address, {KEY} the loaded API key.")
        public String url = "https://proxyradar.io/v1/check?key={KEY}&ip={IP}&format=json";

        public Map<String, String> headers = new LinkedHashMap<>();

        public Values values = new Values();

        public static final class Values extends OkaeriConfig {

            @Comment("Dot-path of the JSON field to read (e.g. 'data.proxy'). Ignored for HTML/CONTAINS. Leave "
                    + "empty to skip this direct check entirely and decide purely from 'conditions' below "
                    + "(no group matching then means ALLOW) - useful with a provider rich enough to avoid "
                    + "blocking on a single low-confidence signal.")
            public String field = "proxy";

            @Comment("BOOLEAN treats the field as true/false (also accepts 1/0). STRING compares it against "
                    + "'stringMatch'.")
            public FieldType type = FieldType.BOOLEAN;

            @Comment("For type STRING: value that flags the connection. For model HTML/CONTAINS: substring that "
                    + "flags the connection when present in the raw response body.")
            public String stringMatch = "Y";

            public Conditions conditions = new Conditions();

            public static final class Conditions extends OkaeriConfig {

                @Comment("Each key groups AND-ed conditions; any group matching means OR between groups. "
                        + "Syntax: '{field}OPvalue', operators: =, !=, >, >=, <, <=. Matching a bypass group "
                        + "always allows the connection, skipping 'flag' and the direct field check.")
                public Map<String, List<String>> bypass = new LinkedHashMap<>();

                @Comment("Same syntax as 'bypass'. Matching a flag group always blocks the connection, skipping "
                        + "the direct field check. The matching group's key is also what appears as 'type=' in "
                        + "the per-provider log line - name a group 'RESIDENTIAL_PROXY' to see that exact label.")
                public Map<String, List<String>> flag = new LinkedHashMap<>();
            }
        }
    }

    public static final class Cache extends OkaeriConfig {

        public long allowedTtlMillis = 86_400_000L;
        public long riskyTtlMillis = 21_600_000L;
        public int maximumEntries = 100_000;

        @Comment("Persist the cache in the configured database so it survives restarts and is shared across "
                + "multiple Velocity nodes (multi-proxy). The in-memory cache is still used as the hot path.")
        public boolean database = false;
    }

    public static final class Allowlist extends OkaeriConfig {

        public boolean privateAddresses = true;

        @Comment("Case-insensitive exact match by default; prefix an entry with 'regex:' for a regular expression "
                + "(e.g. 'regex:^Staff_.*$').")
        public List<String> usernames = new ArrayList<>();

        @Comment("Exact match by default; prefix an entry with 'regex:' for a regular expression.")
        public List<String> addresses = new ArrayList<>();

        @Comment("Requires 'geoIp' to be enabled. ASN numbers (e.g. 'AS8308') whose connections skip every "
                + "'services' detection call entirely - known-good ISPs never get sent to a third party.")
        public List<String> asns = new ArrayList<>(List.of(
                "AS8308", "AS198537", "AS12831", "AS56983",
                "AS210142", "AS56475", "AS56712"));

        @Comment("Requires 'geoIp' to be enabled. Case-insensitive substring match against the ASN "
                + "organization name (e.g. 'Orange', 'T-Mobile'). Same effect as 'asns'.")
        public List<String> isps = new ArrayList<>(List.of(
                "Orange", "Orange Polska", "Play", "P4", "T-Mobile", "T-Mobile Polska",
                "Plus", "Polkomtel", "NETIA", "INEA", "UPC", "Vectra", "Asta-Net", "EXATEL",
                "TK Telekom",
                "Naukowa I Akademicka Siec Komputerowa - Panstwowy Instytut Badawczy"));

        @Comment("Requires 'geoIp' to be enabled. ISO 3166-1 alpha-2 country codes (e.g. 'PL') whose "
                + "connections skip every 'services' detection call entirely.")
        public List<String> countries = new ArrayList<>();
    }

    public static final class GeoIp extends OkaeriConfig {

        public boolean enabled = false;

        @Comment("Path to a GeoLite2-ASN.mmdb file, relative to the plugin data folder. Download from "
                + "MaxMind (free account + license key required) and keep it updated periodically.")
        public String asnDatabasePath = "GeoLite2-ASN.mmdb";

        @Comment("Path to a GeoLite2-Country.mmdb file, relative to the plugin data folder. Leave the file "
                + "missing to skip country-based allowlist/geoBlacklist entries.")
        public String countryDatabasePath = "GeoLite2-Country.mmdb";

        @Comment("Automatically downloads and periodically refreshes the two databases above from "
                + "MaxMind, so they never need to be updated by hand.")
        public AutoUpdate autoUpdate = new AutoUpdate();

        public static final class AutoUpdate extends OkaeriConfig {

            public boolean enabled = false;

            @Comment("Do NOT put the actual key here - this is only the NAME of an environment variable "
                    + "that must be set on the Velocity process. If that variable is not set, the key is "
                    + "read from 'licenseKeyFile' instead (put only the raw key there, nothing else). Get "
                    + "a free key from your MaxMind account at maxmind.com.")
            public String licenseKeyEnvironmentVariable = "MAXMIND_LICENSE_KEY";

            public String licenseKeyFile = "maxmind.key";

            @Comment("How often to check MaxMind for a newer database, in hours. GeoLite2 is published "
                    + "roughly twice a week, so there is no point checking much more often than that.")
            public int refreshHours = 24;
        }
    }

    public static final class GeoBlacklist extends OkaeriConfig {

        @Comment("Requires 'geoIp' to be enabled. ASN numbers (e.g. 'AS16276') that are denied immediately, "
                + "without calling any 'services' entry.")
        public List<String> asns = new ArrayList<>(List.of(
                // Hosting providers: a home connection does not come from a datacentre.
                "AS16276", "AS24940", "AS14061", "AS9009", "AS31898"));

        @Comment("Requires 'geoIp' to be enabled. Case-insensitive substring match against the ASN "
                + "organization name (e.g. 'NordVPN', 'Surfshark'). Same effect as 'asns'.")
        public List<String> isps = new ArrayList<>(List.of("NordVPN", "Surfshark"));

        @Comment("Requires 'geoIp' to be enabled. ISO 3166-1 alpha-2 country codes that are denied "
                + "immediately, without calling any 'services' entry.")
        public List<String> countries = new ArrayList<>();

    }

    public static final class Blacklist extends OkaeriConfig {

        public List<String> usernames = new ArrayList<>();

    }

    public static final class IpLimiter extends OkaeriConfig {

        public boolean enabled = false;
        public int maximum = 3;

        @Comment("Duration string ('30m', '1h', '7d', ...) to auto-reset the counter, or 'DISABLE' to only "
                + "decrement it when a player disconnects.")
        public String time = "DISABLE";

    }

    public static final class IpRange extends OkaeriConfig {

        public boolean enabled = false;
        public List<Source> sources = new ArrayList<>();

        public static final class Source extends OkaeriConfig {

            public String name = "";
            public String url = "";
            public int refreshMinutes = 60;

            public Source() {
            }

            public Source(String name, String url, int refreshMinutes) {
                this.name = name;
                this.url = url;
                this.refreshMinutes = refreshMinutes;
            }
        }
    }

}
