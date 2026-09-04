package pl.landmc.antiproxy.detection;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import pl.landmc.antiproxy.IpReputation;
import pl.landmc.antiproxy.config.AntiProxyConfig;

public final class DetectionServiceClient {

    private final HttpClient httpClient;
    private final Logger logger;
    private final boolean debugEnabled;
    private final long timeoutMillis;
    private final String apiKey;

    private final boolean outputErrors;
    private final ResponseModel model;
    private final String providerName;
    private final String urlTemplate;
    private final Map<String, String> headers;
    private final String fieldPath;
    private final FieldType fieldType;
    private final String stringMatch;
    private final Map<String, List<Condition>> bypassConditions;
    private final Map<String, List<Condition>> flagConditions;

    public DetectionServiceClient(
            AntiProxyConfig.Api apiConfig,
            AntiProxyConfig.Service serviceConfig,
            String apiKey,
            Logger logger,
            boolean debugEnabled
    ) {
        this.timeoutMillis = apiConfig.timeoutMillis;
        this.apiKey = apiKey;
        this.logger = logger;
        this.debugEnabled = debugEnabled;

        this.outputErrors = serviceConfig.outputErrors;
        this.model = serviceConfig.model;
        this.providerName = serviceConfig.name.isBlank() ? serviceConfig.url : serviceConfig.name;
        this.urlTemplate = serviceConfig.url;
        this.headers = Map.copyOf(serviceConfig.headers);
        this.fieldPath = serviceConfig.values.field;
        this.fieldType = serviceConfig.values.type;
        this.stringMatch = serviceConfig.values.stringMatch;
        this.bypassConditions = Condition.compile(serviceConfig.values.conditions.bypass);
        this.flagConditions = Condition.compile(serviceConfig.values.conditions.flag);

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(this.timeoutMillis))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public CompletableFuture<IpReputation> lookup(String address) {
        return this.httpClient.sendAsync(this.buildRequest(address), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(response -> this.interpret(address, response));
    }

    private IpReputation interpret(String address, HttpResponse<String> response) {
        String body = response.body();
        if (this.debugEnabled) {
            this.logger.info(
                    "[AntiProxy debug] service response for {}: HTTP {} -> {}",
                    address,
                    response.statusCode(),
                    body);
        }
        if (response.statusCode() != 200) {
            throw new DetectionServiceException("Detection service returned HTTP " + response.statusCode());
        }
        Detection detection = switch (this.model) {
            case JSON -> this.evaluateDetection(body);
            case HTML, CONTAINS -> {
                boolean proxy = this.evaluateText(body);
                yield new Detection(proxy, proxy ? "PROXY" : "");
            }
        };
        return new IpReputation(address, detection.proxy(), this.providerName, detection.type());
    }

    boolean evaluateJson(String body) {
        return this.evaluateDetection(body).proxy();
    }

    /**
     * The returned {@link Detection#type()} is what a caller surfaces as the human-readable detection
     * category: the matched 'flag' group's key (e.g. 'RESIDENTIAL_PROXY') when one matches, otherwise
     * the raw field value for a STRING field check, or the generic 'PROXY' label for a BOOLEAN one -
     * there is no richer signal available for a plain true/false field.
     */
    Detection evaluateDetection(String body) {
        JsonElement root;
        try {
            root = JsonParser.parseString(body);
        }
        catch (JsonSyntaxException exception) {
            throw new DetectionServiceException("Detection service returned invalid JSON");
        }

        Map<String, Object> fields = JsonFlattener.flatten(root);
        if (Condition.anyGroupMatches(this.bypassConditions, fields)) {
            return new Detection(false, "");
        }
        String flaggedGroup = Condition.firstMatchingGroup(this.flagConditions, fields);
        if (flaggedGroup != null) {
            return new Detection(true, flaggedGroup);
        }
        if (this.fieldPath.isBlank()) {
            return new Detection(false, "");
        }

        Object value = fields.get(this.fieldPath);
        if (value == null) {
            if (this.outputErrors) {
                this.logger.warn("Detection service response is missing field '{}'.", this.fieldPath);
            }
            throw new DetectionServiceException("Detection service response is missing field '" + this.fieldPath + "'");
        }
        boolean proxy = this.fieldType == FieldType.BOOLEAN ? asBoolean(value) : this.matchesString(value);
        if (!proxy) {
            return new Detection(false, "");
        }
        return new Detection(true, this.fieldType == FieldType.STRING ? String.valueOf(value) : "PROXY");
    }

    private boolean evaluateText(String body) {
        return body != null && body.contains(this.stringMatch);
    }

    private boolean matchesString(Object value) {
        return String.valueOf(value).equalsIgnoreCase(this.stringMatch);
    }

    private HttpRequest buildRequest(String address) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(this.requestUri(address))
                .timeout(Duration.ofMillis(this.timeoutMillis))
                .header("Accept", "application/json")
                .GET();
        for (Map.Entry<String, String> header : this.headers.entrySet()) {
            builder.header(header.getKey(), this.interpolate(header.getValue(), address));
        }
        return builder.build();
    }

    URI requestUri(String address) {
        return URI.create(this.interpolate(this.urlTemplate, address));
    }

    private String interpolate(String template, String address) {
        String encodedKey = URLEncoder.encode(this.apiKey, StandardCharsets.UTF_8);
        String encodedAddress = URLEncoder.encode(address, StandardCharsets.UTF_8);
        return template.replace("{KEY}", encodedKey).replace("{IP}", encodedAddress);
    }

    private static boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Number number) {
            return number.doubleValue() != 0;
        }
        String text = String.valueOf(value).trim().toLowerCase(Locale.ROOT);
        if (text.equals("true") || text.equals("1") || text.equals("yes")) {
            return true;
        }
        if (text.equals("false") || text.equals("0") || text.equals("no")) {
            return false;
        }
        throw new DetectionServiceException("Cannot interpret '" + value + "' as a boolean");
    }

    public static final class DetectionServiceException extends RuntimeException {

        public DetectionServiceException(String message) {
            super(message);
        }
    }
}
