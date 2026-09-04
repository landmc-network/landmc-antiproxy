package pl.landmc.antiproxy.detection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import pl.landmc.antiproxy.config.AntiProxyConfig;

class DetectionServiceClientTest {

    @Test
    void interpolatesIpAndKeyPlaceholdersInTheConfiguredUrl() {
        DetectionServiceClient client = client(config -> config.url = "https://example.test/check?key={KEY}&ip={IP}&format=json");

        assertEquals(
                "https://example.test/check?key=s3cr3t+key&ip=1.2.3.4&format=json",
                client.requestUri("1.2.3.4").toString());
    }

    @Test
    void directFieldCheckBlocksOnTruthyBooleanField() {
        DetectionServiceClient client = client(config -> config.values.field = "proxy");

        assertTrue(client.evaluateJson("{\"proxy\":true}"));
        assertFalse(client.evaluateJson("{\"proxy\":false}"));
    }

    @Test
    void blankFieldWithNoMatchingConditionsDefaultsToAllow() {
        DetectionServiceClient client = client(config -> config.values.field = "");

        assertFalse(client.evaluateJson("{\"fraud_score\":10,\"trusted_network\":true}"));
    }

    @Test
    void flagConditionBlocksEvenWithBlankDirectField() {
        DetectionServiceClient client = client(config -> {
            config.values.field = "";
            config.values.conditions.flag = Map.of("high-risk", List.of("{fraud_score}>=85"));
        });

        assertTrue(client.evaluateJson("{\"fraud_score\":90}"));
        assertFalse(client.evaluateJson("{\"fraud_score\":40}"));
    }

    @Test
    void bypassConditionWinsOverFlagAndDirectField() {
        DetectionServiceClient client = client(config -> {
            config.values.field = "proxy";
            config.values.conditions.bypass = Map.of("trusted", List.of("{trusted_network}=true"));
            config.values.conditions.flag = Map.of("high-risk", List.of("{fraud_score}>=85"));
        });

        assertFalse(client.evaluateJson("{\"proxy\":true,\"fraud_score\":99,\"trusted_network\":true}"));
    }

    @Test
    void flaggedDirectBooleanFieldReportsAGenericProxyType() {
        DetectionServiceClient client = client(config -> config.values.field = "proxy");

        Detection detection = client.evaluateDetection("{\"proxy\":true}");

        assertTrue(detection.proxy());
        assertEquals("PROXY", detection.type());
    }

    @Test
    void flaggedDirectStringFieldReportsTheMatchedValueAsType() {
        DetectionServiceClient client = client(config -> {
            config.values.field = "connection_type";
            config.values.type = FieldType.STRING;
            config.values.stringMatch = "RESIDENTIAL_PROXY";
        });

        Detection detection = client.evaluateDetection("{\"connection_type\":\"RESIDENTIAL_PROXY\"}");

        assertTrue(detection.proxy());
        assertEquals("RESIDENTIAL_PROXY", detection.type());
    }

    @Test
    void flaggedConditionGroupReportsItsOwnKeyAsType() {
        DetectionServiceClient client = client(config -> {
            config.values.field = "";
            config.values.conditions.flag = Map.of("RESIDENTIAL_PROXY", List.of("{fraud_score}>=85"));
        });

        Detection detection = client.evaluateDetection("{\"fraud_score\":90}");

        assertTrue(detection.proxy());
        assertEquals("RESIDENTIAL_PROXY", detection.type());
    }

    @Test
    void cleanResultReportsNoType() {
        DetectionServiceClient client = client(config -> config.values.field = "proxy");

        Detection detection = client.evaluateDetection("{\"proxy\":false}");

        assertFalse(detection.proxy());
        assertEquals("", detection.type());
    }

    private static DetectionServiceClient client(java.util.function.Consumer<AntiProxyConfig.Service> customizer) {
        AntiProxyConfig.Api apiConfig = new AntiProxyConfig.Api();
        AntiProxyConfig.Service serviceConfig = new AntiProxyConfig.Service();
        customizer.accept(serviceConfig);
        return new DetectionServiceClient(
                apiConfig, serviceConfig, "s3cr3t key", LoggerFactory.getLogger("DetectionServiceClientTest"), false);
    }
}
