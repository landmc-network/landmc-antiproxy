package pl.landmc.antiproxy.detection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonFlattenerTest {

    @Test
    void flattensNestedObjectsWithDotNotation() {
        JsonElement root = JsonParser.parseString("{\"data\":{\"proxy\":true,\"score\":42},\"ip\":\"1.2.3.4\"}");

        Map<String, Object> flattened = JsonFlattener.flatten(root);

        assertEquals(true, flattened.get("data.proxy"));
        assertEquals(42.0, flattened.get("data.score"));
        assertEquals("1.2.3.4", flattened.get("ip"));
    }

    @Test
    void flattensArraysWithIndexNotation() {
        JsonElement root = JsonParser.parseString("{\"tags\":[\"vpn\",\"tor\"]}");

        Map<String, Object> flattened = JsonFlattener.flatten(root);

        assertEquals("vpn", flattened.get("tags[0]"));
        assertEquals("tor", flattened.get("tags[1]"));
    }

    @Test
    void resolveReturnsNullForMissingField() {
        JsonElement root = JsonParser.parseString("{\"proxy\":false}");

        assertNull(JsonFlattener.resolve(root, "missing"));
    }

    @Test
    void resolveReadsNestedField() {
        JsonElement root = JsonParser.parseString("{\"data\":{\"proxy\":1}}");

        assertEquals(1.0, JsonFlattener.resolve(root, "data.proxy"));
    }
}
