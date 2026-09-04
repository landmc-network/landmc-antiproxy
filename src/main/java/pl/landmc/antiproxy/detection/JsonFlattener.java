package pl.landmc.antiproxy.detection;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns a nested JSON response into {@code a.b.c -> value} pairs.
 *
 * <p>Exists so a condition in the configuration can name a field several levels down without
 * this project knowing the shape of any particular provider's response.
 */
public final class JsonFlattener {

    private JsonFlattener() {
    }

    public static Map<String, Object> flatten(JsonElement element) {
        Map<String, Object> result = new LinkedHashMap<>();
        flattenInto(result, "", element);
        return result;
    }

    public static Object resolve(JsonElement root, String dotPath) {
        return flatten(root).get(dotPath);
    }

    private static void flattenInto(Map<String, Object> target, String prefix, JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return;
        }
        if (element.isJsonObject()) {
            JsonObject object = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
                String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                flattenInto(target, key, entry.getValue());
            }
            return;
        }
        if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (int index = 0; index < array.size(); index++) {
                flattenInto(target, prefix + "[" + index + "]", array.get(index));
            }
            return;
        }
        target.put(prefix, toValue(element));
    }

    private static Object toValue(JsonElement element) {
        JsonPrimitive primitive = element.getAsJsonPrimitive();
        if (primitive.isBoolean()) {
            return primitive.getAsBoolean();
        }
        if (primitive.isNumber()) {
            return primitive.getAsDouble();
        }
        return primitive.getAsString();
    }
}
