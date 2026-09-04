package pl.landmc.antiproxy.detection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ConditionTest {

    @Test
    void parsesNumericGreaterThanOrEqual() {
        Condition condition = Condition.parse("{fraud_score}>=85");

        assertEquals("fraud_score", condition.fieldPath());
        assertEquals(Condition.Operator.GREATER_OR_EQUAL, condition.operator());
        assertTrue(condition.matches(Map.of("fraud_score", 90.0)));
        assertFalse(condition.matches(Map.of("fraud_score", 80.0)));
    }

    @Test
    void parsesStringEquality() {
        Condition condition = Condition.parse("{country}=US");

        assertTrue(condition.matches(Map.of("country", "us")));
        assertFalse(condition.matches(Map.of("country", "PL")));
    }

    @Test
    void missingFieldNeverMatches() {
        Condition condition = Condition.parse("{fraud_score}>50");

        assertFalse(condition.matches(Map.of()));
    }

    @Test
    void rejectsInvalidExpression() {
        assertThrows(IllegalArgumentException.class, () -> Condition.parse("fraud_score >= 85"));
    }

    @Test
    void anyGroupMatchesUsesAndWithinGroupAndOrAcrossGroups() {
        Map<String, List<Condition>> groups = Condition.compile(Map.of(
                "1", List.of("{score}>=85", "{country}=US"),
                "2", List.of("{trusted}=true")
        ));

        assertTrue(Condition.anyGroupMatches(groups, Map.of("trusted", true)));
        assertTrue(Condition.anyGroupMatches(groups, Map.of("score", 90.0, "country", "US")));
        assertFalse(Condition.anyGroupMatches(groups, Map.of("score", 90.0, "country", "PL")));
        assertFalse(Condition.anyGroupMatches(groups, Map.of()));
    }
}
