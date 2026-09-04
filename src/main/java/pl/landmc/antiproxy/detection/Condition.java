package pl.landmc.antiproxy.detection;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public record Condition(String fieldPath, Operator operator, String value) {

    private static final Pattern EXPRESSION_PATTERN =
            Pattern.compile("^\\{([^}]+)}\\s*(>=|<=|!=|=|>|<)\\s*(.+)$");

    public static Condition parse(String expression) {
        Matcher matcher = EXPRESSION_PATTERN.matcher(expression.trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid condition expression: " + expression);
        }
        return new Condition(matcher.group(1).trim(), Operator.fromSymbol(matcher.group(2)), matcher.group(3).trim());
    }

    public static Map<String, List<Condition>> compile(Map<String, List<String>> rawGroups) {
        Map<String, List<Condition>> compiled = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : rawGroups.entrySet()) {
            List<Condition> conditions = new ArrayList<>();
            for (String expression : entry.getValue()) {
                conditions.add(Condition.parse(expression));
            }
            compiled.put(entry.getKey(), conditions);
        }
        return compiled;
    }

    public static boolean anyGroupMatches(Map<String, List<Condition>> groups, Map<String, Object> fields) {
        return firstMatchingGroup(groups, fields) != null;
    }

    /**
     * @return the key of the first group whose conditions all match, or {@code null} if none do. The
     *         key is also what a caller surfaces as the detection "type" (e.g. name a flag group
     *         'RESIDENTIAL_PROXY' to see that exact label wherever the match is reported).
     */
    public static String firstMatchingGroup(Map<String, List<Condition>> groups, Map<String, Object> fields) {
        for (Map.Entry<String, List<Condition>> group : groups.entrySet()) {
            List<Condition> conditions = group.getValue();
            if (!conditions.isEmpty() && conditions.stream().allMatch(condition -> condition.matches(fields))) {
                return group.getKey();
            }
        }
        return null;
    }

    public boolean matches(Map<String, Object> fields) {
        return this.matchesValue(fields.get(this.fieldPath));
    }

    private boolean matchesValue(Object fieldValue) {
        if (fieldValue == null) {
            return false;
        }
        Double numericField = asNumber(fieldValue);
        Double numericTarget = asNumber(this.value);
        if (numericField != null && numericTarget != null) {
            return switch (this.operator) {
                case EQUAL -> numericField.doubleValue() == numericTarget.doubleValue();
                case NOT_EQUAL -> numericField.doubleValue() != numericTarget.doubleValue();
                case GREATER -> numericField > numericTarget;
                case GREATER_OR_EQUAL -> numericField >= numericTarget;
                case LESS -> numericField < numericTarget;
                case LESS_OR_EQUAL -> numericField <= numericTarget;
            };
        }
        String stringField = String.valueOf(fieldValue);
        return switch (this.operator) {
            case EQUAL -> stringField.equalsIgnoreCase(this.value);
            case NOT_EQUAL -> !stringField.equalsIgnoreCase(this.value);
            default -> false;
        };
    }

    private static Double asNumber(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String string) {
            try {
                return Double.parseDouble(string);
            }
            catch (NumberFormatException exception) {
                return null;
            }
        }
        return null;
    }

    public enum Operator {
        EQUAL("="),
        NOT_EQUAL("!="),
        GREATER(">"),
        GREATER_OR_EQUAL(">="),
        LESS("<"),
        LESS_OR_EQUAL("<=");

        private final String symbol;

        Operator(String symbol) {
            this.symbol = symbol;
        }

        static Operator fromSymbol(String symbol) {
            for (Operator operator : values()) {
                if (operator.symbol.equals(symbol)) {
                    return operator;
                }
            }
            throw new IllegalArgumentException("Unknown condition operator: " + symbol);
        }
    }
}
