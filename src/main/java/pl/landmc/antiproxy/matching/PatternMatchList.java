package pl.landmc.antiproxy.matching;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class PatternMatchList {

    private static final String REGEX_PREFIX = "regex:";

    private final Set<String> exact;
    private final List<Pattern> patterns;
    private final boolean caseInsensitive;

    public PatternMatchList(Iterable<String> rawEntries, boolean caseInsensitive) {
        this.caseInsensitive = caseInsensitive;
        Set<String> exactEntries = new HashSet<>();
        List<Pattern> compiledPatterns = new ArrayList<>();
        for (String raw : rawEntries) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String trimmed = raw.trim();
            if (trimmed.regionMatches(true, 0, REGEX_PREFIX, 0, REGEX_PREFIX.length())) {
                int flags = caseInsensitive ? Pattern.CASE_INSENSITIVE : 0;
                compiledPatterns.add(Pattern.compile(trimmed.substring(REGEX_PREFIX.length()), flags));
            }
            else {
                exactEntries.add(caseInsensitive ? trimmed.toLowerCase(Locale.ROOT) : trimmed);
            }
        }
        this.exact = Set.copyOf(exactEntries);
        this.patterns = List.copyOf(compiledPatterns);
    }

    public boolean matches(String value) {
        if (value == null) {
            return false;
        }
        String normalized = this.caseInsensitive ? value.toLowerCase(Locale.ROOT) : value;
        if (this.exact.contains(normalized)) {
            return true;
        }
        for (Pattern pattern : this.patterns) {
            if (pattern.matcher(value).matches()) {
                return true;
            }
        }
        return false;
    }
}
