package pl.landmc.antiproxy.matching;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PatternMatchListTest {

    @Test
    void exactMatchIsCaseInsensitiveWhenConfigured() {
        PatternMatchList list = new PatternMatchList(List.of("Notch"), true);

        assertTrue(list.matches("notch"));
        assertTrue(list.matches("NOTCH"));
        assertFalse(list.matches("jeb_"));
    }

    @Test
    void exactMatchIsCaseSensitiveWhenConfigured() {
        PatternMatchList list = new PatternMatchList(List.of("1.2.3.4"), false);

        assertTrue(list.matches("1.2.3.4"));
        assertFalse(list.matches("1.2.3.5"));
    }

    @Test
    void regexPrefixCompilesAndMatchesPattern() {
        PatternMatchList list = new PatternMatchList(List.of("regex:^Alt_.*$"), true);

        assertTrue(list.matches("Alt_123"));
        assertTrue(list.matches("alt_abc"));
        assertFalse(list.matches("RealPlayer"));
    }

    @Test
    void mixesExactAndRegexEntries() {
        PatternMatchList list = new PatternMatchList(List.of("Notch", "regex:^Bot\\d+$"), true);

        assertTrue(list.matches("notch"));
        assertTrue(list.matches("Bot42"));
        assertFalse(list.matches("Bot"));
    }

    @Test
    void blankAndNullEntriesAreIgnored() {
        PatternMatchList list = new PatternMatchList(java.util.Arrays.asList("", "  ", null, "Notch"), true);

        assertTrue(list.matches("Notch"));
        assertFalse(list.matches(""));
    }
}
