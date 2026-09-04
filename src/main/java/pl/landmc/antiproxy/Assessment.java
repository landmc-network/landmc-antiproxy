package pl.landmc.antiproxy;

import java.util.List;

/**
 * The decision about one address, and why.
 *
 * <p>The reason is kept in the provider's own words rather than translated: it goes to the log
 * for staff to read, never to the player, who sees the configured kick screen.
 */
public record Assessment(Level level, String reason, List<IpReputation> reputations, int violationLevel) {

    public enum Level {
        ALLOW,
        BLOCK
    }

    public static Assessment allow(String reason) {
        return new Assessment(Level.ALLOW, reason, List.of(), 0);
    }

    public Assessment withViolationLevel(int violationLevel) {
        return new Assessment(this.level, this.reason, this.reputations, violationLevel);
    }
}
