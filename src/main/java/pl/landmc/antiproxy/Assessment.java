package pl.landmc.antiproxy;

import java.util.List;

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
