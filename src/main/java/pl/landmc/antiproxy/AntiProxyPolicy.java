package pl.landmc.antiproxy;

import java.util.List;
import java.util.Locale;
import pl.landmc.antiproxy.detection.CombinationMode;

public final class AntiProxyPolicy {

    public Assessment assess(List<IpReputation> reputations, CombinationMode mode) {
        long flagged = reputations.stream().filter(IpReputation::proxy).count();
        boolean blocked = switch (mode) {
            case ALL -> flagged == reputations.size();
            case ANY -> flagged > 0;
            case MAJORITY -> flagged * 2 > reputations.size();
        };

        if (blocked) {
            String reason = mode.name().toLowerCase(Locale.ROOT) + ":" + flagged + "/" + reputations.size();
            return new Assessment(Assessment.Level.BLOCK, reason, List.copyOf(reputations), 0);
        }
        return new Assessment(Assessment.Level.ALLOW, "low-risk", List.copyOf(reputations), 0);
    }
}
