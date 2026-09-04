package pl.landmc.antiproxy;

import java.util.List;
import java.util.Locale;
import pl.landmc.antiproxy.detection.CombinationMode;

/**
 * Turns what the detection services said into one decision.
 *
 * <p>The combination mode is the whole point of allowing several services: ALL needs them to
 * agree before anybody is refused, ANY refuses on a single flag. Services that failed to answer
 * do not count towards either side - an outage should not read as agreement.
 */
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
