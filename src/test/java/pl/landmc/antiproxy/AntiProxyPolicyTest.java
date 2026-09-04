package pl.landmc.antiproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import pl.landmc.antiproxy.detection.CombinationMode;

class AntiProxyPolicyTest {

    private final AntiProxyPolicy policy = new AntiProxyPolicy();

    @Test
    void singleServiceBlocksOnProxy() {
        Assessment result = this.policy.assess(List.of(new IpReputation("1.2.3.4", true)), CombinationMode.ANY);

        assertEquals(Assessment.Level.BLOCK, result.level());
    }

    @Test
    void singleServiceAllowsWhenClean() {
        Assessment result = this.policy.assess(List.of(new IpReputation("1.2.3.4", false)), CombinationMode.ALL);

        assertEquals(Assessment.Level.ALLOW, result.level());
        assertEquals("low-risk", result.reason());
    }

    @Test
    void anyModeBlocksWhenOnlyOneOfTwoFlags() {
        List<IpReputation> reputations = List.of(
                new IpReputation("1.2.3.4", true),
                new IpReputation("1.2.3.4", false));

        assertEquals(Assessment.Level.BLOCK, this.policy.assess(reputations, CombinationMode.ANY).level());
    }

    @Test
    void allModeRequiresEveryServiceToAgree() {
        List<IpReputation> reputations = List.of(
                new IpReputation("1.2.3.4", true),
                new IpReputation("1.2.3.4", false));

        assertEquals(Assessment.Level.ALLOW, this.policy.assess(reputations, CombinationMode.ALL).level());
    }

    @Test
    void allModeBlocksWhenEveryServiceAgrees() {
        List<IpReputation> reputations = List.of(
                new IpReputation("1.2.3.4", true),
                new IpReputation("1.2.3.4", true));

        assertEquals(Assessment.Level.BLOCK, this.policy.assess(reputations, CombinationMode.ALL).level());
    }

    @Test
    void majorityModeNeedsMoreThanHalf() {
        List<IpReputation> reputations = List.of(
                new IpReputation("1.2.3.4", true),
                new IpReputation("1.2.3.4", true),
                new IpReputation("1.2.3.4", false));

        assertEquals(Assessment.Level.BLOCK, this.policy.assess(reputations, CombinationMode.MAJORITY).level());
    }

    @Test
    void majorityModeAllowsOnATie() {
        List<IpReputation> reputations = List.of(
                new IpReputation("1.2.3.4", true),
                new IpReputation("1.2.3.4", false));

        assertEquals(Assessment.Level.ALLOW, this.policy.assess(reputations, CombinationMode.MAJORITY).level());
    }
}
