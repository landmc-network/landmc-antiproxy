package pl.landmc.antiproxy.iplimiter;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import pl.landmc.antiproxy.config.AntiProxyConfig;

class IpConnectionLimiterTest {

    @Test
    void deniesConnectionsAboveMaximumWhenDisabled() {
        IpConnectionLimiter limiter = new IpConnectionLimiter(disabledTimeConfig(2));

        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertFalse(limiter.tryAcquire("1.2.3.4"));
    }

    @Test
    void releaseFreesUpASlotInCountedMode() {
        IpConnectionLimiter limiter = new IpConnectionLimiter(disabledTimeConfig(1));

        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertFalse(limiter.tryAcquire("1.2.3.4"));

        limiter.release("1.2.3.4");

        assertTrue(limiter.tryAcquire("1.2.3.4"));
    }

    @Test
    void disabledLimiterAlwaysAllows() {
        AntiProxyConfig.IpLimiter config = disabledTimeConfig(1);
        config.enabled = false;
        IpConnectionLimiter limiter = new IpConnectionLimiter(config);

        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertTrue(limiter.tryAcquire("1.2.3.4"));
    }

    @Test
    void resetClearsAStuckCounterInCountedMode() {
        IpConnectionLimiter limiter = new IpConnectionLimiter(disabledTimeConfig(1));

        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertFalse(limiter.tryAcquire("1.2.3.4"));

        assertTrue(limiter.reset("1.2.3.4"));

        assertTrue(limiter.tryAcquire("1.2.3.4"));
    }

    @Test
    void resetReportsFalseForAnUntrackedAddress() {
        IpConnectionLimiter limiter = new IpConnectionLimiter(disabledTimeConfig(1));

        assertFalse(limiter.reset("9.9.9.9"));
    }

    @Test
    void differentAddressesAreTrackedIndependently() {
        IpConnectionLimiter limiter = new IpConnectionLimiter(disabledTimeConfig(1));

        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertTrue(limiter.tryAcquire("5.6.7.8"));
    }

    private static AntiProxyConfig.IpLimiter disabledTimeConfig(int maximum) {
        AntiProxyConfig.IpLimiter config = new AntiProxyConfig.IpLimiter();
        config.enabled = true;
        config.maximum = maximum;
        config.time = "DISABLE";
        return config;
    }
}
