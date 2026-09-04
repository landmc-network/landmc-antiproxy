package pl.landmc.antiproxy.iplimiter;

import dev.rollczi.litecommands.time.DurationParser;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import pl.landmc.antiproxy.config.AntiProxyConfig;

/**
 * Caps how many connections one address may hold at once.
 *
 * <p>Aimed at a bot that opens hundreds of connections from one machine, not at players: a
 * household, a student hall or a mobile carrier's NAT can legitimately put several people
 * behind one address, which is why the default is off and the limit is not one.
 *
 * <p>A slot is taken at pre-login and released on disconnect. Anything that refuses a
 * connection after taking one has to release it - see the note in the login listener, because
 * a leaked slot eventually locks out everyone sharing that address.
 */
public final class IpConnectionLimiter {

    private final boolean enabled;
    private final int maximum;
    private final Duration window;

    private final ConcurrentHashMap<String, AtomicInteger> activeCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Deque<Long>> recentConnections = new ConcurrentHashMap<>();

    public IpConnectionLimiter(AntiProxyConfig.IpLimiter config) {
        this.enabled = config.enabled;
        this.maximum = config.maximum;
        this.window = "DISABLE".equalsIgnoreCase(config.time.trim()) ? null : new DurationParser().parse(config.time);
    }

    public boolean isEnabled() {
        return this.enabled;
    }


    public boolean tryAcquire(String address) {
        if (!this.enabled) {
            return true;
        }
        return this.window != null ? this.tryAcquireWindowed(address) : this.tryAcquireCounted(address);
    }

    /**
     * Clears any tracked state for the given address, in either mode. Used by the admin
     * '/antiproxy' command to recover an address whose counter got stuck above
     * 'maximum' - e.g. a connection that was denied before ever reaching a state that would call
     * release() - without needing to restart the whole proxy.
     */
    public boolean reset(String address) {
        boolean removedActive = this.activeCounts.remove(address) != null;
        boolean removedRecent = this.recentConnections.remove(address) != null;
        return removedActive || removedRecent;
    }

    public void release(String address) {
        if (!this.enabled || this.window != null) {
            return;
        }
        this.activeCounts.computeIfPresent(address, (key, counter) -> {
            int updated = counter.decrementAndGet();
            return updated <= 0 ? null : counter;
        });
    }

    private boolean tryAcquireCounted(String address) {
        AtomicInteger counter = this.activeCounts.computeIfAbsent(address, key -> new AtomicInteger());
        int updated = counter.incrementAndGet();
        if (updated > this.maximum) {
            counter.decrementAndGet();
            return false;
        }
        return true;
    }

    private boolean tryAcquireWindowed(String address) {
        long now = System.currentTimeMillis();
        long cutoff = now - this.window.toMillis();
        boolean[] allowed = new boolean[1];
        this.recentConnections.compute(address, (key, existing) -> {
            Deque<Long> deque = existing == null ? new ArrayDeque<>() : existing;
            while (!deque.isEmpty() && deque.peekFirst() < cutoff) {
                deque.pollFirst();
            }
            if (deque.size() >= this.maximum) {
                allowed[0] = false;
            }
            else {
                deque.addLast(now);
                allowed[0] = true;
            }
            return deque.isEmpty() ? null : deque;
        });
        return allowed[0];
    }
}
