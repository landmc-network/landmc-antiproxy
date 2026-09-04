package pl.landmc.antiproxy.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import java.net.InetAddress;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import net.kyori.adventure.text.Component;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import pl.landmc.antiproxy.AntiProxyService;
import pl.landmc.antiproxy.Assessment;
import pl.landmc.antiproxy.config.AntiProxyConfig;
import pl.landmc.antiproxy.config.AntiProxyMessages;
import pl.landmc.antiproxy.config.EnforcementMode;
import pl.landmc.antiproxy.geoip.GeoIpLookupService;
import pl.landmc.antiproxy.geoip.GeoMatcher;
import pl.landmc.antiproxy.iplimiter.IpConnectionLimiter;
import pl.landmc.antiproxy.matching.PatternMatchList;
import pl.landmc.antiproxy.whitelist.WhitelistStore;
import pl.landmc.platform.component.ComponentFormatter;

/**
 * Decides who gets in, in the order that costs least.
 *
 * <p>Every check that can be answered from memory runs before the one that cannot. A blacklisted
 * name, a datacentre ASN or a Polish ISP is settled from local data; only what is left reaches
 * an external service, which is both the slow step and the one that is paid for per request.
 *
 * <p>The whole thing hangs off {@link EventTask}, so the connection waits without a proxy thread
 * waiting with it. Nothing here blocks and nothing calls {@code join()}: a login that stalls on
 * an unreachable API would stall every other login behind it.
 */
public final class LoginListener {

    private final AntiProxyService service;
    private final AntiProxyConfig config;
    private final AntiProxyMessages messages;
    private final ComponentFormatter formatter;
    private final Logger logger;

    private final @Nullable GeoIpLookupService geoIp;
    private final @Nullable IpConnectionLimiter ipLimiter;
    private final @Nullable WhitelistStore whitelist;
    private final PatternMatchList blacklistedUsernames;
    private final PatternMatchList allowedUsernames;
    private final PatternMatchList allowedAddresses;

    public LoginListener(
            AntiProxyService service,
            AntiProxyConfig config,
            AntiProxyMessages messages,
            ComponentFormatter formatter,
            @Nullable GeoIpLookupService geoIp,
            @Nullable IpConnectionLimiter ipLimiter,
            @Nullable WhitelistStore whitelist,
            Logger logger) {

        this.service = Objects.requireNonNull(service, "service");
        this.config = Objects.requireNonNull(config, "config");
        this.messages = Objects.requireNonNull(messages, "messages");
        this.formatter = Objects.requireNonNull(formatter, "formatter");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.geoIp = geoIp;
        this.ipLimiter = ipLimiter;
        this.whitelist = whitelist;

        // Compiled once. These are matched for every connection, and compiling a pattern per
        // login is exactly the kind of work that belongs at startup.
        this.blacklistedUsernames = new PatternMatchList(config.blacklist.usernames, true);
        this.allowedUsernames = new PatternMatchList(config.allowlist.usernames, true);
        this.allowedAddresses = new PatternMatchList(config.allowlist.addresses, false);
    }

    @Subscribe(order = PostOrder.FIRST)
    public EventTask onPreLogin(PreLoginEvent event) {
        if (!event.getResult().isAllowed()) {
            return null;
        }

        InetAddress address = event.getConnection().getRemoteAddress().getAddress();
        String hostAddress = address.getHostAddress();
        String username = event.getUsername();
        boolean exempt = this.isExempt(username, hostAddress);

        if (!exempt && this.blacklistedUsernames.matches(username)) {
            this.deny(event, this.messages.blacklistKick);
            this.logger.warn("Blocked {} ({}): username blacklist.", username, hostAddress);
            return null;
        }

        if (!exempt && this.matchesGeoBlacklist(address)) {
            this.deny(event, this.messages.geoBlacklistKick);
            this.logger.warn("Blocked {} ({}): ASN, ISP or country rule.", username, hostAddress);
            return null;
        }

        if (this.ipLimiter != null && this.ipLimiter.isEnabled() && !this.ipLimiter.tryAcquire(hostAddress)) {
            this.deny(event, this.messages.ipLimitKick);
            return null;
        }

        // A known-good ISP never reaches the paid API: resolved from the local GeoLite2 files,
        // with no request at all. On a Polish network this is most connections.
        if (this.matchesGeoAllowlist(address)) {
            return null;
        }

        if (exempt || this.config.passive) {
            return null;
        }

        return EventTask.resumeWhenComplete(this.service.check(username, address)
                .thenAccept(assessment -> this.apply(event, assessment, username, hostAddress))
                .exceptionally(throwable -> {
                    // A detection service that is down must not close the network. The failure
                    // is logged once per cause by the service itself; here the player gets in.
                    this.logger.warn(
                            "Letting {} ({}) through: the check could not be completed ({}).",
                            username, hostAddress, rootCause(throwable));
                    return null;
                }));
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        if (this.ipLimiter != null) {
            this.ipLimiter.release(event.getPlayer().getRemoteAddress().getAddress().getHostAddress());
        }
    }

    private void apply(PreLoginEvent event, Assessment assessment, String username, String hostAddress) {
        if (assessment.level() == Assessment.Level.ALLOW) {
            return;
        }

        if (this.config.mode == EnforcementMode.MONITOR) {
            this.logger.warn(
                    "Would block {} ({}): {} [vl={}].",
                    username, hostAddress, assessment.reason(), assessment.violationLevel());
            return;
        }

        this.logger.warn(
                "Blocked {} ({}): {} [vl={}].",
                username, hostAddress, assessment.reason(), assessment.violationLevel());

        // The limiter reserved a slot for this address above. A denial here means the connection
        // never becomes a player, so DisconnectEvent - which normally frees that slot - never
        // fires for it. Left alone the slot leaks, and eventually locks out everyone behind the
        // same NAT or mobile carrier.
        if (this.ipLimiter != null) {
            this.ipLimiter.release(hostAddress);
        }

        this.deny(event, this.messages.blockedKick);
    }

    private boolean matchesGeoBlacklist(InetAddress address) {
        return this.geoIp != null
                && GeoMatcher.matches(
                        this.geoIp,
                        address,
                        this.config.geoBlacklist.asns,
                        this.config.geoBlacklist.isps,
                        this.config.geoBlacklist.countries);
    }

    private boolean matchesGeoAllowlist(InetAddress address) {
        return this.geoIp != null
                && GeoMatcher.matches(
                        this.geoIp,
                        address,
                        this.config.allowlist.asns,
                        this.config.allowlist.isps,
                        this.config.allowlist.countries);
    }

    /** Staff and known addresses skip every check, including the blacklist. */
    private boolean isExempt(String username, String address) {
        return this.allowedUsernames.matches(username)
                || this.allowedAddresses.matches(address)
                || (this.whitelist != null && this.whitelist.isWhitelisted(username, address));
    }

    private void deny(PreLoginEvent event, String message) {
        event.setResult(PreLoginEvent.PreLoginComponentResult.denied(this.kickScreen(message)));
    }

    /**
     * A kick screen is a single component handed to Velocity, so it is a MiniMessage string
     * rather than a Notice - there is no player left to send an action bar to.
     */
    private Component kickScreen(String message) {
        return this.formatter.format(message);
    }

    private static String rootCause(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return message == null ? current.getClass().getSimpleName() : message;
    }
}
