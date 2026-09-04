package pl.landmc.antiproxy;

import java.net.InetAddress;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import pl.landmc.antiproxy.config.AntiProxyConfig;
import pl.landmc.antiproxy.cache.AddressCacheEntity;
import pl.landmc.antiproxy.cache.AddressCacheRepository;
import pl.landmc.antiproxy.detection.DetectionServiceClient;
import pl.landmc.antiproxy.iprange.IpRangeService;
import pl.landmc.antiproxy.matching.PatternMatchList;
import pl.landmc.antiproxy.whitelist.WhitelistStore;

public final class AntiProxyService {

    private static final long RATE_WINDOW_MILLIS = 60_000L;

    private final List<DetectionServiceClient> clients;
    private final AntiProxyPolicy policy;
    private final AntiProxyConfig config;
    private final WhitelistStore whitelistStore;
    private final IpRangeService ipRangeService;
    private final AddressCacheRepository cacheRepository;
    private final PatternMatchList allowedUsernames;
    private final PatternMatchList allowedAddresses;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CompletableFuture<Assessment>> inFlight = new ConcurrentHashMap<>();
    // Counts how many times each address has been freshly flagged BLOCK (cache hits don't recount -
    // they reuse the assessment computed on the flagging check), so the log can show a rising
    // "vl" that tells a one-off false positive apart from a persistent proxy/VPN address.
    private final ConcurrentHashMap<String, AtomicInteger> violationCounters = new ConcurrentHashMap<>();
    private final Semaphore requestPermits;
    private final AtomicLong rateWindowStarted = new AtomicLong(System.currentTimeMillis());
    private final AtomicInteger rateWindowRequests = new AtomicInteger();
    private final LongAdder checks = new LongAdder();
    private final LongAdder cacheHits = new LongAdder();
    private final LongAdder apiRequests = new LongAdder();
    private final LongAdder failures = new LongAdder();

    public AntiProxyService(
            List<DetectionServiceClient> clients,
            AntiProxyPolicy policy,
            AntiProxyConfig config,
            WhitelistStore whitelistStore,
            IpRangeService ipRangeService,
            AddressCacheRepository cacheRepository
    ) {
        this.clients = List.copyOf(clients);
        this.policy = policy;
        this.config = config;
        this.whitelistStore = whitelistStore;
        this.ipRangeService = ipRangeService;
        this.cacheRepository = cacheRepository;
        this.allowedUsernames = new PatternMatchList(config.allowlist.usernames, true);
        this.allowedAddresses = new PatternMatchList(config.allowlist.addresses, false);
        this.requestPermits = new Semaphore(config.api.maximumConcurrentRequests);
    }

    public CompletableFuture<Assessment> check(String username, InetAddress inetAddress) {
        this.checks.increment();
        String address = inetAddress.getHostAddress();
        if (this.allowedUsernames.matches(username)) {
            return CompletableFuture.completedFuture(Assessment.allow("username-allowlist"));
        }
        if (this.allowedAddresses.matches(address)) {
            return CompletableFuture.completedFuture(Assessment.allow("address-allowlist"));
        }
        if (this.whitelistStore != null && this.whitelistStore.isWhitelisted(username, address)) {
            return CompletableFuture.completedFuture(Assessment.allow("whitelist"));
        }
        if (this.config.allowlist.privateAddresses && isPrivate(inetAddress)) {
            return CompletableFuture.completedFuture(Assessment.allow("private-address"));
        }
        if (this.ipRangeService != null && this.ipRangeService.contains(inetAddress)) {
            Assessment blocked = new Assessment(Assessment.Level.BLOCK, "ip-range", List.of(), 0);
            this.putCache(address, blocked);
            return CompletableFuture.completedFuture(blocked);
        }

        CacheEntry cached = this.cache.get(address);
        long now = System.nanoTime();
        if (cached != null && cached.expiresAtNanos > now) {
            this.cacheHits.increment();
            return CompletableFuture.completedFuture(cached.assessment);
        }
        if (cached != null) {
            this.cache.remove(address, cached);
        }

        if (this.cacheRepository != null) {
            return this.cacheRepository.find(address).thenCompose(databaseHit -> {
                if (databaseHit.isPresent()) {
                    this.cacheHits.increment();
                    AddressCacheEntity entity = databaseHit.get();
                    Assessment assessment = fromEntity(entity);
                    this.cache.put(address, new CacheEntry(assessment, nanosFromEpochMillis(entity.expiresAt)));
                    return CompletableFuture.completedFuture(assessment);
                }
                return this.lookupWithDeduplication(address);
            });
        }

        return this.lookupWithDeduplication(address);
    }

    public Statistics statistics() {
        return new Statistics(
                this.checks.sum(),
                this.cacheHits.sum(),
                this.apiRequests.sum(),
                this.failures.sum(),
                this.cache.size());
    }

    private CompletableFuture<Assessment> lookupWithDeduplication(String address) {
        CompletableFuture<Assessment> future = this.inFlight.computeIfAbsent(address, this::startLookup);
        future.whenComplete((result, exception) -> this.inFlight.remove(address, future));
        return future;
    }

    private CompletableFuture<Assessment> startLookup(String address) {
        if (!this.requestPermits.tryAcquire()) {
            this.failures.increment();
            return CompletableFuture.failedFuture(new CheckUnavailableException("concurrency limit reached"));
        }
        if (!this.acquireRateLimit()) {
            this.requestPermits.release();
            this.failures.increment();
            return CompletableFuture.failedFuture(new CheckUnavailableException("request rate limit reached"));
        }

        this.apiRequests.add(this.clients.size());
        List<CompletableFuture<IpReputation>> lookups = this.clients.stream()
                .map(client -> client.lookup(address).handle((reputation, exception) -> exception == null ? reputation : null))
                .toList();

        return CompletableFuture.allOf(lookups.toArray(CompletableFuture[]::new))
                .thenApply(ignored -> lookups.stream()
                        .map(CompletableFuture::join)
                        .filter(Objects::nonNull)
                        .toList())
                .thenApply(reputations -> {
                    if (reputations.isEmpty()) {
                        throw new CheckUnavailableException("all detection services failed");
                    }
                    return this.policy.assess(reputations, this.config.combination);
                })
                .thenApply(assessment -> {
                    Assessment withViolationLevel = assessment.level() == Assessment.Level.BLOCK
                            ? assessment.withViolationLevel(this.violationCounters
                                    .computeIfAbsent(address, ignored -> new AtomicInteger())
                                    .incrementAndGet())
                            : assessment;
                    this.putCache(address, withViolationLevel);
                    return withViolationLevel;
                })
                .whenComplete((result, exception) -> {
                    this.requestPermits.release();
                    if (exception != null) {
                        this.failures.increment();
                    }
                });
    }

    private synchronized boolean acquireRateLimit() {
        long now = System.currentTimeMillis();
        long started = this.rateWindowStarted.get();
        if (now - started >= RATE_WINDOW_MILLIS) {
            this.rateWindowStarted.set(now);
            this.rateWindowRequests.set(0);
        }
        return this.rateWindowRequests.incrementAndGet() <= this.config.api.maximumRequestsPerMinute;
    }

    private void putCache(String address, Assessment assessment) {
        if (this.cache.size() >= this.config.cache.maximumEntries) {
            this.removeExpiredEntries();
        }
        if (this.cache.size() >= this.config.cache.maximumEntries) {
            this.cache.keySet().stream().findAny().ifPresent(this.cache::remove);
        }
        long ttlMillis = assessment.level() == Assessment.Level.ALLOW
                ? this.config.cache.allowedTtlMillis
                : this.config.cache.riskyTtlMillis;
        this.cache.put(address, new CacheEntry(assessment, System.nanoTime() + ttlMillis * 1_000_000L));
        if (this.cacheRepository != null) {
            this.cacheRepository.put(
                    address,
                    assessment.level() != Assessment.Level.ALLOW,
                    assessment.reason(),
                    System.currentTimeMillis() + ttlMillis);
        }
    }

    private void removeExpiredEntries() {
        long now = System.nanoTime();
        this.cache.entrySet().removeIf(entry -> entry.getValue().expiresAtNanos <= now);

        // The violation counters were never cleaned in the original: one entry per address ever
        // flagged, kept for the lifetime of the proxy. They exist to tell a one-off false
        // positive from a persistent VPN address, which only means anything while that address
        // is still in the cache.
        this.violationCounters.keySet().removeIf(address -> !this.cache.containsKey(address));
    }

    private static Assessment fromEntity(AddressCacheEntity entity) {
        Assessment.Level level = entity.blocked ? Assessment.Level.BLOCK : Assessment.Level.ALLOW;
        return new Assessment(level, entity.reason, List.of(), 0);
    }

    private static long nanosFromEpochMillis(long expiresAtEpochMillis) {
        long remainingMillis = Math.max(0L, expiresAtEpochMillis - System.currentTimeMillis());
        return System.nanoTime() + remainingMillis * 1_000_000L;
    }

    private static boolean isPrivate(InetAddress address) {
        return address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress();
    }

    private record CacheEntry(Assessment assessment, long expiresAtNanos) {
    }

    public record Statistics(long checks, long cacheHits, long apiRequests, long failures, int cacheEntries) {
    }

    public static final class CheckUnavailableException extends RuntimeException {

        public CheckUnavailableException(String message) {
            super(message);
        }
    }
}
