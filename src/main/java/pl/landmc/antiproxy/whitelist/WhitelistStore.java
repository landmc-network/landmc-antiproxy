package pl.landmc.antiproxy.whitelist;

import eu.okaeri.configs.ConfigManager;
import eu.okaeri.configs.serdes.commons.SerdesCommons;
import eu.okaeri.configs.yaml.snakeyaml.YamlSnakeYamlConfigurer;
import java.io.File;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

public final class WhitelistStore {

    private final WhitelistConfig config;
    private final CopyOnWriteArrayList<WhitelistConfig.Entry> entries;

    public WhitelistStore(File file) {
        this.config = ConfigManager.create(WhitelistConfig.class);
        this.config.withConfigurer(new YamlSnakeYamlConfigurer(), new SerdesCommons())
                .withBindFile(file)
                .withRemoveOrphans(true)
                .saveDefaults()
                .load(true);
        this.entries = new CopyOnWriteArrayList<>(this.config.entries);
    }

    public boolean isWhitelisted(String username, String address) {
        long now = System.currentTimeMillis();
        for (WhitelistConfig.Entry entry : this.entries) {
            if (entry.isExpired(now)) {
                continue;
            }
            if (entry.matches(WhitelistTargetType.USERNAME, username)
                    || entry.matches(WhitelistTargetType.ADDRESS, address)) {
                return true;
            }
        }
        return false;
    }

    public synchronized void add(
            WhitelistTargetType type,
            String target,
            Duration duration,
            String reason,
            String addedBy
    ) {
        String normalized = normalize(type, target);
        this.entries.removeIf(entry -> entry.matches(type, normalized));
        long now = System.currentTimeMillis();
        long expiresAt = duration == null ? 0L : now + duration.toMillis();
        this.entries.add(new WhitelistConfig.Entry(type, normalized, reason, expiresAt, addedBy, now));
        this.persist();
    }

    public synchronized boolean remove(String target) {
        boolean removed = this.entries.removeIf(entry -> entry.target.equalsIgnoreCase(target));
        if (removed) {
            this.persist();
        }
        return removed;
    }

    public Optional<WhitelistConfig.Entry> info(String target) {
        long now = System.currentTimeMillis();
        return this.entries.stream()
                .filter(entry -> entry.target.equalsIgnoreCase(target) && !entry.isExpired(now))
                .findFirst();
    }

    public synchronized int purge() {
        int count = this.entries.size();
        this.entries.clear();
        this.persist();
        return count;
    }

    public List<WhitelistConfig.Entry> entries() {
        return List.copyOf(this.entries);
    }

    private void persist() {
        this.config.entries = List.copyOf(this.entries);
        this.config.save();
    }

    private static String normalize(WhitelistTargetType type, String target) {
        return type == WhitelistTargetType.USERNAME ? target.toLowerCase(Locale.ROOT) : target.trim();
    }
}
