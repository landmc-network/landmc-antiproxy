package pl.landmc.antiproxy.whitelist;

import eu.okaeri.configs.OkaeriConfig;
import java.util.ArrayList;
import java.util.List;

public final class WhitelistConfig extends OkaeriConfig {

    public List<Entry> entries = new ArrayList<>();

    public static final class Entry extends OkaeriConfig {

        public WhitelistTargetType type = WhitelistTargetType.USERNAME;
        public String target = "";
        public String reason = "";
        public long expiresAtEpochMillis = 0L;
        public String addedBy = "console";
        public long createdAtEpochMillis = 0L;

        public Entry() {
        }

        public Entry(
                WhitelistTargetType type,
                String target,
                String reason,
                long expiresAtEpochMillis,
                String addedBy,
                long createdAtEpochMillis
        ) {
            this.type = type;
            this.target = target;
            this.reason = reason;
            this.expiresAtEpochMillis = expiresAtEpochMillis;
            this.addedBy = addedBy;
            this.createdAtEpochMillis = createdAtEpochMillis;
        }

        public boolean isExpired(long nowEpochMillis) {
            return this.expiresAtEpochMillis > 0L && this.expiresAtEpochMillis <= nowEpochMillis;
        }

        public boolean matches(WhitelistTargetType targetType, String normalizedTarget) {
            return this.type == targetType && this.target.equalsIgnoreCase(normalizedTarget);
        }
    }
}
