package pl.landmc.antiproxy.cache;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.DeleteBuilder;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import pl.landmc.platform.database.DatabaseService;

/**
 * The address cache that survives a restart and is shared by every proxy.
 *
 * <p>Replaces the original's own Hikari pool, its own ORMLite setup and its own single-thread
 * executor with the platform's - one bounded pool for the process instead of one per feature,
 * which is the rule the rest of the network already follows.
 *
 * <p>Shared matters as much as durable: a second proxy checking the same address finds this row
 * instead of spending another request against a per-minute quota.
 */
public final class AddressCacheRepository {

    private final DatabaseService database;

    public AddressCacheRepository(DatabaseService database) {
        this.database = Objects.requireNonNull(database, "database");
    }

    /** Creates the table on first start. Startup work, blocking. */
    public void createTables() {
        this.database.createTables(AddressCacheEntity.class);
    }

    /**
     * The stored verdict for an address, if there is a live one.
     *
     * <p>An expired row is reported as a miss and left for {@link #deleteExpired(long)} rather
     * than deleted here: a login is not the place to spend a write.
     */
    public CompletableFuture<Optional<AddressCacheEntity>> find(String address) {
        return this.database.supplyAsync(() -> {
            AddressCacheEntity stored = this.dao().queryForId(address);
            if (stored == null || stored.expiresAt <= System.currentTimeMillis()) {
                return Optional.empty();
            }
            return Optional.of(stored);
        });
    }

    public CompletableFuture<Void> put(String address, boolean blocked, String reason, long expiresAt) {
        return this.database.runAsync(() ->
                this.dao().createOrUpdate(new AddressCacheEntity(address, blocked, reason, expiresAt)));
    }

    /**
     * Drops rows that have expired.
     *
     * <p>Run at startup rather than on a timer. The table is a cache with a bounded number of
     * distinct addresses, and an expired row is already ignored on read - sweeping it is
     * housekeeping, not correctness.
     *
     * @return how many rows went, for the startup log
     */
    public int deleteExpired(long now) throws SQLException {
        DeleteBuilder<AddressCacheEntity, String> builder = this.dao().deleteBuilder();
        builder.where().le("expires_at", now);
        return builder.delete();
    }

    private Dao<AddressCacheEntity, String> dao() {
        return this.database.dao(AddressCacheEntity.class);
    }
}
