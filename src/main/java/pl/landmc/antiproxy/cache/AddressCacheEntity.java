package pl.landmc.antiproxy.cache;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * One address and what the detection services said about it.
 *
 * <p>The row exists so a paid lookup is not repeated - by this proxy after a restart, or by
 * another proxy that has never seen the address. Everything about it is a cache: losing the
 * table costs money and latency, never correctness.
 *
 * <p>{@code expires_at} is indexed because the only query that is not a lookup by address is
 * the sweep that deletes what has expired.
 */
@DatabaseTable(tableName = "antiproxy_address_cache")
public class AddressCacheEntity {

    /** 45 characters is the longest an IPv6 address with an embedded IPv4 can be. */
    @DatabaseField(id = true, columnName = "address", width = 45)
    public String address;

    @DatabaseField(canBeNull = false, columnName = "blocked")
    public boolean blocked;

    @DatabaseField(canBeNull = false, columnName = "reason", width = 64)
    public String reason;

    @DatabaseField(columnName = "expires_at", index = true)
    public long expiresAt;

    /** Required by ORMLite. */
    public AddressCacheEntity() {
    }

    AddressCacheEntity(String address, boolean blocked, String reason, long expiresAt) {
        this.address = address;
        this.blocked = blocked;
        this.reason = reason;
        this.expiresAt = expiresAt;
    }
}
