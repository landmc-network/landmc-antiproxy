package pl.landmc.antiproxy.whitelist;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

class WhitelistStoreTest {

    // Okaeri/SnakeYAML can keep the bound file briefly locked on Windows after the test.
    @TempDir(cleanup = CleanupMode.NEVER)
    Path temporaryDirectory;

    @Test
    void permanentEntryStaysWhitelistedAcrossReload() {
        File file = this.temporaryDirectory.resolve("whitelist.yml").toFile();
        WhitelistStore store = new WhitelistStore(file);

        store.add(WhitelistTargetType.USERNAME, "Notch", null, "trusted", "console");

        assertTrue(store.isWhitelisted("notch", "9.9.9.9"));

        WhitelistStore reloaded = new WhitelistStore(file);
        assertTrue(reloaded.isWhitelisted("Notch", "9.9.9.9"));
    }

    @Test
    void expiredEntryIsNotWhitelisted() {
        File file = this.temporaryDirectory.resolve("expired.yml").toFile();
        WhitelistStore store = new WhitelistStore(file);

        store.add(WhitelistTargetType.ADDRESS, "1.2.3.4", Duration.ofMillis(-1), "temp", "console");

        assertFalse(store.isWhitelisted("someone", "1.2.3.4"));
    }

    @Test
    void removeDeletesEntryByTarget() {
        File file = this.temporaryDirectory.resolve("remove.yml").toFile();
        WhitelistStore store = new WhitelistStore(file);
        store.add(WhitelistTargetType.ADDRESS, "1.2.3.4", null, "", "console");

        assertTrue(store.remove("1.2.3.4"));
        assertFalse(store.isWhitelisted("someone", "1.2.3.4"));
        assertFalse(store.remove("1.2.3.4"));
    }

    @Test
    void purgeClearsAllEntries() {
        File file = this.temporaryDirectory.resolve("purge.yml").toFile();
        WhitelistStore store = new WhitelistStore(file);
        store.add(WhitelistTargetType.USERNAME, "Alice", null, "", "console");
        store.add(WhitelistTargetType.ADDRESS, "1.2.3.4", null, "", "console");

        int purged = store.purge();

        assertTrue(purged == 2);
        assertFalse(store.isWhitelisted("alice", "1.2.3.4"));
    }
}
