package pl.landmc.antiproxy;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import dev.rollczi.litecommands.LiteCommands;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import pl.landmc.antiproxy.cache.AddressCacheRepository;
import pl.landmc.antiproxy.command.AntiProxyCommand;
import pl.landmc.antiproxy.config.AntiProxyConfig;
import pl.landmc.antiproxy.config.AntiProxyMessages;
import pl.landmc.antiproxy.detection.DetectionServiceClient;
import pl.landmc.antiproxy.geoip.GeoIpDatabaseUpdater;
import pl.landmc.antiproxy.geoip.GeoIpLookupService;
import pl.landmc.antiproxy.iplimiter.IpConnectionLimiter;
import pl.landmc.antiproxy.iprange.IpRangeService;
import pl.landmc.antiproxy.listener.LoginListener;
import pl.landmc.antiproxy.whitelist.WhitelistStore;
import pl.landmc.platform.api.ModuleLifecycle;
import pl.landmc.platform.component.ComponentFormatter;
import pl.landmc.platform.config.ConfigPlaceholders;
import pl.landmc.platform.config.ConfigService;
import pl.landmc.platform.database.DatabaseService;
import pl.landmc.platform.notice.AudienceNoticeService;
import pl.landmc.platform.notice.NoticeServiceProvider;
import pl.landmc.platform.proxy.command.VelocityCommands;

/**
 * Refuses connections that come through a VPN, a proxy or a datacentre.
 *
 * <p>The order of the checks is the design: a blacklisted name, a hosting ASN or a known Polish
 * ISP is decided from local data, and only what survives that reaches a paid API. On a Polish
 * network most connections never leave this process.
 *
 * <p>Two things are worth knowing before changing anything here. Every check hangs off an
 * {@code EventTask}, so a slow API delays one connection rather than the proxy. And a failing
 * detection service lets players in: an anti-VPN that closes the network when its provider has
 * an outage has caused more damage than the VPNs it was there to stop.
 */
@Plugin(
        id = "landmc-antiproxy",
        name = "LandMC AntiProxy",
        version = "1.0.0-SNAPSHOT",
        description = "Wykrywanie VPN i proxy na wejściu do sieci LandMC.",
        url = "https://github.com/landmc-network/landmc-antiproxy",
        authors = {"Crispi"})
public final class AntiProxyPlugin {

    private final ProxyServer proxy;
    private final Logger logger;
    private final Path dataDirectory;
    private final ModuleLifecycle lifecycle;

    private AntiProxyConfig config;
    private AntiProxyMessages messages;
    private AntiProxyService service;
    private DatabaseService database;
    private LiteCommands<CommandSource> commands;
    private @Nullable GeoIpLookupService geoIp;
    private @Nullable IpRangeService ipRanges;
    private @Nullable GeoIpDatabaseUpdater geoIpUpdater;

    @Inject
    public AntiProxyPlugin(ProxyServer proxy, Logger logger, @DataDirectory Path dataDirectory) {
        this.proxy = proxy;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.lifecycle = new ModuleLifecycle(logger);
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        ConfigService configs = new ConfigService(ConfigPlaceholders.forPlugin(this.dataDirectory));
        this.config = configs.load(this.dataDirectory, "config.yml", AntiProxyConfig.class);
        this.messages = configs.load(this.dataDirectory, "messages.yml", AntiProxyMessages.class);

        if (!this.config.enabled) {
            this.logger.info("AntiProxy is disabled in config.yml.");
            return;
        }

        List<DetectionServiceClient> clients = this.detectionClients();
        if (clients.isEmpty()) {
            // Deliberately not fatal. The proxy has to start; what it must not do is pretend
            // it is filtering anything.
            this.logger.error(
                    "AntiProxy is inactive: no detection service has a usable API key, so no"
                            + " connection will be checked against one.");
        }

        AddressCacheRepository cache = this.startDatabase();
        this.startGeoIp();

        WhitelistStore whitelist = new WhitelistStore(this.dataDirectory.resolve("whitelist.yml").toFile());
        this.ipRanges = new IpRangeService(this.logger, this.config.ipRange);
        IpConnectionLimiter ipLimiter = new IpConnectionLimiter(this.config.ipLimiter);

        this.service = new AntiProxyService(
                clients, new AntiProxyPolicy(), this.config, whitelist, this.ipRanges, cache);

        ComponentFormatter formatter = ComponentFormatter.standard();
        NoticeServiceProvider<CommandSource> platformNotices =
                new AudienceNoticeService<>(this.messages.platform, formatter);

        this.commands = VelocityCommands.builder(this.proxy, formatter, platformNotices, this.logger)
                .commands(new AntiProxyCommand(this.service, whitelist, this.config, this.logger))
                .build();

        this.proxy.getEventManager().register(this, new LoginListener(
                this.service,
                this.config,
                this.messages,
                formatter,
                this.geoIp,
                ipLimiter,
                whitelist,
                this.logger));

        this.logger.info(
                "AntiProxy ready in {} mode{}, {} detection service(s), GeoIP {}.",
                this.config.mode,
                this.config.passive ? " (passive)" : "",
                clients.size(),
                this.geoIp == null ? "off" : "on");
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (this.commands != null) {
            this.commands.unregister();
            this.commands = null;
        }
        if (this.geoIpUpdater != null) {
            this.geoIpUpdater.shutdown();
            this.geoIpUpdater = null;
        }
        if (this.geoIp != null) {
            this.geoIp.close();
            this.geoIp = null;
        }
        if (this.ipRanges != null) {
            this.ipRanges.shutdown();
            this.ipRanges = null;
        }

        if (this.service != null) {
            AntiProxyService.Statistics statistics = this.service.statistics();
            this.logger.info(
                    "AntiProxy stopped: checks={}, cacheHits={}, apiRequests={}, failures={}.",
                    statistics.checks(),
                    statistics.cacheHits(),
                    statistics.apiRequests(),
                    statistics.failures());
            this.service = null;
        }

        this.lifecycle.disableAll();
    }

    /**
     * Opens the shared address cache.
     *
     * <p>Shared is the point: a second proxy checking the same address finds the row instead of
     * spending another request against the per-minute quota.
     */
    private AddressCacheRepository startDatabase() {
        if (!this.config.cache.database) {
            this.logger.info("Address cache is in memory only; it will not survive a restart.");
            return null;
        }

        this.database = new DatabaseService(
                "landmc-antiproxy", this.config.database, this.dataDirectory, this.logger);
        this.lifecycle.register(this.database).enableAll();

        AddressCacheRepository repository = new AddressCacheRepository(this.database);
        repository.createTables();

        try {
            int removed = repository.deleteExpired(System.currentTimeMillis());
            if (removed > 0) {
                this.logger.info("Removed {} expired address cache entries.", removed);
            }
        }
        catch (SQLException exception) {
            this.logger.warn("Could not sweep the address cache", exception);
        }

        return repository;
    }

    private void startGeoIp() {
        if (!this.config.geoIp.enabled) {
            return;
        }

        if (this.config.geoIp.autoUpdate.enabled) {
            String licenseKey = this.readKey(
                    this.config.geoIp.autoUpdate.licenseKeyEnvironmentVariable,
                    this.config.geoIp.autoUpdate.licenseKeyFile);

            if (licenseKey == null) {
                this.logger.warn(
                        "GeoIP auto-update is on but no MaxMind licence key was found: set {} on"
                                + " this process, or put the raw key in plugins/landmc-antiproxy/{}.",
                        this.config.geoIp.autoUpdate.licenseKeyEnvironmentVariable,
                        this.config.geoIp.autoUpdate.licenseKeyFile);
            }
            else {
                // Reloads the lookup service in place when a fresh database lands, so an
                // update does not need a proxy restart to take effect.
                this.geoIpUpdater = new GeoIpDatabaseUpdater(
                        this.logger,
                        licenseKey,
                        this.dataDirectory.toFile(),
                        this.config.geoIp,
                        () -> {
                            if (this.geoIp != null) {
                                this.geoIp.reload();
                            }
                        });
                this.geoIpUpdater.start();
            }
        }

        this.geoIp = GeoIpLookupService.load(this.logger, this.config.geoIp, this.dataDirectory.toFile());
    }

    private List<DetectionServiceClient> detectionClients() {
        List<DetectionServiceClient> clients = new ArrayList<>();

        for (AntiProxyConfig.Service serviceConfig : this.config.services) {
            if (!serviceConfig.enabled) {
                continue;
            }

            String name = serviceConfig.name.isBlank() ? serviceConfig.url : serviceConfig.name;
            String key = this.readKey(serviceConfig.keyEnvironmentVariable, serviceConfig.keyFile);
            if (key == null) {
                this.logger.error(
                        "Detection service '{}' is inactive: set the environment variable {}, or"
                                + " put only the raw key in plugins/landmc-antiproxy/{}.",
                        name, serviceConfig.keyEnvironmentVariable, serviceConfig.keyFile);
                continue;
            }

            clients.add(new DetectionServiceClient(
                    this.config.api, serviceConfig, key, this.logger, this.config.debug));
        }

        return clients;
    }

    /**
     * An API key, from the environment or from a file next to the configuration.
     *
     * <p>Never from config.yml itself. A key in the configuration ends up in a paste when
     * somebody asks for help with their settings, which is how a paid quota becomes somebody
     * else's.
     */
    private @Nullable String readKey(String environmentVariable, String fileName) {
        String fromEnvironment = System.getenv(environmentVariable);
        if (fromEnvironment != null && !fromEnvironment.isBlank()) {
            return fromEnvironment.trim();
        }

        Path file = this.dataDirectory.resolve(fileName);
        if (!Files.isRegularFile(file)) {
            return null;
        }

        try {
            String key = Files.readString(file, StandardCharsets.UTF_8).trim();
            return key.isEmpty() ? null : key;
        }
        catch (IOException exception) {
            this.logger.warn("Could not read {}", file, exception);
            return null;
        }
    }
}
