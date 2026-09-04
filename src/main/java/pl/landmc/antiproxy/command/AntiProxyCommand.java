package pl.landmc.antiproxy.command;

import com.velocitypowered.api.command.CommandSource;
import dev.rollczi.litecommands.annotations.argument.Arg;
import dev.rollczi.litecommands.annotations.command.Command;
import dev.rollczi.litecommands.annotations.context.Context;
import dev.rollczi.litecommands.annotations.execute.Execute;
import dev.rollczi.litecommands.annotations.permission.Permission;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;
import pl.landmc.antiproxy.AntiProxyService;
import pl.landmc.antiproxy.config.AntiProxyConfig;
import pl.landmc.antiproxy.config.EnforcementMode;
import pl.landmc.antiproxy.whitelist.WhitelistStore;
import pl.landmc.antiproxy.whitelist.WhitelistTargetType;

/**
 * {@code /antiproxy} - the operator's view of what the filter is doing.
 *
 * <p>Answers in plain components rather than configurable notices: this is a staff tool whose
 * output is numbers and addresses, and nothing here is shown to a player.
 */
@Command(name = "antiproxy", aliases = "apx")
@Permission("landmc.antiproxy.admin")
public class AntiProxyCommand {

    private final AntiProxyService service;
    private final WhitelistStore whitelist;
    private final AntiProxyConfig config;
    private final Logger logger;

    public AntiProxyCommand(
            AntiProxyService service, WhitelistStore whitelist, AntiProxyConfig config, Logger logger) {

        this.service = Objects.requireNonNull(service, "service");
        this.whitelist = Objects.requireNonNull(whitelist, "whitelist");
        this.config = Objects.requireNonNull(config, "config");
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    @Execute
    void status(@Context CommandSource sender) {
        AntiProxyService.Statistics statistics = this.service.statistics();

        sender.sendMessage(line("Tryb", this.config.mode + (this.config.passive ? " (pasywny)" : "")));
        sender.sendMessage(line("Sprawdzeń", Long.toString(statistics.checks())));
        sender.sendMessage(line("Z cache", statistics.cacheHits() + " (" + hitRate(statistics) + ")"));
        sender.sendMessage(line("Zapytań do API", Long.toString(statistics.apiRequests())));
        sender.sendMessage(line("Błędów", Long.toString(statistics.failures())));
        sender.sendMessage(line("Adresów w pamięci", Integer.toString(statistics.cacheEntries())));
    }

    /**
     * Checks one address by hand.
     *
     * <p>Goes through the same path a login does, cache included, so the answer is the one a
     * player would get rather than a fresh opinion from the API.
     */
    @Execute(name = "check")
    void check(@Context CommandSource sender, @Arg("adres") String address) {
        InetAddress parsed;
        try {
            parsed = InetAddress.getByName(address);
        }
        catch (UnknownHostException exception) {
            sender.sendMessage(Component.text("Nieprawidłowy adres: " + address, NamedTextColor.RED));
            return;
        }

        sender.sendMessage(Component.text("Sprawdzam " + address + "...", NamedTextColor.GRAY));

        this.service.check("(manual)", parsed)
                .thenAccept(assessment -> sender.sendMessage(Component.text(
                        address + " -> " + assessment.level() + " (" + assessment.reason() + ")",
                        assessment.level() == pl.landmc.antiproxy.Assessment.Level.ALLOW
                                ? NamedTextColor.GREEN
                                : NamedTextColor.RED)))
                .exceptionally(throwable -> {
                    this.logger.warn("Manual check of {} failed", address, throwable);
                    sender.sendMessage(Component.text(
                            "Nie udało się sprawdzić adresu - szczegóły w konsoli.", NamedTextColor.RED));
                    return null;
                });
    }

    @Execute(name = "mode")
    void mode(@Context CommandSource sender, @Arg("tryb") EnforcementMode mode) {
        this.config.mode = mode;

        // Deliberately not saved: this is a switch for the length of an incident, and a
        // restart should bring back what the file says.
        sender.sendMessage(Component.text(
                "Tryb ustawiony na " + mode + " do restartu proxy.", NamedTextColor.GREEN));
        this.logger.warn("AntiProxy mode changed to {} by {}.", mode, sender);
    }

    @Execute(name = "whitelist add")
    void whitelistAdd(@Context CommandSource sender, @Arg("nick lub adres") String target) {
        // The type is derived rather than asked for: an operator adding an exception knows the
        // nickname or the address, not which of the store's categories it belongs to.
        WhitelistTargetType type = target.matches("[0-9a-fA-F.:]+")
                ? WhitelistTargetType.ADDRESS
                : WhitelistTargetType.USERNAME;

        this.whitelist.add(type, target, null, "added via command", sender.toString());
        sender.sendMessage(Component.text("Dodano do whitelisty: " + target, NamedTextColor.GREEN));
        this.logger.info("AntiProxy whitelist: {} added by {}.", target, sender);
    }

    @Execute(name = "whitelist remove")
    void whitelistRemove(@Context CommandSource sender, @Arg("nick lub adres") String target) {
        boolean removed = this.whitelist.remove(target);
        sender.sendMessage(removed
                ? Component.text("Usunięto z whitelisty: " + target, NamedTextColor.GREEN)
                : Component.text("Nie ma tego na whiteliście: " + target, NamedTextColor.RED));
    }

    private static Component line(String label, String value) {
        return Component.text(label + ": ", NamedTextColor.GRAY)
                .append(Component.text(value, NamedTextColor.WHITE));
    }

    private static String hitRate(AntiProxyService.Statistics statistics) {
        if (statistics.checks() == 0) {
            return "-";
        }
        return Math.round(100.0 * statistics.cacheHits() / statistics.checks()) + "%";
    }
}
