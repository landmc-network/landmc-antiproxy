package pl.landmc.antiproxy.config;

import eu.okaeri.configs.OkaeriConfig;
import eu.okaeri.configs.annotation.Comment;
import eu.okaeri.configs.annotation.CustomKey;
import pl.landmc.platform.config.message.PlatformMessagesConfig;

/**
 * {@code messages.yml} - what a refused connection sees.
 *
 * <p>All of these are kick screens, so they are plain MiniMessage rather than Notice objects:
 * a disconnect screen is one component handed to Velocity, and there is no player left to send
 * an action bar or a title to.
 */
public class AntiProxyMessages extends OkaeriConfig {

    @Comment("Komunikaty techniczne wspolne dla calej sieci - dostarcza je landmc-platform.")
    public PlatformMessagesConfig platform = new PlatformMessagesConfig();

    @Comment("Ekran rozlaczenia po wykryciu VPN/proxy.")
    @CustomKey("blocked-kick")
    public String blockedKick =
            "<green><bold>LANDMC.PL</bold>"
                    + "<newline><newline><gray>Wykryto połączenie przez VPN lub proxy."
                    + "<newline><gray>Wyłącz je i połącz się ponownie."
                    + "<newline><gray>Jeśli to pomyłka, napisz do administracji.";

    @Comment("")
    @Comment("Ekran rozlaczenia dla zablokowanego ASN, operatora lub kraju.")
    @CustomKey("geo-blacklist-kick")
    public String geoBlacklistKick =
            "<green><bold>LANDMC.PL</bold>"
                    + "<newline><newline><gray>Połączenia od tego operatora nie są dozwolone.";

    @Comment("Ekran rozlaczenia dla nicku z czarnej listy.")
    @CustomKey("blacklist-kick")
    public String blacklistKick =
            "<green><bold>LANDMC.PL</bold>"
                    + "<newline><newline><gray>Ten nick jest zablokowany.";

    @Comment("Ekran rozlaczenia po przekroczeniu limitu polaczen z jednego adresu.")
    @CustomKey("ip-limit-kick")
    public String ipLimitKick =
            "<green><bold>LANDMC.PL</bold>"
                    + "<newline><newline><gray>Z tego adresu jest już połączonych zbyt wielu graczy.";
}
