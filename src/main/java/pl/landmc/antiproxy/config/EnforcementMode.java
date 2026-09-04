package pl.landmc.antiproxy.config;

/**
 * Whether the filter acts on what it finds.
 *
 * <p>MONITOR exists because an anti-VPN is worth reading for a while before it starts refusing
 * players: the allowlists need tuning against real traffic, and a false positive in ENFORCE is
 * a player who cannot join.
 */
public enum EnforcementMode {
    MONITOR,
    ENFORCE
}
