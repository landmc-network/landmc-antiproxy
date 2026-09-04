package pl.landmc.antiproxy.detection;

/**
 * How several detection services are combined into one verdict.
 *
 * <p>Services that failed to answer count towards neither side: an outage must not read as
 * agreement.
 */
public enum CombinationMode {
    ALL,
    ANY,
    MAJORITY
}
