package pl.landmc.antiproxy.detection;

/** The shape of a provider's response: parsed as JSON, or searched as text. */
public enum ResponseModel {
    JSON,
    HTML,
    CONTAINS
}
