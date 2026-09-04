package pl.landmc.antiproxy.detection;

/** What one provider concluded, before it is combined with the others. */
record Detection(boolean proxy, String type) {
}
