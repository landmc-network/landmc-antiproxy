import java.util.zip.ZipFile

plugins {
    `java-library`
    alias(libs.plugins.shadow)
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()

java {
    toolchain.languageVersion = JavaLanguageVersion.of(25)
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // Velocity 4 and platform-proxy are compiled for Java 25; --release 21 cannot read them.
    options.release = 25
    options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Xlint:unchecked", "-parameters"))
}

configurations.runtimeClasspath {
    // Velocity provides these; a second copy inside the plugin jar shadows the proxy's own.
    exclude(group = "org.slf4j", module = "slf4j-api")
    exclude(group = "net.kyori")
}

dependencies {
    compileOnly(libs.velocity.api)
    annotationProcessor(libs.velocity.api)

    implementation(libs.platform.api)
    implementation(libs.platform.common)
    implementation(libs.platform.config)
    implementation(libs.platform.database)
    implementation(libs.platform.proxy)

    // Reads GeoLite2 locally, which is what lets a known-good Polish ISP skip the paid API
    // call entirely rather than being looked up over the network.
    implementation(libs.maxmind.geoip)

    // No JDBC driver here. Velocity lets plugin class loaders see one another, so a driver
    // packaged into several plugins is defined several times over, and an object made by one
    // copy handed to code from another is a LinkageError rather than a connection. landmc-proxy
    // carries the drivers for every plugin on this proxy, and this plugin declares a hard
    // dependency on it so they are loaded before anything here asks for a connection.

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.velocity.api)
    testImplementation(libs.h2)
    testRuntimeOnly(libs.slf4j.simple)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.shadowJar {
    archiveFileName = "landmc-antiproxy.jar"

    // Gson is NOT relocated: Velocity provides it, and the detection responses are parsed with
    // the proxy's own copy rather than a second one inside this jar.
    val shaded = "pl.landmc.antiproxy.libs"
    listOf(
        "eu.okaeri",
        "dev.rollczi.litecommands",
        "com.eternalcode.multification",
        "com.zaxxer.hikari",
        "com.j256.ormlite",
        "com.maxmind",
        "org.yaml.snakeyaml",
    ).forEach { relocate(it, "$shaded.$it") }

    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/versions/**/module-info.class")
    exclude("org/jetbrains/annotations/**", "org/intellij/lang/**")

    mergeServiceFiles()
}

/**
 * Packages that must not end up inside this jar.
 *
 * A JDBC driver is looked up by name and its objects travel out of the plugin that created
 * them, so on a proxy running more than one LandMC plugin every extra copy is the same class
 * defined twice by two class loaders - which is a LinkageError, not a slower connection.
 * landmc-proxy is the one plugin that ships them.
 */
val databaseDrivers = listOf("org/h2/", "org/mariadb/")

val checkNoDatabaseDriver = tasks.register("checkNoDatabaseDriver") {
    group = "verification"
    description = "Fails when a JDBC driver is packaged into this plugin."
    dependsOn(tasks.shadowJar)

    val jarFile = tasks.shadowJar.flatMap { it.archiveFile }
    inputs.file(jarFile)

    doLast {
        val bundled = ZipFile(jarFile.get().asFile).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { name -> databaseDrivers.any { name.startsWith(it) } }
                .take(1)
                .toList()
        }

        check(bundled.isEmpty()) {
            "A JDBC driver is packaged into this plugin (${bundled.first()}). See the note " +
                "above databaseDrivers for why a second copy of one breaks at runtime."
        }
    }
}

tasks.named("check") { dependsOn(checkNoDatabaseDriver) }

tasks.build {
    dependsOn(tasks.shadowJar)
}
