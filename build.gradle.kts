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

    runtimeOnly(libs.h2)
    runtimeOnly(libs.mariadb)

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
 * Packages that must reach the runtime under their real names.
 *
 * H2 because its file format records class names; the JDBC drivers because the platform looks
 * them up by name and because a driver registers through META-INF/services, which a relocation
 * rewrites out from under it.
 */
val relocatedDatabaseLibraries = listOf("org/h2/", "org/mariadb/")

val checkDatabaseNotRelocated = tasks.register("checkDatabaseNotRelocated") {
    group = "verification"
    description = "Fails when a database library ends up relocated."
    dependsOn(tasks.shadowJar)

    val jarFile = tasks.shadowJar.flatMap { it.archiveFile }
    inputs.file(jarFile)

    doLast {
        val relocated = ZipFile(jarFile.get().asFile).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { name -> relocatedDatabaseLibraries.any { name.startsWith("pl/landmc/antiproxy/libs/$it") } }
                .take(1)
                .toList()
        }

        check(relocated.isEmpty()) {
            "A database library is relocated (${relocated.first()}). See the note above " +
                "relocatedDatabaseLibraries for why that breaks at runtime rather than at build time."
        }
    }
}

tasks.named("check") { dependsOn(checkDatabaseNotRelocated) }

tasks.build {
    dependsOn(tasks.shadowJar)
}
