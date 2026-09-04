pluginManagement {
    repositories {
        gradlePluginPortal()
    }
}

plugins {
    // Provisions a JDK 25 when the machine does not have one; Velocity 4 and the platform's
    // proxy module both publish Java 25 bytecode.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS

    repositories {
        // The platform is consumed as a published artifact, not as an included build: every
        // LandMC project is its own repository.
        //
        // mavenLocal first, so a platform built locally with publishToMavenLocal wins over the
        // published snapshot while both are being worked on. CI has no local cache, so there
        // it resolves from GitHub Packages.
        mavenLocal()

        // GitHub Packages requires authentication even for a public package, so a checkout
        // without credentials cannot resolve the platform at all. gpr.user/gpr.token come from
        // ~/.gradle/gradle.properties on a developer machine and from the workflow in CI; the
        // repository is only declared when they exist, so `mavenLocal` development still works
        // with no GitHub configuration at all.
        val githubUser: String? = providers.gradleProperty("gpr.user").orNull
        val githubToken: String? = providers.gradleProperty("gpr.token").orNull
        if (githubUser != null && githubToken != null) {
            maven("https://maven.pkg.github.com/landmc-network/landmc-platform") {
                name = "GitHubPackages"
                credentials {
                    username = githubUser
                    password = githubToken
                }
                // Nothing else lives here, and every miss is a round trip with a login.
                content { includeGroup("pl.landmc") }
            }
        }

        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/") {
            content {
                includeGroup("com.velocitypowered")
                includeGroup("com.mojang")
                includeGroup("net.md-5")
            }
        }
        maven("https://repo.codemc.io/repository/maven-releases/") {
            content { includeGroup("com.github.retrooper") }
        }
        maven("https://repo.panda-lang.org/releases/") {
            content { includeGroup("dev.rollczi") }
        }
        maven("https://repo.eternalcode.pl/releases/") {
            content { includeGroup("com.eternalcode") }
        }
        maven("https://storehouse.okaeri.eu/repository/maven-public/") {
            content { includeGroup("eu.okaeri") }
        }
    }
}

rootProject.name = "landmc-antiproxy"
