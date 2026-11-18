// Copyright 2026 Anapaya Systems

/*
 * An app outside the engine build. It gets the engine from a Maven repository,
 * as an app does, and sends a request over the test network in the test
 * process. CI runs it against the publication of a release.
 *
 * Usage, in the engine directory:
 *
 *   ./gradlew -p tests/consumer -PscionRepository=<repository> allTests testAndroidHostTest
 *
 * Without -PscionRepository, it uses build/repository of the engine build.
 * -PsdkVersion selects a version. The default is the newest one.
 */

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") { from(files("../../gradle/libs.versions.toml")) }
    }

    val repository = providers.gradleProperty("scionRepository")
        .map { file(it) }
        .getOrElse(settingsDir.resolve("../../build/repository"))
    repositories {
        // Only this repository supplies the engine, also when Maven Central
        // has other versions.
        exclusiveContent {
            forRepository { maven(repository) }
            filter { includeGroup("net.anapaya.scion") }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "consumer"
