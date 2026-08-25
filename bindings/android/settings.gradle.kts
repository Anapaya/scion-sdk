// Copyright 2026 Anapaya Systems

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // For the sample app built against a released AAR rather than against the module here; see
        // the scionSdkVersion property in hello-scion/build.gradle.kts.
        mavenLocal()
    }
}

// Every value here has a fallback, so that tasks needing none of cargo's output, a lint-only
// invocation say, still work without a Rust toolchain.
val cargoWorkspaceDir = settingsDir.resolve("../..").canonicalFile

@Suppress("UNCHECKED_CAST")
val cargoMetadata: Map<String, Any>? =
    runCatching {
        val process =
            ProcessBuilder("cargo", "metadata", "--format-version", "1", "--no-deps")
                .directory(cargoWorkspaceDir)
                .redirectErrorStream(false)
                .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "cargo metadata failed" }
        groovy.json.JsonSlurper().parseText(output) as Map<String, Any>
    }.getOrElse {
        logger.info("could not run cargo metadata: $it")
        null
    }

gradle.extra["cargoTargetDir"] =
    cargoMetadata?.let { File(it["target_directory"] as String) }
        ?: cargoWorkspaceDir.resolve("target").also {
            logger.info("assuming the default cargo target directory: $it")
        }

// The version the AAR is published under, taken from the SDK's own crates rather than kept in a
// Gradle property, so that `sdk-releaser bump` needs to know nothing about Android and the two can
// not drift.
val sdkVersionCrate = "scion-stack"

// What a build falls back to when cargo cannot be reached. Publishing refuses it; see
// checkPublishVersion in scion-http3-android/build.gradle.kts.
val unknownSdkVersion = "0.0.0-unknown"
gradle.extra["unknownSdkVersion"] = unknownSdkVersion

@Suppress("UNCHECKED_CAST")
gradle.extra["sdkVersion"] =
    (cargoMetadata?.get("packages") as? List<Map<String, Any>>)
        ?.firstOrNull { it["name"] == sdkVersionCrate }
        ?.get("version") as? String
        ?: unknownSdkVersion.also {
            logger.info("could not read the $sdkVersionCrate version from cargo, using $it")
        }

// A Gradle root of its own, rather than one at the workspace root: `endhost/public` is already both
// a Cargo workspace root and a pnpm workspace root, and a third root marker there makes IDEs try to
// import the whole SDK as a Gradle project.
rootProject.name = "scion-sdk-android"

include(":scion-http3-android")

// The hello-scion sample app.
include(":hello-scion")

// A plain JVM module, not an Android one: the FFI layer touches no Android API, so its tests run on
// a desktop JVM against a host-compiled library, with no emulator in the loop. It compiles the
// generated bindings as its own sources, which is what lets its tests see their `internal`
// declarations. Never published; see its build file.
include(":scion-http3-jvm-test")
