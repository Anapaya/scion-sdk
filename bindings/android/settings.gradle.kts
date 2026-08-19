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
    }
}

// Where cargo puts what it builds, resolved once here and read by both modules through
// `gradle.extra`. Asked of cargo rather than reconstructed from CARGO_TARGET_DIR: the directory can
// equally come from `build.target-dir` in any of the `.cargo/config.toml` files cargo merges, or from
// the default, and CI moves it out of the workspace to share one cache between jobs. Reconstructing
// it silently points at the wrong place, and every path derived from it then goes missing.
//
// Falls back to the default when cargo cannot be run, so that tasks needing none of its output, a
// lint-only invocation say, still work without a Rust toolchain.
val cargoWorkspaceDir = settingsDir.resolve("../..").canonicalFile
gradle.extra["cargoTargetDir"] =
    runCatching {
        val process =
            ProcessBuilder("cargo", "metadata", "--format-version", "1", "--no-deps")
                .directory(cargoWorkspaceDir)
                .redirectErrorStream(false)
                .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "cargo metadata failed" }
        @Suppress("UNCHECKED_CAST")
        val metadata = groovy.json.JsonSlurper().parseText(output) as Map<String, Any>
        File(metadata["target_directory"] as String)
    }.getOrElse {
        logger.info("could not ask cargo for its target directory, assuming the default: $it")
        cargoWorkspaceDir.resolve("target")
    }

// A Gradle root of its own, rather than one at the workspace root: `endhost/public` is already both
// a Cargo workspace root and a pnpm workspace root, and a third root marker there makes IDEs try to
// import the whole SDK as a Gradle project.
rootProject.name = "scion-sdk-android"

include(":scion-http3-android")

// A plain JVM module, not an Android one: the FFI layer touches no Android API, so its tests run on
// a desktop JVM against a host-compiled library, with no emulator in the loop. It compiles the
// generated bindings as its own sources, which is what lets its tests see their `internal`
// declarations. Never published; see its build file.
include(":scion-http3-jvm-test")
