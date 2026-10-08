// Copyright 2026 Anapaya Systems

plugins {
    id("rust-kmp-library")
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(libs.ktor.client.core)
            implementation(libs.kotlinx.coroutines.core)
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            // The test network, in the test process.
            implementation(project(":ktor-client-scion-testing"))
        }

        androidInstrumentedTest.dependencies {
            implementation(libs.androidx.test.runner)
        }
    }
}

android {
    namespace = "net.anapaya.ktor.scion"
    defaultConfig { consumerProguardFiles("consumer-rules.pro") }
}

// The Android platform verifier.

val coreDirectory: File = layout.projectDirectory.dir("rust").asFile

/**
 * The AAR with the Kotlin side of rustls-platform-verifier. It ships in the
 * source of the rustls-platform-verifier-android crate, not on Maven, so the
 * crate that cargo resolves for the Rust library decides the version.
 */
fun rustlsPlatformVerifierAar(): File {
    // Find the crate that cargo resolves for Android.
    val packages = Cargo.metadata(coreDirectory, "--filter-platform", "aarch64-linux-android")["packages"] as List<*>
    val crate = packages.map { it as Map<*, *> }.single { it["name"] == "rustls-platform-verifier-android" }

    // Find the AAR in its source.
    val maven = File(crate["manifest_path"] as String).resolveSibling("maven")
    return maven.walkTopDown().single { it.extension == "aar" }
}

/**
 * The AAR holds only classes.jar. A library module cannot depend on a local
 * AAR, but it bundles a local jar, so apps need no extra repository.
 */
val extractRustlsPlatformVerifier = tasks.register<Copy>("extractRustlsPlatformVerifier") {
    group = "build"
    from({ zipTree(rustlsPlatformVerifierAar()) }) { include("classes.jar") }
    rename { "rustls-platform-verifier.jar" }
    into(layout.buildDirectory.dir("rustls-platform-verifier"))
}

dependencies {
    "androidMainImplementation"(
        files(layout.buildDirectory.file("rustls-platform-verifier/rustls-platform-verifier.jar"))
            .builtBy(extractRustlsPlatformVerifier),
    )
}
