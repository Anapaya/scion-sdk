// Copyright 2026 Anapaya Systems

import com.android.build.api.variant.HasHostTestsBuilder
import com.android.build.api.variant.HostTestBuilder
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree

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

// commonTest also runs as an Android host test: the Android classes on a
// desktop JVM, as in the host test of an app. rust-kmp-library disables host
// tests, so this module turns them on again.
kotlin {
    androidTarget {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        unitTestVariant.sourceSetTree.set(KotlinSourceSetTree.test)
    }
}

androidComponents {
    beforeVariants { variant ->
        (variant as HasHostTestsBuilder).hostTests.getValue(HostTestBuilder.UNIT_TEST_TYPE).enable = true
    }
}

dependencies {
    // The host library of the test network. Gobley adds the host libraries
    // of commonMain dependencies only.
    "rustRuntimeOnly"(project(":ktor-client-scion-testing"))
}

// The Android platform verifier.

val coreDirectory: File = layout.projectDirectory.dir("rust").asFile

/**
 * The version of the Kotlin side of rustls-platform-verifier. It must be the
 * version of the rustls-platform-verifier-android crate that cargo resolves
 * for the Rust library.
 */
fun rustlsPlatformVerifierVersion(): String {
    val packages = Cargo.metadata(coreDirectory, "--filter-platform", "aarch64-linux-android")["packages"] as List<*>
    val crate = packages.map { it as Map<*, *> }.single { it["name"] == "rustls-platform-verifier-android" }
    return crate["version"] as String
}

/** The AAR with the Kotlin side of rustls-platform-verifier, from its Maven repository. */
val rustlsPlatformVerifierAar: Configuration = configurations.create("rustlsPlatformVerifierAar") {
    isCanBeConsumed = false
    isTransitive = false
}

dependencies {
    addProvider(
        rustlsPlatformVerifierAar.name,
        provider { "org.rustls:rustls-platform-verifier:${rustlsPlatformVerifierVersion()}@aar" },
    )
}

/**
 * Bundles only classes.jar of the AAR. A library module cannot depend on a
 * local AAR, but it bundles a local jar, so apps need no extra repository.
 *
 * The AAR also sets a network security config that allows plain HTTP to the
 * CRL hosts. The engine does not take it: in an app with its own config, the
 * manifest merge fails. See the README for the effect on origin certificates.
 */
val extractRustlsPlatformVerifier = tasks.register<Copy>("extractRustlsPlatformVerifier") {
    group = "build"
    from({ zipTree(rustlsPlatformVerifierAar.singleFile) }) { include("classes.jar") }
    rename { "rustls-platform-verifier.jar" }
    into(layout.buildDirectory.dir("rustls-platform-verifier"))
}

dependencies {
    "androidMainImplementation"(
        files(layout.buildDirectory.file("rustls-platform-verifier/rustls-platform-verifier.jar"))
            .builtBy(extractRustlsPlatformVerifier),
    )
}
