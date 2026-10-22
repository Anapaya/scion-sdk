// Copyright 2026 Anapaya Systems

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    // AGP goes first. The Kotlin plugin reads its version while it applies.
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.kotlinMultiplatform)
}

/**
 * An app that talks to its API through a WebGateway, and a test that runs it
 * over SCION with ktor-client-scion-testing, on the JVM, as an Android host
 * test, and on the native targets of the host.
 *
 * An app outside this build uses the Maven coordinates instead of the project
 * paths: `net.anapaya.ktor:ktor-client-scion` and, for the tests,
 * `net.anapaya.ktor:ktor-client-scion-testing`. For the Android host test, it
 * adds the `-jvm` artifacts of both.
 */
kotlin {
    jvm {
        compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
    }

    // Only for the Android host test: it runs commonTest with the setup from
    // "Android host tests" in the README. The android block below and the lint
    // switch only configure this target.
    androidTarget {
        compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
    }

    // The engine declares its native targets per host, so the sample follows.
    val hostOs = System.getProperty("os.name").lowercase()
    when {
        hostOs.contains("mac") -> {
            macosArm64()
            iosSimulatorArm64()
        }
        hostOs.contains("windows") -> mingwX64()
        else -> {
            linuxX64()
            mingwX64()
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(project(":ktor-client-scion"))
        }

        commonTest.dependencies {
            implementation(project(":ktor-client-scion-testing"))
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.core)
            // The API of the app, as the test runs it.
            implementation(libs.ktor.server.cio)
        }

        // See "Android host tests" in the README.
        androidUnitTest.dependencies {
            runtimeOnly(project(":ktor-client-scion", "jvmRuntimeElements"))
            runtimeOnly(project(":ktor-client-scion-testing", "jvmRuntimeElements"))
        }
    }
}

android {
    namespace = "net.anapaya.ktor.scion.sample.testing"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()
    defaultConfig { minSdk = libs.versions.androidMinSdk.get().toInt() }

    // The engine has only a release variant.
    testBuildType = "release"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

androidComponents {
    beforeVariants(selector().withBuildType("debug")) { it.enable = false }
}

// See rust-kmp-library in build-logic: Android Lint cannot read this module.
tasks.matching { it.name.startsWith("lint") }.configureEach { enabled = false }
