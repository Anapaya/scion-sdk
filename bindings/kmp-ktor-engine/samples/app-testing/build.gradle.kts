// Copyright 2026 Anapaya Systems

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

/**
 * An app that talks to its API through a WebGateway, and a test that runs it
 * over SCION with ktor-client-scion-testing, on the JVM and on the native
 * targets of the host.
 *
 * An app outside this build uses the Maven coordinates instead of the project
 * paths: `net.anapaya.ktor:ktor-client-scion` and, for the tests,
 * `net.anapaya.ktor:ktor-client-scion-testing`.
 */
kotlin {
    jvm {
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
    }
}
