// Copyright 2026 Anapaya Systems

plugins {
    id("rust-kmp-library")
}

/**
 * The test network runs in the test process: through the cdylib on the JVM
 * and on Android, and through the static library on Kotlin/Native.
 */
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":ktor-client-scion"))
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.core)
        }

        androidInstrumentedTest.dependencies {
            implementation(libs.androidx.test.runner)
        }
    }
}

android {
    namespace = "net.anapaya.ktor.scion.testing"
}
