// Copyright 2026 Anapaya Systems

plugins {
    // AGP goes first. The Kotlin plugin reads its version while it applies.
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.kotlinMultiplatform)
}

val sdkVersion = providers.gradleProperty("sdkVersion").getOrElse("+")

kotlin {
    jvm()

    // ANCHOR: android-library
    androidLibrary {
        namespace = "net.anapaya.ktor.scion.consumer"
        compileSdk = libs.versions.androidCompileSdk.get().toInt()
        minSdk = libs.versions.androidMinSdk.get().toInt()
        withHostTestBuilder {}
        // Runs commonTest on a device too, not only the tests in androidDeviceTest.
        withDeviceTestBuilder { sourceSetTreeName = "test" }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }
    // ANCHOR_END: android-library

    // The release has the iOS targets only.
    if (System.getProperty("os.name").lowercase().contains("mac")) {
        iosSimulatorArm64()
    }

    // ANCHOR: dependencies
    sourceSets {
        commonMain.dependencies {
            implementation("net.anapaya.scion:ktor-client-scion:$sdkVersion")
        }

        commonTest.dependencies {
            implementation("net.anapaya.scion:ktor-client-scion-testing:$sdkVersion")
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.core)
        }

        // ANCHOR: android-host-test
        // The desktop libraries for the Android host test, which runs on the JVM.
        getByName("androidHostTest").dependencies {
            runtimeOnly("net.anapaya.scion:ktor-client-scion-jvm:$sdkVersion")
            runtimeOnly("net.anapaya.scion:ktor-client-scion-testing-jvm:$sdkVersion")
        }
        // ANCHOR_END: android-host-test

        // ANCHOR: android-device-test
        getByName("androidDeviceTest").dependencies {
            implementation(libs.androidx.test.runner)
        }
        // ANCHOR_END: android-device-test
    }
    // ANCHOR_END: dependencies
}
