// Copyright 2026 Anapaya Systems

plugins {
    // AGP goes first. The Kotlin plugin reads its version while it applies.
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.kotlinMultiplatform)
}

val scionVersion = providers.gradleProperty("scionVersion").getOrElse("+")

kotlin {
    jvm()

    androidLibrary {
        namespace = "net.anapaya.ktor.scion.consumer"
        compileSdk = libs.versions.androidCompileSdk.get().toInt()
        minSdk = libs.versions.androidMinSdk.get().toInt()
        withHostTestBuilder {}
    }

    // The release has the iOS targets only.
    if (System.getProperty("os.name").lowercase().contains("mac")) {
        iosSimulatorArm64()
    }

    sourceSets {
        commonMain.dependencies {
            implementation("net.anapaya.scion:ktor-client-scion:$scionVersion")
        }

        commonTest.dependencies {
            implementation("net.anapaya.scion:ktor-client-scion-testing:$scionVersion")
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.core)
        }

        // The recipe of "Android host tests" in the README.
        getByName("androidHostTest").dependencies {
            runtimeOnly("net.anapaya.scion:ktor-client-scion-jvm:$scionVersion")
            runtimeOnly("net.anapaya.scion:ktor-client-scion-testing-jvm:$scionVersion")
        }
    }
}
