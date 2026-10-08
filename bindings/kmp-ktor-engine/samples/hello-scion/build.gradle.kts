// Copyright 2026 Anapaya Systems

import com.android.build.api.variant.HasHostTestsBuilder
import com.android.build.api.variant.HostTestBuilder
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree

plugins {
    // AGP goes first. The Kotlin plugin reads its version while it applies.
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.kotlinMultiplatform)
}

kotlin {
    jvm {
        // The executable adds the task runJvm.
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        binaries {
            executable { mainClass.set("net.anapaya.ktor.scion.sample.MainKt") }
        }
    }

    androidTarget {
        compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
        // commonTest runs on a device or an emulator.
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        instrumentedTestVariant.sourceSetTree.set(KotlinSourceSetTree.test)
    }

    // The engine declares its native targets per host, so the sample follows.
    val hostOs = System.getProperty("os.name").lowercase()
    val nativeTargets = when {
        hostOs.contains("mac") -> listOf(macosArm64())
        hostOs.contains("windows") -> listOf(mingwX64())
        else -> listOf(linuxX64(), mingwX64())
    }

    nativeTargets.forEach { target ->
        target.binaries {
            executable {
                entryPoint = "net.anapaya.ktor.scion.sample.main"
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(project(":ktor-client-scion"))
            implementation(libs.kotlinx.coroutines.core)
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(project(":ktor-client-scion-testing"))
        }

        androidMain.dependencies {
            // The test network for a run without an API key.
            implementation(project(":ktor-client-scion-testing"))
        }

        androidInstrumentedTest.dependencies {
            implementation(libs.androidx.test.runner)
            implementation(libs.androidx.test.core)
        }
    }
}

android {
    namespace = "net.anapaya.ktor.scion.sample"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()

    defaultConfig {
        applicationId = "net.anapaya.ktor.scion.sample"
        minSdk = libs.versions.androidMinSdk.get().toInt()
        targetSdk = libs.versions.androidCompileSdk.get().toInt()
        versionCode = 1
        versionName = version.toString()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        // A release build signed with the debug key installs without setup.
        release { signingConfig = signingConfigs.getByName("debug") }
        // The engine has only a release variant.
        debug { matchingFallbacks += "release" }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

androidComponents {
    // See rust-kmp-library in build-logic: an Android unit test cannot load
    // the Android library of the engine.
    beforeVariants { variant ->
        (variant as HasHostTestsBuilder).hostTests.getValue(HostTestBuilder.UNIT_TEST_TYPE).enable = false
    }
}

// See rust-kmp-library in build-logic: Android Lint cannot read this module.
tasks.matching { it.name.startsWith("lint") }.configureEach { enabled = false }
