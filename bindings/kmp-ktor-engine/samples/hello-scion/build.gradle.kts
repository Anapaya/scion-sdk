// Copyright 2026 Anapaya Systems

import com.android.build.api.variant.HasHostTestsBuilder
import com.android.build.api.variant.HostTestBuilder
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.NativeBuildType
import org.jetbrains.kotlin.konan.target.Family

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

    // The iOS app. Its entry point starts UIKit, not the command line.
    if (hostOs.contains("mac")) {
        listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
            target.binaries {
                executable {
                    entryPoint = "net.anapaya.ktor.scion.sample.startIosApp"
                }
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

        // Only a Mac declares the iOS targets, so only a Mac has iosMain.
        if (hostOs.contains("mac")) {
            iosMain.dependencies {
                // The test network for a run without an API key.
                implementation(project(":ktor-client-scion-testing"))
            }
        }
    }
}

// Packs each iOS executable with Info.plist into HelloScion.app.
kotlin.targets.withType<KotlinNativeTarget>()
    .matching { it.konanTarget.family == Family.IOS }
    .configureEach {
        val executable = binaries.getExecutable(NativeBuildType.RELEASE)
        val name = targetName.replaceFirstChar { it.uppercase() }
        val app = layout.buildDirectory.dir("ios/$targetName/HelloScion.app")

        // Pack the executable and Info.plist. map, not flatMap, keeps the
        // dependency on the link task.
        val bundle = tasks.register<Sync>("bundleIosApp$name") {
            from(executable.linkTaskProvider.map { it.outputFile.get() }) {
                rename { "HelloScion" }
            }
            from("src/iosMain/Info.plist")
            into(app)
        }

        // The simulator refuses to launch a bundle without a signature, so
        // sign it ad hoc. For a device, codesign replaces the signature.
        tasks.register<Exec>("assembleIosApp$name") {
            dependsOn(bundle)
            commandLine("codesign", "--force", "--sign", "-", app.get().asFile.path)
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
