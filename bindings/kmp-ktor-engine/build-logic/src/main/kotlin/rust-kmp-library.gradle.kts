// Copyright 2026 Anapaya Systems

/*
 * Sets up a Kotlin Multiplatform library around the Rust crate in `rust/`,
 * with Gobley for the Rust build and the UniFFI bindings. The module adds its
 * Android namespace and its dependencies.
 *
 * The root project loads every plugin that this applies, so that all of them
 * share one classloader. build-logic only compiles against them.
 */

import com.android.build.api.dsl.LibraryExtension
import com.android.build.api.variant.HasHostTestsBuilder
import com.android.build.api.variant.HostTestBuilder
import com.android.build.api.variant.LibraryAndroidComponentsExtension
import gobley.gradle.Variant
import gobley.gradle.cargo.dsl.CargoExtension
import gobley.gradle.cargo.dsl.jvm
import gobley.gradle.rust.targets.RustTarget
import gobley.gradle.uniffi.dsl.UniFfiExtension
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree

// AGP goes first. The Kotlin plugin reads its version while it applies.
pluginManager.apply("com.android.library")
pluginManager.apply("org.jetbrains.kotlin.multiplatform")
pluginManager.apply("dev.gobley.cargo")
pluginManager.apply("dev.gobley.uniffi")
pluginManager.apply("org.jetbrains.kotlin.plugin.atomicfu")
pluginManager.apply("maven-publish")
pluginManager.apply("native-jar-combiner")
pluginManager.apply("rust-staticlib-isolation")

val versions = the<VersionCatalogsExtension>().named("libs")
fun version(name: String): String = versions.findVersion(name).get().requiredVersion

configure<KotlinMultiplatformExtension> {
    explicitApi()

    jvm {
        compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
    }

    androidTarget {
        publishLibraryVariants("release")
        compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
        // commonTest runs on a device or an emulator.
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        instrumentedTestVariant.sourceSetTree.set(KotlinSourceSetTree.test)
    }

    // A Linux host builds the Linux and the Windows targets, a Windows host
    // the Windows target. Only a Mac builds the Apple targets, because they
    // need Xcode. A Mac also cross compiles the Linux and the Windows targets,
    // so that it builds every artifact.
    when (NativeTarget.hostOs) {
        NativeTarget.Os.Linux -> {
            linuxX64()
            mingwX64()
        }
        NativeTarget.Os.Windows -> mingwX64()
        NativeTarget.Os.MacOs -> {
            iosArm64()
            iosSimulatorArm64()
            iosX64()
            macosArm64()
            linuxX64()
            mingwX64()
        }
    }
}

configure<CargoExtension> {
    packageDirectory = layout.projectDirectory.dir("rust")

    // Only the release profile. A debug build of the Rust library doubles the
    // size of the cargo target directory. Nobody debugs the Rust side through
    // this module, only the Kotlin side.
    jvmVariant = Variant.Release
    nativeVariant = Variant.Release
    builds.jvm {
        // native-jar-combiner puts every JVM library into the main jar.
        embedRustLibrary = false
    }
}

configure<UniFfiExtension> {
    generateFromLibrary {
        // The default is an Android debug build. It cross-compiles the full
        // SCION stack, also for the JVM tests. The host release build exists
        // in any case, and the metadata does not depend on the target.
        // NativeTarget.host is GNU on Windows, so no build needs MSVC.
        build = RustTarget(NativeTarget.host.rustTriple)
        variant = Variant.Release
    }
}

configure<LibraryExtension> {
    compileSdk = version("androidCompileSdk").toInt()
    // Gobley reads this to find <sdk>/ndk/<version> for the Rust cross build.
    ndkVersion = version("androidNdk")

    defaultConfig {
        minSdk = version("androidMinSdk").toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Gobley builds the Rust library only for these ABIs. An emulator run
        // needs one, for example -Pscion.androidAbis=x86_64.
        providers.gradleProperty("scion.androidAbis").orNull?.let { ndk.abiFilters += it.split(",") }
    }

    // We do not build a debug variant.
    testBuildType = "release"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

configure<LibraryAndroidComponentsExtension> {
    // An Android unit test runs on the desktop JVM, which cannot load an
    // Android .so. Only a test on a device tests that binding.
    beforeVariants { variant ->
        (variant as HasHostTestsBuilder).hostTests.getValue(HostTestBuilder.UNIT_TEST_TYPE).enable = false
    }

    // We only build the release variant. Debug is not really useful to us.
    beforeVariants(selector().withBuildType("debug")) { it.enable = false }
}

// Android Lint has its own, older Kotlin compiler. It cannot read the
// metadata of this module, so its reports are wrong.
tasks.matching { it.name.startsWith("lint") }.configureEach { enabled = false }

// Gobley hooks a cargo check per target into check, duplicating work of the build.
tasks.matching { it.name.startsWith("cargoCheck") }.configureEach { enabled = false }

configure<PublishingExtension> {
    repositories {
        maven {
            name = "localBuild"
            url = uri(rootProject.layout.buildDirectory.dir("repository"))
        }
    }
}
