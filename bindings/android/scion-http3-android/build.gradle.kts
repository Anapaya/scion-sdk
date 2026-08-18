// Copyright 2026 Anapaya Systems

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jlleitschuh.gradle.ktlint")
}

// ABIs the AAR ships, mirroring the Rust targets built by ../tools/android.py:
// arm64-v8a <- aarch64-linux-android, x86_64 <- x86_64-linux-android. armeabi-v7a is deliberately
// out of scope; adding it means one entry here and one in android.py.
val shippedAbis = listOf("arm64-v8a", "x86_64")
val nativeLibraryFileName = "libscion_http3_ffi.so"

android {
    namespace = "com.anapaya.scion.http3"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        // No targetSdk: a library inherits the consuming application's.
        consumerProguardFiles("consumer-rules.pro")
    }

    // No ndkVersion on purpose. The .so files are produced by cargo, outside Gradle, so there is no
    // externalNativeBuild for AGP to run. Declaring an NDK version would make an NDK a hard
    // requirement for `assembleRelease`, when it is a Rust-build-time dependency only.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            // generated/ is gitignored and written by non-Gradle steps: jniLibs by
            // ../tools/android.py, and kotlin/ by the bindings generator. It sits outside
            // build/ so that `gradle clean` cannot delete artifacts Gradle did not produce.
            jniLibs.srcDirs("src/main/jniLibs", "generated/jniLibs")
            kotlin.srcDirs("src/main/kotlin", "generated/kotlin")
        }
    }

    packaging {
        jniLibs {
            // Keep AGP away from the libraries. Its stripReleaseDebugSymbols task needs an NDK (see
            // above) and rewrites the binary, which would invalidate the 16 KB segment alignment
            // ../tools/android.py checks. With this, the bytes in the AAR are the bytes cargo
            // produced, and the same file can be checked before and after packaging.
            keepDebugSymbols += "**/*.so"

            // useLegacyPackaging is deliberately not set: AGP ignores it for library modules,
            // because whether native libraries are extracted or mapped out of the APK is the
            // consuming application's decision. 16 KB page-size compatibility needs
            // useLegacyPackaging = false, which is already the default for minSdk >= 23. For the
            // same reason src/main/AndroidManifest.xml must not declare android:extractNativeLibs,
            // which the manifest merger would otherwise impose on every consumer.
        }
    }

    // No abiFilters either: the AAR ships exactly the ABI directories that are present, so a
    // missing library fails the checkNativeLibraries task below instead of silently disappearing
    // from the artifact.

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    // Every declaration has to state its visibility, so the published API surface stays deliberate.
    explicitApi()
}

ktlint {
    version.set("1.3.1")
    android.set(true)
    ignoreFailures.set(false)
    filter {
        // Everything under generated/ is machine-generated.
        exclude { it.file.path.contains("/generated/") }
    }
}

// Without this, `assembleRelease` succeeds and produces an AAR with no jni/ directory at all, which
// is the most likely way this pipeline ships nothing while looking healthy.
val checkNativeLibraries by tasks.registering {
    group = "verification"
    description = "Asserts that tools/android.py has produced a library for every shipped ABI."

    // Deliberately declares no inputs or outputs: this is a cheap assertion that has to run every
    // time, and a task with inputs but no outputs is never up to date anyway.
    val jniLibsDir = layout.projectDirectory.dir("generated/jniLibs")
    val abis = shippedAbis
    val libraryName = nativeLibraryFileName

    doLast {
        val missing =
            abis
                .map { abi -> jniLibsDir.file("$abi/$libraryName").asFile }
                .filterNot { it.isFile }
        if (missing.isNotEmpty()) {
            throw GradleException(
                buildString {
                    appendLine("Missing prebuilt native libraries:")
                    missing.forEach { appendLine("  $it") }
                    appendLine()
                    appendLine("Run ../tools/android.py build first (see ../README.md), or pass")
                    appendLine("-PskipNativeCheck to assemble without them, to run ktlint say.")
                },
            )
        }
    }
}

if (!project.hasProperty("skipNativeCheck")) {
    tasks.named("preBuild") { dependsOn(checkNativeLibraries) }
}
