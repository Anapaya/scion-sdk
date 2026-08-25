// Copyright 2026 Anapaya Systems

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jlleitschuh.gradle.ktlint")
}

android {
    namespace = "com.anapaya.scion.http3.hello"
    compileSdk = 35

    // Pinned for the same reason as in scion-http3-android: AGP's default for this version is
    // 34.0.0, and letting it choose downloads a second copy of the build tools.
    buildToolsVersion = "35.0.0"

    defaultConfig {
        applicationId = "com.anapaya.scion.http3.hello"
        // The library's floor, so the sample cannot use anything a consumer on 24 could not.
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Never published and never signed for release: assembleDebug is what CI builds and what a
    // reader installs.
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

// A consumer adds the released AAR, so the sample can be built that way too:
// `-PscionSdkVersion=<version>` after `publishToMavenLocal`, or against an unpacked release. Without
// the property it builds against the module in this repository, so CI builds what it ships.
val releasedSdkVersion: String? = providers.gradleProperty("scionSdkVersion").orNull

dependencies {
    if (releasedSdkVersion != null) {
        implementation("com.anapaya.scion:scion-http3-android:$releasedSdkVersion")
    } else {
        implementation(project(":scion-http3-android"))
    }
    implementation(libs.kotlinx.coroutines.android)
}

ktlint {
    version.set("1.3.1")
    android.set(true)
    ignoreFailures.set(false)
}
