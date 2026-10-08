// Copyright 2026 Anapaya Systems

plugins {
    // Every plugin loads here, so that all of them share one classloader. The
    // Kotlin plugin reads the version of the Android plugin, and that fails
    // across classloaders.
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.androidApplication) apply false
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.gobleyCargo) apply false
    alias(libs.plugins.gobleyUniffi) apply false
    alias(libs.plugins.kotlinAtomicfu) apply false
}

allprojects {
    group = "net.anapaya.ktor"
    version = "0.1.0"
}
