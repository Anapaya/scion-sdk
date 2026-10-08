// Copyright 2026 Anapaya Systems

plugins {
    `kotlin-dsl`
}

dependencies {
    // Only for compilation. The root project loads the plugins themselves.
    compileOnly(libs.android.gradlePlugin)
    compileOnly(libs.kotlin.gradlePlugin)
    compileOnly(libs.gobley.gradleCargo)
    compileOnly(libs.gobley.gradleUniffi)
}
