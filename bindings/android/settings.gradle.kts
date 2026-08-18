// Copyright 2026 Anapaya Systems

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

// A Gradle root of its own, rather than one at the workspace root: `endhost/public` is already both
// a Cargo workspace root and a pnpm workspace root, and a third root marker there makes IDEs try to
// import the whole SDK as a Gradle project.
rootProject.name = "scion-sdk-android"

include(":scion-http3-android")
