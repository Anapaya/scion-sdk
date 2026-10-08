// Copyright 2026 Anapaya Systems

pluginManagement {
    includeBuild("build-logic")
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "ktor-scion"

include(":ktor-client-scion")
include(":ktor-client-scion-testing")

include(":hello-scion")
project(":hello-scion").projectDir = file("samples/hello-scion")
include(":app-testing")
project(":app-testing").projectDir = file("samples/app-testing")
