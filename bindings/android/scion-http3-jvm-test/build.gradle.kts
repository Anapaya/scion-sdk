// Copyright 2026 Anapaya Systems

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jlleitschuh.gradle.ktlint")
}

// The Cargo workspace root.
val cargoWorkspace = layout.projectDirectory.dir("../../..")

// Where cargo puts what it builds, resolved by asking cargo in settings.gradle.kts.
val cargoTargetDir: File by lazy { gradle.extra["cargoTargetDir"] as File }

// Refusing the platforms this has never run on beats letting the failure surface as a missing file.
val hostOs: String = System.getProperty("os.name").lowercase()
val hostLibraryFileName: String =
    when {
        "linux" in hostOs -> "libscion_http3_ffi.so"
        "mac" in hostOs -> "libscion_http3_ffi.dylib"
        else -> throw GradleException(
            "the JVM-host tests support Linux and macOS only, not $hostOs",
        )
    }

// The two artefacts the tests load, taken from cargo's output directly rather than staged into this
// module. The library is the one the bindings were generated from, so the two cannot be from
// different builds.
val nativeLibrary = File(cargoTargetDir, "release/$hostLibraryFileName")
val testServer = File(cargoTargetDir, "release/scion-h3-test-server")

// The generated bindings, resolved as an artifact the Android module offers rather than as a path in
// it. An artifact registered from a task carries the task and its declared outputs, so the
// compilation waits for the bindings and reads the files the task says it wrote; a plain path
// carries neither, and a compilation that reads it too early sees an empty tree.
// Two configurations, as the current Gradle API requires: one to declare the dependency in, one to
// resolve it through.
val bindingsSource by configurations.dependencyScope("bindingsSource")

val bindings by
    configurations.resolvable("bindings") {
        extendsFrom(bindingsSource)
        attributes {
            attribute(
                Category.CATEGORY_ATTRIBUTE,
                objects.named(Category::class.java, "uniffi-bindings"),
            )
        }
    }

kotlin {
    jvmToolchain(17)

    sourceSets.named("main") {
        // The generated bindings are this module's production code. That is the whole reason the
        // module exists in this shape: Kotlin compiles a test source set as a friend of its main
        // one, so the tests can see `internal` declarations, and UniFFI's record of in-flight
        // futures (uniffiContinuationHandleMap) is `internal`. Without it the cancellation test
        // could assert that a request stopped, but not that nothing was left behind.
        //
        // Compiling them here rather than depending on the Android module's artifact is what makes
        // them this module's own main source set, which is what the friend relationship needs.
        kotlin.setSrcDirs(listOf(bindings))
    }
}

dependencies {
    bindingsSource(project(":scion-http3-android"))

    // The plain jar rather than the @aar the Android module uses: this runs on a desktop JVM,
    // which has JNA's native library on its own classpath.
    implementation(libs.jna)
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.gson)
    testRuntimeOnly(libs.junit.platform.launcher)
}

ktlint {
    version.set("1.3.1")
    ignoreFailures.set(false)
    filter {
        exclude { it.file.path.contains("/generated/") }
    }
}

val buildTestServer by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the PocketSCION test server the tests run their requests against."
    workingDir = cargoWorkspace.asFile
    commandLine("cargo", "build", "--locked", "--release", "-p", "scion-h3-test-server")

    // Declared, but never up to date: cargo decides what to rebuild, and Gradle only invalidates its
    // view of a file when a task says it produces it.
    outputs.file(testServer)
    outputs.upToDateWhen { false }
}

// A compilation that read an empty view of the generated directory would otherwise fail as a wall of
// unresolved references in the test sources, which says nothing about the cause. This says it once.
val checkBindingsCompiled by tasks.registering {
    group = "verification"
    description = "Asserts that the generated bindings were compiled into this module."

    dependsOn(tasks.named("compileKotlin"))
    val classesDir = layout.buildDirectory.dir("classes/kotlin/main")
    val sources = bindings

    doLast {
        // The package comes from the generated sources rather than being written down again here.
        // The class name does not: it is the exported object, and a rename should be noticed.
        val declared =
            sources.asFileTree
                .first { it.extension == "kt" }
                .useLines { lines -> lines.first { it.startsWith("package ") } }
                .removePrefix("package ")
                .trim()
        val expected = "${declared.replace('.', '/')}/ScionHttp3Client.class"
        val compiled = classesDir.get().file(expected).asFile
        if (!compiled.isFile) {
            throw GradleException(
                "The generated bindings were not compiled into this module: $compiled is " +
                    "missing. The Kotlin compilation read an empty view of the generated " +
                    "bindings, which means the dependency on the task that produced them was lost.",
            )
        }
    }
}

tasks.named("compileTestKotlin") { dependsOn(checkBindingsCompiled) }

tasks.named<Test>("test") {
    dependsOn(buildTestServer)
    useJUnitPlatform()

    // The server binary, declared as an input rather than only passed as a system property below.
    // Without this the tests are up to date whenever their own sources and classpath are unchanged,
    // however much the server they run against has moved: a property is a string, and this one's
    // value is a path that never changes. A change to the Rust fixture would then report the last
    // run's result, which is the most convincing way for this tier to be wrong.
    inputs.file(testServer)

    // One fork, which is also Gradle's default. Each would start a topology of its own, since the
    // shared test server is a per-JVM lazy, and one boot is enough.
    maxParallelForks = 1

    // How the generated bindings find the library. Simpler and more reliable than assembling a
    // jna.library.path directory, and it names the exact file the build just produced.
    systemProperty("uniffi.component.scion_http3_ffi.libraryOverride", nativeLibrary.absolutePath)
    // A JNA installed system-wide must not win over the one resolved above: the generated bindings
    // are compiled against the structure layouts of exactly that version.
    systemProperty("jna.nosys", "true")
    systemProperty("scion.test.server", testServer.absolutePath)

    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}
