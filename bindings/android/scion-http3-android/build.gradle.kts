// Copyright 2026 Anapaya Systems

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jlleitschuh.gradle.ktlint")
}

// ABIs the AAR ships, mirroring the Rust targets built by ../tools/android.py:
// arm64-v8a <- aarch64-linux-android, x86_64 <- x86_64-linux-android.
val shippedAbis = listOf("arm64-v8a", "x86_64")

// Android always names it .so, whatever the machine doing the build.
val nativeLibraryFileName = "libscion_http3_ffi.so"

// The host build, which the bindings are generated from, names it per platform. Refusing the
// platforms this has never run on beats letting the failure surface as a missing file.
val hostOs: String = System.getProperty("os.name").lowercase()
val hostLibraryFileName: String =
    when {
        "linux" in hostOs -> "libscion_http3_ffi.so"
        "mac" in hostOs -> "libscion_http3_ffi.dylib"
        else -> throw GradleException("host builds support Linux and macOS only, not $hostOs")
    }

// endhost/public, i.e. the Cargo workspace root.
val cargoWorkspace = layout.projectDirectory.dir("../../..")

// Where cargo puts what it builds, resolved by asking cargo in settings.gradle.kts.
val cargoTargetDir: File by lazy { gradle.extra["cargoTargetDir"] as File }

// The Kotlin bindings, generated from a host build of scion-http3-ffi rather than from either
// cross-compiled library. UniFFI reads its metadata out of the built library and that metadata says
// nothing about the target, so one host compile produces the Kotlin that ships in this AAR and the
// Kotlin the JVM-host tests run against.
//
// Note that this does call cargo, which the native libraries above deliberately do not: those are
// cross-compiled by ../tools/android.py, outside Gradle, so that AGP needs no NDK. A host build
// needs none of that machinery.
val bindingsOutputDir = layout.projectDirectory.dir("generated/kotlin")

// The attribute a consuming project matches on to resolve the generated bindings.
val bindingsCategory = "uniffi-bindings"

// Compilation of any variant, ktlint's scan of the same tree, and the sources jar the release
// variant publishes.
fun consumesGeneratedSources(taskName: String): Boolean =
    (taskName.startsWith("compile") && taskName.endsWith("Kotlin")) ||
        taskName.startsWith("runKtlint") ||
        taskName.endsWith("SourcesJar")

val hostLibrary = File(cargoTargetDir, "release/$hostLibraryFileName")

val buildHostLibrary by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the host shared library, which the bindings are generated from."
    workingDir = cargoWorkspace.asFile
    commandLine("cargo", "build", "--locked", "--release", "-p", "scion-http3-ffi")

    // The output is declared but the task never claims to be up to date. Both halves matter. Cargo
    // decides what to rebuild, far better than a declared input list over the crate graph could, so
    // this always runs. And Gradle only invalidates its view of a file when a task says it produces
    // it: an undeclared file written by an external process stays stale in the virtual file system,
    // and whoever reads it next may see what was there before.
    outputs.file(hostLibrary)
    outputs.upToDateWhen { false }
}

val generateBindings by tasks.registering(Exec::class) {
    group = "build"
    description = "Regenerates the UniFFI Kotlin bindings from the host library."
    dependsOn(buildHostLibrary)
    workingDir = cargoWorkspace.asFile

    // Removed rather than overwritten: a renamed or deleted namespace would otherwise leave behind a
    // file that still compiles and still calls symbols the library no longer exports.
    doFirst { delete(bindingsOutputDir) }

    // Declared for the same reason as the library above: the Kotlin compilations that read this
    // directory only see new files if Gradle knows a task produced them. Unlike the cargo tasks this
    // one does get an up-to-date check, because it has a reliable key. The bindings are a function of
    // the library alone, and cargo leaves the library untouched when nothing changed, so an unchanged
    // input means identical output and there is no reason to regenerate and recompile the tree.
    inputs.file(hostLibrary)
    outputs.dir(bindingsOutputDir)

    // Through the workspace's own bindgen rather than an installed one: the generator and the
    // library have to come from the same uniffi version, and a mismatch fails at load time with an
    // error that names neither of them. --no-format because ktlint formats this tree, and ktfmt is
    // not a prerequisite anyone here has.
    commandLine(
        "cargo",
        "run",
        "--locked",
        "--quiet",
        "--release",
        "-p",
        "uniffi-bindgen",
        "--",
        "generate",
        "--language",
        "kotlin",
        "--library",
        hostLibrary.absolutePath,
        "--out-dir",
        bindingsOutputDir.asFile.absolutePath,
        "--no-format",
    )

    doLast {
        // Without this the AAR still assembles, still carries the native libraries, and has nothing
        // to call them with.
        val generated = bindingsOutputDir.asFile.walkTopDown().filter { it.extension == "kt" }
        if (generated.none()) {
            throw GradleException(
                "No Kotlin was generated under ${bindingsOutputDir.asFile}. The library " +
                    "exports no UniFFI metadata, which usually means " +
                    "uniffi::setup_scaffolding! is missing or the package name in " +
                    "uniffi.toml changed.",
            )
        }
    }
}

android {
    namespace = "com.anapaya.scion.http3"
    compileSdk = 35

    // Pinned rather than left to AGP, whose default for this version is 34.0.0. Without it the
    // build quietly downloads a second copy of the build tools, which works only where the SDK
    // directory is writable and disagrees with the version CI installs.
    buildToolsVersion = "35.0.0"

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
            // generated/ is written by non-Gradle steps: jniLibs by ../tools/android.py, and
            // kotlin/ by the bindings generator.
            jniLibs.srcDirs("src/main/jniLibs", "generated/jniLibs")
            // The task, not the directory it writes. Naming the task is what ties a consumer to the
            // files the task declares it produced; naming the directory leaves the order to chance,
            // and a consumer that reads it too early sees an empty tree and compiles nothing.
            kotlin.srcDirs("src/main/kotlin", generateBindings)
        }
    }

    packaging {
        jniLibs {
            // Keep AGP away from the libraries. Its stripReleaseDebugSymbols task needs an NDK (see
            // above) and rewrites the binary, which would invalidate the 16 KB segment alignment
            // ../tools/android.py checks. With this, the bytes in the AAR are the bytes cargo
            // produced, and the same file can be checked before and after packaging.
            keepDebugSymbols += "**/*.so"
        }
    }

    // No abiFilters: the AAR ships exactly the ABI directories that are present, so a
    // missing library fails the checkNativeLibraries task below instead of silently disappearing
    // from the artifact.

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

// The generated bindings, offered to other projects as an artifact. Registering it from the task
// carries the task and its declared outputs, so a consumer resolving this gets both the dependency
// and the files, without naming a path in this project or reaching into its task container.
val bindingsElements by
    configurations.consumable("bindingsElements") {
        attributes {
            attribute(
                Category.CATEGORY_ATTRIBUTE,
                objects.named(Category::class.java, bindingsCategory),
            )
        }
    }

artifacts.add(bindingsElements.name, generateBindings)

dependencies {
    // Both are `api` rather than `implementation`, because both appear in what this module exposes.
    // The generated bindings declare `suspend` functions, whose callers need the coroutines types,
    // and a public `RustBuffer` that extends JNA's `Structure`. Gradle would let either sit on
    // `implementation`; a consumer would then fail to resolve a type this module handed it.
    api(libs.kotlinx.coroutines.core)
    // The @aar artifact, not the plain jar: it carries JNA's own native libraries for each Android
    // ABI, which is how the generated bindings reach ours.
    api("${libs.jna.android.get()}@aar")
}

// Every task that reads the main source set has to be told about generateBindings by hand. Adding
// the task to `kotlin.srcDirs` carries the dependency for a plain Kotlin source set, but neither
// AGP's source sets nor ktlint's file collections keep it: both reduce the entry to a path and lose
// what produced it. Gradle fails the build on the omission rather than leaving it to chance, so a
// consumer added later says so.
tasks
    .matching { consumesGeneratedSources(it.name) }
    .configureEach { dependsOn(generateBindings) }

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

// The generated package name appears in four places. Three of them fail loudly if it changes: the
// bindings themselves, the AAR check in CI, and the JVM tests' own check. The ProGuard rules are the
// exception, and they fail in the worst way, by letting R8 strip the bindings out of a consumer's
// release build. Read from the generated sources rather than uniffi.toml, so a change in what
// bindgen does with the configured name is caught too.
val checkConsumerRules by tasks.registering {
    group = "verification"
    description =
        "Asserts that consumer-rules.pro keeps the package the bindings are generated into."

    dependsOn(generateBindings)
    val rulesFile = layout.projectDirectory.file("consumer-rules.pro")
    val generatedDir = bindingsOutputDir

    doLast {
        val declared =
            generatedDir.asFile
                .walkTopDown()
                .first { it.extension == "kt" }
                .useLines { lines -> lines.first { it.startsWith("package ") } }
                .removePrefix("package ")
                .trim()
        if (!rulesFile.asFile.readText().contains(declared)) {
            throw GradleException(
                "consumer-rules.pro does not mention $declared, the package the bindings are " +
                    "generated into. R8 would strip them from a consuming application's release " +
                    "build, and nothing else here would notice.",
            )
        }
    }
}

// Only the native-library check is gated. checkConsumerRules needs nothing that -PskipNativeCheck
// skips, and the lint-only flows that pass the flag are exactly the ones where a package rename is
// most likely to go unnoticed.
tasks.named("preBuild") { dependsOn(checkConsumerRules) }

if (!project.hasProperty("skipNativeCheck")) {
    tasks.named("preBuild") { dependsOn(checkNativeLibraries) }
}
