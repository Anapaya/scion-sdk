// Copyright 2026 Anapaya Systems

import groovy.json.JsonSlurper
import java.io.File

/** Helpers that query cargo. */
object Cargo {
    /** Runs `cargo metadata` for the package in [dir]. */
    fun metadata(dir: File, vararg options: String): Map<*, *> {
        // Run cargo metadata.
        val errors = File.createTempFile("cargo-metadata", ".log")
        val process = ProcessBuilder("cargo", "metadata", "--format-version", "1", *options)
            .directory(dir)
            .redirectError(errors)
            // Cargo rejects an empty value, and a reused daemon can carry one.
            .apply { if (environment()["CARGO_TARGET_DIR"].isNullOrEmpty()) environment().remove("CARGO_TARGET_DIR") }
            .start()

        // Read the output and check the status.
        val metadata = process.inputStream.bufferedReader().readText()
        val status = process.waitFor()
        val log = errors.readText().also { errors.delete() }
        check(status == 0) { "cargo metadata failed in $dir:\n$log" }
        return JsonSlurper().parseText(metadata) as Map<*, *>
    }

    /** Where cargo puts the build output of the package in [dir]. */
    fun targetDirectory(dir: File): File = File(metadata(dir, "--no-deps")["target_directory"] as String)
}
