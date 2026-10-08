// Copyright 2026 Anapaya Systems

/** A target that the build compiles the Rust library for. */
class NativeTarget private constructor(
    /** The name of the target in the Gobley task names. */
    val gobleyTarget: String,
    val rustTriple: String,
) {
    enum class Os { Linux, MacOs, Windows }

    companion object {
        /** The OS of the build host. */
        val hostOs: Os = System.getProperty("os.name").lowercase().let {
            when {
                it.contains("mac") -> Os.MacOs
                it.contains("windows") -> Os.Windows
                else -> Os.Linux
            }
        }

        private val hostIsArm: Boolean =
            System.getProperty("os.arch").lowercase() in setOf("aarch64", "arm64")

        /**
         * The target for every Windows build. It uses MinGW, because
         * Kotlin/Native has no MSVC target.
         */
        val windows: NativeTarget = NativeTarget("MinGWX64", "x86_64-pc-windows-gnu")

        /** The target of a Mac host for Linux. */
        val linux: NativeTarget = NativeTarget("LinuxX64", "x86_64-unknown-linux-gnu")

        val host: NativeTarget = when (hostOs) {
            Os.MacOs ->
                if (hostIsArm) NativeTarget("MacOSArm64", "aarch64-apple-darwin")
                else NativeTarget("MacOSX64", "x86_64-apple-darwin")
            Os.Linux ->
                if (hostIsArm) NativeTarget("LinuxArm64", "aarch64-unknown-linux-gnu")
                else linux
            Os.Windows -> windows
        }

        /** The targets whose library goes into the JVM jar on this host. */
        val jvmTargets: List<NativeTarget> = when (hostOs) {
            Os.Linux -> listOf(host, windows)
            Os.MacOs -> listOf(host, linux, windows)
            Os.Windows -> listOf(host)
        }
    }
}
