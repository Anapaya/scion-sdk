// Copyright 2026 Anapaya Systems

/*
 * Keeps only the UniFFI symbols of the Rust static library of the crate in
 * `rust/` under their own names, as a cdylib does.
 *
 * A Rust static library exports every symbol of Rust std, its crates, and
 * C code such as BoringSSL. A Kotlin/Native binary that links two of them,
 * this one and any other Rust library, fails with duplicate symbols, or
 * binds a call to the wrong copy. After each native cargo build, this
 * changes every symbol except `uniffi_<library>_*` and `ffi_<library>_*`:
 * on ELF and Mach-O it makes them local, on COFF it renames them.
 *
 * It also makes the cinterop klib independent of the build machine. See
 * `bundleLibraries`.
 */

val crateDirectory: File = layout.projectDirectory.dir("rust").asFile

/** The library name of the crate, for example `ktor_scion_core`. */
val libraryName: Provider<String> = providers.provider {
    // Find the package of the crate.
    val manifest = crateDirectory.resolve("Cargo.toml").canonicalPath
    val packages = Cargo.metadata(crateDirectory, "--no-deps")["packages"] as List<*>
    val crate = packages.map { it as Map<*, *> }.single { File(it["manifest_path"] as String).canonicalPath == manifest }

    // Take the name of its static library.
    val targets = (crate["targets"] as List<*>).map { it as Map<*, *> }
    targets.single { "staticlib" in (it["kind"] as List<*>) }["name"] as String
}

/** The Kotlin/Native targets of this host: Gobley target name to Rust triple. */
val nativeTargets: Map<String, String> = when (NativeTarget.hostOs) {
    NativeTarget.Os.Linux -> mapOf("LinuxX64" to "x86_64-unknown-linux-gnu", "MinGWX64" to "x86_64-pc-windows-gnu")
    NativeTarget.Os.Windows -> mapOf("MinGWX64" to "x86_64-pc-windows-gnu")
    NativeTarget.Os.MacOs -> mapOf(
        "IosArm64" to "aarch64-apple-ios",
        "IosSimulatorArm64" to "aarch64-apple-ios-sim",
        "IosX64" to "x86_64-apple-ios",
        "MacOSArm64" to "aarch64-apple-darwin",
        "LinuxX64" to "x86_64-unknown-linux-gnu",
        "MinGWX64" to "x86_64-pc-windows-gnu",
    )
}

for ((gobleyTarget, rustTriple) in nativeTargets) {
    tasks.matching { it.name == "cargoBuild${gobleyTarget}Release" }.configureEach {
        val work = temporaryDir
        // The task type of Gobley is not on the classpath of build-logic.
        val defFile = withGroovyBuilder { getProperty("nativeStaticLibsDefFile") } as RegularFileProperty
        doLast {
            // Find the archive.
            val name = libraryName.get()
            val archive = Cargo.targetDirectory(crateDirectory).resolve("$rustTriple/release/lib$name.a")

            // A fresh folder per run, so that no other run can change its files.
            val runDirectory = java.nio.file.Files.createTempDirectory(work.toPath(), "run").toFile()
            try {
                LocalSymbols.localize(archive, name, rustTriple, runDirectory, crateDirectory)
            } finally {
                runDirectory.deleteRecursively()
            }

            bundleLibraries(defFile.get().asFile, archive.parentFile)
        }
    }
}

/**
 * Makes the cinterop klib independent of the build machine. Gobley writes
 * each `rustc-link-search` of a build script into [defFile] as an absolute
 * `-L` path. A library that one of those folders holds, for example an import
 * library from the cargo registry, moves from `-l` to `staticLibraries`, so
 * that cinterop packs it into the klib from [libraryDirectory]. Then all `-L`
 * paths go. The other `-l` flags name system libraries and stay.
 */
fun bundleLibraries(defFile: File, libraryDirectory: File) {
    // Read the linker flags and the static libraries.
    val lines = defFile.readLines().filter(String::isNotBlank)
    val (linkerKey, linkerFlags) = lines.firstOrNull { it.startsWith("linkerOpts") }
        ?.split("=", limit = 2)?.let { (key, value) -> key.trim() to value.trim().split(Regex("\\s+")) }
        ?: return
    val staticLibraries = lines.first { it.startsWith("staticLibraries") }
        .substringAfter("=").trim().split(Regex("\\s+"))

    // Bundle each library that a search path holds.
    val searchPaths = linkerFlags.filter { it.startsWith("-L") }.map { File(it.removePrefix("-L")) }
    val bundled = mutableListOf<String>()
    val kept = linkerFlags.filter { flag ->
        if (!flag.startsWith("-l")) return@filter !flag.startsWith("-L")
        val fileName = "lib${flag.removePrefix("-l")}.a"
        val library = searchPaths.map { it.resolve(fileName) }.firstOrNull(File::isFile) ?: return@filter true
        library.copyTo(libraryDirectory.resolve(fileName), overwrite = true)
        bundled += fileName
        false
    }

    // Write the def file back.
    defFile.writeText(
        buildString {
            if (kept.isNotEmpty()) append("$linkerKey = ${kept.joinToString(" ")}\n")
            append("staticLibraries = ${(staticLibraries + bundled).distinct().joinToString(" ")}\n")
        },
    )
}

/**
 * Makes the symbols of a Rust static library local, except the UniFFI ones.
 * See the top of this file.
 */
object LocalSymbols {
    /** Rewrites [archive] in place. A second run on the result changes nothing. */
    fun localize(archive: File, library: String, rustTriple: String, work: File, crateDirectory: File) {
        // The intermediate objects.
        val merged = work.resolve("merged.o")
        val local = work.resolve("local.o")

        when {
            "windows" in rustTriple -> renameCoff(archive, library, work, binutils(rustTriple))
            "apple" in rustTriple -> {
                // Mach-O names carry a leading underscore. With -r, ld64 turns
                // the symbols outside the list into static ones.
                val exported = work.resolve("exported.txt")
                exported.writeText("_uniffi_${library}_*\n_ffi_${library}_*\n")
                val arch = if (rustTriple.startsWith("aarch64")) "arm64" else "x86_64"

                // The linker of Xcode 15 and later refuses to run without the
                // platform, also with -r. The minimum OS is the one that rustc
                // built the objects for.
                val (platform, sdk) = when {
                    "darwin" in rustTriple -> "macos" to "macosx"
                    rustTriple.endsWith("-sim") || rustTriple.startsWith("x86_64") -> "ios-simulator" to "iphonesimulator"
                    else -> "ios" to "iphoneos"
                }
                val minimumOs = output(listOf("rustc", "--print", "deployment-target", "--target", rustTriple), directory = crateDirectory)
                    .trim().substringAfter("=")
                val sdkVersion = output(listOf("xcrun", "--sdk", sdk, "--show-sdk-version")).trim()

                // -S drops the debug map. It names the objects of the old archive
                // and of the run folder, which both go away. dsymutil then fails
                // on every debug binary that links this library.
                run(
                    listOf(
                        "xcrun", "ld", "-r", "-S", "-arch", arch,
                        "-platform_version", platform, minimumOs, sdkVersion,
                        "-exported_symbols_list", exported.path,
                        "-all_load", archive.path, "-o", local.path,
                    ),
                )

                // Replace the archive.
                archive.delete()
                run(listOf("xcrun", "libtool", "-static", "-o", archive.path, local.path))
            }
            else -> {
                val tools = binutils(rustTriple)

                // Without COMDAT groups, the final link cannot drop a section of
                // this library for a copy of the group in another one.
                run(listOf("${tools}ld", "-r", "--force-group-allocation", "--whole-archive", archive.path, "-o", merged.path))
                run(
                    listOf(
                        "${tools}objcopy", "--wildcard",
                        "--keep-global-symbol=uniffi_${library}_*",
                        "--keep-global-symbol=ffi_${library}_*",
                        merged.path, local.path,
                    ),
                )

                // Replace the archive.
                archive.delete()
                run(listOf("${tools}ar", "rcs", archive.path, local.path))
            }
        }
    }

    /**
     * The prefix of the GNU binutils that read the objects of [rustTriple]. A
     * Mac keeps `ld` and `ar` of Xcode under the plain names, so there the
     * binutils carry the target prefix.
     */
    private fun binutils(rustTriple: String): String = when {
        NativeTarget.hostOs != NativeTarget.Os.MacOs -> ""
        "windows" in rustTriple -> "x86_64-w64-mingw32-"
        else -> "x86_64-unknown-linux-gnu-"
    }

    /**
     * The COFF step. COFF has no safe way to make a COMDAT or
     * a weak symbol local, so this renames every symbol outside the UniFFI ones
     * to `<library>_rs_<name>`. A renamed symbol stays global, but no other
     * library defines it. GNU `nm` and `objcopy` read COFF: on a Linux host
     * those of binutils, on a Windows host those of MinGW, on a Mac the MinGW
     * cross binutils with the prefix [tools].
     *
     * The archive also holds DLL import members, for example from windows-sys
     * raw-dylib: short import members, or COFF objects with `.idata$*` sections
     * from dlltool. objcopy breaks or rejects both, so only the objects with code
     * go through objcopy, and the import members stay as they are.
     */
    private fun renameCoff(archive: File, library: String, work: File, tools: String) {
        // The names that keep their form.
        val marker = "${library}_rs_"
        val kept = listOf("uniffi_${library}_", "ffi_${library}_", marker)
        fun keep(name: String): Boolean =
            kept.any(name::startsWith) ||
                // MSVC C++ names, and linker metadata such as `@feat.00`.
                name.startsWith("??") || name.startsWith("@") ||
                // The DLL import machinery must keep its names to fold with the
                // import library of the consumer.
                name.startsWith("__imp_") || "__IMPORT_DESCRIPTOR_" in name ||
                "__NULL_IMPORT_DESCRIPTOR" in name || name.endsWith("_NULL_THUNK_DATA")

        // Read the archive.
        val members = ArMember.read(archive)
        val index = ArMember.index(members)
        val objects = members.filter { it.isCoffObject }
        if (objects.isEmpty()) return

        // The member names repeat, so the objects get unique names here.
        val objectDirectory = work.resolve("objects").apply { deleteRecursively(); mkdirs() }
        val objectFiles = objects.mapIndexed { index, member ->
            objectDirectory.resolve("o%06d.o".format(index)).apply { writeBytes(member.data) }
        }
        val objectArchive = work.resolve("objects.a").apply { delete() }
        // A response file, because the names exceed the command line limit of
        // Windows. It holds plain names: GNU tools read a backslash in it as an
        // escape.
        val objectList = work.resolve("objects.txt")
        objectList.writeText(objectFiles.joinToString("\n") { it.name })
        run(listOf("${tools}ar", "rcS", objectArchive.path, "@${objectList.path}"), directory = objectDirectory)

        // Only the objects define names to rename. The import members define the
        // DLL functions, and those keep their names.
        val defined = globalSymbols(objectArchive, definedOnly = true, tools)
        // A new name must not exist yet, defined or undefined. Else it binds to
        // the wrong definition.
        val taken = globalSymbols(archive, definedOnly = false, tools).toMutableSet()
        val renames = defined.filterNot(::keep).associateWith { name ->
            var candidate = "$marker$name"
            var counter = 0
            while (candidate in taken) candidate = "$marker${++counter}_$name"
            taken += candidate
            candidate
        }
        if (renames.isEmpty()) return

        // Rename the symbols in the objects.
        val map = work.resolve("renames.txt")
        map.writeText(renames.entries.joinToString("") { (old, new) -> "$old $new\n" })
        val renamedArchive = work.resolve("renamed.a")
        run(listOf("${tools}objcopy", "--redefine-syms=${map.path}", objectArchive.path, renamedArchive.path))
        val renamed = ArMember.read(renamedArchive).filter { it.isCoffObject }.iterator()

        // Put the renamed objects back.
        val rebuilt = members.filterNot { it.isIndex }.map { if (it.isCoffObject) it.withData(renamed.next().data) else it }
        check(!renamed.hasNext()) { "objcopy changed the number of objects in $archive" }
        // GNU ranlib rewrites the dlltool import objects, and lld cannot read
        // them afterwards. So the new index is the old one with the new names.
        ArMember.write(archive, rebuilt, index.map { (name, member) -> (renames[name] ?: name) to member })
    }

    /** The global symbol names of [archive], from `nm` in POSIX format. */
    private fun globalSymbols(archive: File, definedOnly: Boolean, tools: String): Set<String> {
        // List the symbols.
        val command = listOf("${tools}nm", "-g", "-P") + (if (definedOnly) listOf("--defined-only") else emptyList()) + archive.path
        val listing = output(command)

        // Keep the names.
        return listing.lineSequence()
            .map { it.trim().split(Regex("\\s+")) }
            // A symbol line is `name type [value size]`. A member line ends in `:`.
            .filter { it.size >= 2 && it[1].length == 1 && !it[0].endsWith(":") }
            .map { it[0] }
            .toSet()
    }

    private fun run(command: List<String>, directory: File? = null) {
        output(command, directory)
    }

    private fun output(command: List<String>, directory: File? = null): String {
        // stderr goes to a file, so a full pipe cannot block the tool.
        val errors = File.createTempFile("rust-staticlib-isolation", ".log")
        try {
            val process = ProcessBuilder(command).directory(directory).redirectError(errors).start()
            val stdout = process.inputStream.bufferedReader().readText()
            check(process.waitFor() == 0) { "${command.first()} failed:\n$stdout${errors.readText()}" }
            return stdout
        } finally {
            errors.delete()
        }
    }
}

/** A member of a GNU `ar` archive: its 60-byte header and its data. */
class ArMember(private val header: ByteArray, val data: ByteArray, private val offset: Int = -1) {
    private val name: String = String(header, 0, 16, Charsets.US_ASCII).trimEnd()

    /** The symbol index, `/` or `/SYM64/`. */
    val isIndex: Boolean = name == "/" || name == "/SYM64/"

    /** A COFF object with code, not an index, the long name table, or an import member. */
    val isCoffObject: Boolean
        get() = !isIndex && name != "//" && !isShortImport && !isImportObject

    // A short import member and a bigobj object both start with 0x0000 and
    // 0xFFFF. The version after it is 0 for a short import, 2 or more for a
    // bigobj object.
    private val hasAnonymousHeader: Boolean =
        data.size >= 6 && data[0] == 0.toByte() && data[1] == 0.toByte() &&
            data[2] == 0xFF.toByte() && data[3] == 0xFF.toByte()
    private val isShortImport: Boolean = hasAnonymousHeader && data[4] == 0.toByte() && data[5] == 0.toByte()

    // dlltool writes each import as a regular COFF object with `.idata$*`
    // sections. objcopy breaks those.
    private val isImportObject: Boolean
        get() {
            if (hasAnonymousHeader || data.size < 20) return false

            // Look for an `.idata$` section.
            val sections = u16(2)
            val optionalHeader = u16(16)
            return (0 until sections).any { index ->
                val start = 20 + optionalHeader + index * 40
                start + 8 <= data.size &&
                    String(data, start, 8, Charsets.US_ASCII).startsWith(".idata\$")
            }
        }

    private fun u16(offset: Int): Int = (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

    /** The same member with [data], and its size field to match. */
    fun withData(data: ByteArray): ArMember {
        val header = header.copyOf()
        "%-10d".format(data.size).toByteArray(Charsets.US_ASCII).copyInto(header, 48)
        return ArMember(header, data)
    }

    companion object {
        private val MAGIC = "!<arch>\n".toByteArray(Charsets.US_ASCII)

        fun read(file: File): List<ArMember> {
            // Check the magic.
            val bytes = file.readBytes()
            check(bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) { "$file is no ar archive" }

            // Read the members.
            val members = mutableListOf<ArMember>()
            var offset = MAGIC.size
            while (offset + 60 <= bytes.size) {
                val header = bytes.copyOfRange(offset, offset + 60)
                val size = String(header, 48, 10, Charsets.US_ASCII).trim().toInt()
                val start = offset + 60
                members += ArMember(header, bytes.copyOfRange(start, start + size), offset)
                // Members start at even offsets.
                offset = start + size + (size and 1)
            }
            return members
        }

        /**
         * The entries of the GNU symbol index `/` of [members]: each symbol
         * with the position of its member among the members after the index.
         */
        fun index(members: List<ArMember>): List<Pair<String, Int>> {
            // Find the index and the position of each member.
            val index = members.singleOrNull { it.name == "/" } ?: return emptyList()
            val positions = members.filterNot { it.isIndex }.withIndex().associate { (position, member) -> member.offset to position }

            // Read the entries.
            val data = index.data
            val count = u32(data, 0)
            var name = 4 + 4 * count
            return (0 until count).map { entry ->
                val end = (name until data.size).first { data[it] == 0.toByte() }
                val symbol = String(data, name, end - name, Charsets.US_ASCII)
                name = end + 1
                symbol to positions.getValue(u32(data, 4 + 4 * entry))
            }
        }

        /** Writes [members] after a GNU symbol index `/` with [index]. */
        fun write(file: File, members: List<ArMember>, index: List<Pair<String, Int>>) {
            // Build the index.
            val names = index.map { (symbol, _) -> symbol.toByteArray(Charsets.US_ASCII) + 0 }
            val indexSize = 4 + 4 * index.size + names.sumOf { it.size }
            // Offsets of the member headers, after the magic and the index.
            var position = MAGIC.size + 60 + indexSize + (indexSize and 1)
            val offsets = members.map { member ->
                position.also { position += 60 + member.data.size + (member.data.size and 1) }
            }
            val indexData = java.io.ByteArrayOutputStream(indexSize).apply {
                write(be32(index.size))
                for ((_, member) in index) write(be32(offsets[member]))
                for (name in names) write(name)
            }.toByteArray()
            val indexHeader = "%-16s%-12s%-6s%-6s%-8s%-10s`\n".format("/", "0", "0", "0", "0", indexSize).toByteArray(Charsets.US_ASCII)

            // Write the archive.
            file.outputStream().buffered().use { out ->
                out.write(MAGIC)
                for ((header, data) in listOf(indexHeader to indexData) + members.map { it.header to it.data }) {
                    out.write(header)
                    out.write(data)
                    if (data.size % 2 == 1) out.write('\n'.code)
                }
            }
        }

        private fun u32(data: ByteArray, offset: Int): Int =
            (0 until 4).fold(0) { value, byte -> (value shl 8) or (data[offset + byte].toInt() and 0xFF) }

        private fun be32(value: Int): ByteArray = ByteArray(4) { byte -> (value ushr (24 - 8 * byte)).toByte() }
    }
}
