# Copyright 2026 Anapaya Systems
"""Tests for apple.py.

They pin what the checks are built on: the formats parsed out of `otool`, `nm` and rustc, and the
slice table those checks compare against.
"""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest
import unittest.mock

import apple

# Output of `otool -arch arm64 -l libscion_http3_ffi.a` under Xcode 26.3.
IOS_OBJECT = """\
Archive : /tmp/libscion_http3_ffi.a
/tmp/libscion_http3_ffi.a(scion_http3_ffi.o):
Load command 0
      cmd LC_SEGMENT_64
  cmdsize 552
  segname
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 2
    minos 15.0
      sdk n/a
   ntools 1
     tool 3
  version 956.6
Load command 2
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 0.0
"""

# The same object, plus two BoringSSL objects.
IOS_ARCHIVE = (
    IOS_OBJECT
    + """\
/tmp/libscion_http3_ffi.a(aes.o):
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 2
    minos 12.0
      sdk n/a
   ntools 1
     tool 3
  version 956.6
Load command 2
      cmd LC_UUID
  cmdsize 24
     uuid 0F0F0F0F-0F0F-0F0F-0F0F-0F0F0F0F0F0F
/tmp/libscion_http3_ffi.a(sha256.o):
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 2
    minos 12.0
      sdk n/a
   ntools 1
     tool 3
  version 956.6
"""
)


class BuildVersionsTest(unittest.TestCase):
    def test_reads_platform_and_minimum(self):
        self.assertEqual(apple.build_versions(IOS_OBJECT), {("IOS", "15.0"): 1})

    def test_counts_every_object(self):
        self.assertEqual(
            apple.build_versions(IOS_ARCHIVE),
            {("IOS", "15.0"): 1, ("IOS", "12.0"): 2},
        )

    def test_accepts_a_named_platform(self):
        """Some versions of otool print the name where others print the number."""
        named = IOS_OBJECT.replace("platform 2", "platform IOSSIMULATOR")
        self.assertEqual(apple.build_versions(named), {("IOSSIMULATOR", "15.0"): 1})

    def test_names_a_platform_it_does_not_build_for(self):
        """A wrong-SDK build has to be reported, not dropped for being unrecognised."""
        other = IOS_OBJECT.replace("platform 2", "platform 3")
        self.assertEqual(apple.build_versions(other), {("platform 3", "15.0"): 1})

    def test_reads_the_older_load_command(self):
        older = """\
Load command 1
      cmd LC_VERSION_MIN_IPHONEOS
  cmdsize 16
  version 11.0
      sdk 11.0
"""
        self.assertEqual(apple.build_versions(older), {(apple.IOS_FAMILY, "11.0"): 1})

    def test_ignores_the_version_of_the_build_tool(self):
        """LC_BUILD_VERSION lists the tool that built the object, and that tool has a version."""
        self.assertEqual(apple.build_versions(IOS_OBJECT), {("IOS", "15.0"): 1})
        self.assertNotIn(("IOS", "956.6"), apple.build_versions(IOS_OBJECT))

    def test_ignores_other_version_fields(self):
        """A source or dylib version is not a deployment target, and must not be read as one."""
        other = """\
Load command 0
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 0.0
Load command 1
      cmd LC_ID_DYLIB
  cmdsize 56
     name /usr/lib/libSystem.B.dylib
  current version 1.0.0
"""
        self.assertEqual(apple.build_versions(other), {})

    def test_reports_nothing_for_empty_output(self):
        self.assertEqual(apple.build_versions(""), {})


class AcceptedMachoPlatformsTest(unittest.TestCase):
    """What the platform check compares against, per slice platform."""

    def test_covers_every_platform_built_for(self):
        self.assertEqual(
            set(apple.ACCEPTED_MACHO_PLATFORMS),
            {platform.macho_platform for platform in apple.PLATFORMS},
        )

    def test_both_ios_platforms_accept_the_older_load_command(self):
        """It cannot say whether the object is for a device or for a simulator."""
        for name in ("IOS", "IOSSIMULATOR"):
            self.assertIn(apple.IOS_FAMILY, apple.ACCEPTED_MACHO_PLATFORMS[name])

    def test_no_platform_accepts_another_one(self):
        """A host-SDK build is what the platform check is here to catch."""
        self.assertNotIn("MACOS", apple.ACCEPTED_MACHO_PLATFORMS["IOS"])
        self.assertNotIn("MACOS", apple.ACCEPTED_MACHO_PLATFORMS["IOSSIMULATOR"])
        self.assertNotIn(apple.IOS_FAMILY, apple.ACCEPTED_MACHO_PLATFORMS["MACOS"])
        self.assertNotIn("IOS", apple.ACCEPTED_MACHO_PLATFORMS["MACOS"])

    def test_a_simulator_library_refuses_a_device_object(self):
        """LC_BUILD_VERSION does say which of the two an object is for."""
        self.assertNotIn("IOS", apple.ACCEPTED_MACHO_PLATFORMS["IOSSIMULATOR"])
        self.assertNotIn("IOSSIMULATOR", apple.ACCEPTED_MACHO_PLATFORMS["IOS"])


class DefinedSymbolsTest(unittest.TestCase):
    NM_OUTPUT = """\
/tmp/libscion_http3_ffi.a(scion_http3_ffi.o):
0000000000001234 T _ffi_scion_http3_ffi_uniffi_contract_version
0000000000005678 S _some_data
                 U _SecTrustEvaluateWithError
/tmp/libscion_http3_ffi.a(empty.o): no symbols
"""

    def test_keeps_the_defined_ones(self):
        self.assertEqual(
            apple.defined_symbols(self.NM_OUTPUT),
            {"_ffi_scion_http3_ffi_uniffi_contract_version", "_some_data"},
        )

    def test_drops_the_undefined_ones(self):
        self.assertNotIn("_SecTrustEvaluateWithError", apple.defined_symbols(self.NM_OUTPUT))

    def test_reports_nothing_for_empty_output(self):
        self.assertEqual(apple.defined_symbols(""), set())


class DefinedSymbolsOfTest(unittest.TestCase):
    """nm exits non-zero on a static library of this crate, and its output is still usable."""

    # What nm writes to stderr for a static library of this crate under Xcode 26.3.
    NOTES = (
        "libscion_http3_ffi.a:cpu_aarch64_linux.c.o: no symbols\n"
        "nm: error: libscion_http3_ffi.a(compiler_builtins.rcgu.o): Unknown attribute kind (102)\n"
    )

    def run_with(self, stdout, stderr, returncode):
        completed = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)
        with unittest.mock.patch.object(apple.subprocess, "run", return_value=completed):
            return apple.defined_symbols_of(pathlib.Path("libscion_http3_ffi.a"), "arm64")

    def test_keeps_the_symbols_nm_did_list(self):
        listed = "0000000000001234 T _ffi_scion_http3_ffi_uniffi_contract_version\n"
        self.assertEqual(
            self.run_with(listed, self.NOTES, 1),
            {"_ffi_scion_http3_ffi_uniffi_contract_version"},
        )

    def test_reports_output_nm_could_not_produce_at_all(self):
        with self.assertRaises(apple.Failure) as raised:
            self.run_with("", "nm: error: libscion_http3_ffi.a: No such file or directory\n", 1)
        self.assertIn("No such file or directory", str(raised.exception))


class HighestVersionTest(unittest.TestCase):
    def test_compares_by_number(self):
        """9.0 reads as more than 15.0 when the strings are compared instead."""
        self.assertEqual(apple.highest_version({("IOS", "9.0"): 1, ("IOS", "15.0"): 4}), "15.0")

    def test_reads_a_single_version(self):
        self.assertEqual(apple.highest_version({("MACOS", "12.0"): 7}), "12.0")


class NativeStaticLibsTest(unittest.TestCase):
    NOTE = (
        "   Compiling scion-http3-ffi v0.7.0\n"
        "note: Link against the following native artifacts when linking against this static "
        "library. The order and any duplication can be significant on some platforms.\n"
        "note: native-static-libs: -framework Security -liconv -lSystem -lobjc -lc -lm\n"
    )

    def test_reads_the_note(self):
        self.assertEqual(
            apple.native_static_libs(self.NOTE),
            ["-framework", "Security", "-liconv", "-lSystem", "-lobjc", "-lc", "-lm"],
        )

    def test_takes_the_last_note(self):
        """One invocation can link more than one crate type, and each one reports."""
        twice = self.NOTE + "note: native-static-libs: -lSystem\n"
        self.assertEqual(apple.native_static_libs(twice), ["-lSystem"])

    # Captured: `cargo rustc --color always -- --print native-static-libs`, which is what CI gets
    # because the workflow sets CARGO_TERM_COLOR. rustc wraps the whole note, so the reset at the
    # end of the line sits inside the last flag.
    COLOURED = (
        "\x1b[0m\x1b[1m\x1b[38;5;10mnote\x1b[0m\x1b[0m\x1b[1m: native-static-libs: "
        "-framework Security -lc++ -lSystem -lc -lm\x1b[0m\n"
    )

    def test_drops_the_colour_around_the_note(self):
        """A reset left on the last flag asks the linker for a library that cannot exist."""
        self.assertEqual(
            apple.native_static_libs(self.COLOURED),
            ["-framework", "Security", "-lc++", "-lSystem", "-lc", "-lm"],
        )

    def test_reports_a_flag_that_is_still_not_printable(self):
        """Anything that survives the strip would surface as a puzzling linker error instead."""
        with self.assertRaises(apple.Failure) as raised:
            apple.native_static_libs("note: native-static-libs: -lSystem -lm\x07\n")
        self.assertIn("control character", str(raised.exception))

    def test_reports_nothing_when_rustc_did_not_link(self):
        self.assertIsNone(apple.native_static_libs("   Compiling scion-http3-ffi v0.7.0\n"))


class VersionTupleTest(unittest.TestCase):
    def test_compares_by_number(self):
        self.assertGreater(apple.version_tuple("15.0"), apple.version_tuple("9.0"))

    def test_reads_three_components(self):
        self.assertEqual(apple.version_tuple("15.4.1"), (15, 4, 1))


class ModuleNameTest(unittest.TestCase):
    def test_reads_a_module(self):
        text = 'module ScionHTTP3UniffiFFI {\n  header "ScionHTTP3UniffiFFI.h"\n  export *\n}\n'
        self.assertEqual(apple.module_name(text), "ScionHTTP3UniffiFFI")

    def test_reads_a_framework_module(self):
        self.assertEqual(apple.module_name("framework module Foo {\n}\n"), "Foo")

    def test_reports_nothing_without_one(self):
        self.assertIsNone(apple.module_name("// nothing here\n"))


class SliceTableTest(unittest.TestCase):
    def test_every_target_belongs_to_one_slice(self):
        used = [triple for entry in apple.SLICES for triple in entry.triples]
        self.assertEqual(sorted(used), sorted(apple.TARGETS))

    def test_every_slice_names_known_targets(self):
        for entry in apple.SLICES:
            for triple in entry.triples:
                self.assertIn(triple, apple.TARGETS)

    def test_every_target_of_a_slice_shares_its_platform(self):
        """lipo fuses architectures, not platforms: one slice is one platform by definition."""
        for entry in apple.SLICES:
            for target in entry.targets:
                self.assertIs(target.platform, entry.platform)

    def test_identifiers_follow_xcodebuild_naming(self):
        """The name xcodebuild derives: the platform, the sorted architectures, then the variant."""
        for entry in apple.SLICES:
            expected = f"{entry.platform.xcframework_platform}-{'_'.join(sorted(entry.archs))}"
            if entry.platform.xcframework_variant:
                expected += f"-{entry.platform.xcframework_variant}"
            self.assertEqual(entry.identifier, expected)

    def test_the_issue_slices_are_the_ones_built(self):
        self.assertEqual(
            [entry.identifier for entry in apple.SLICES],
            ["ios-arm64", "ios-arm64_x86_64-simulator", "macos-arm64_x86_64"],
        )


if __name__ == "__main__":
    unittest.main()


MANIFEST = """\
let package = Package(
    name: "scion-http3-swift",
    platforms: [.iOS(.v15), .macOS(.v12)],
    targets: [
        .binaryTarget(name: "ScionHTTP3UniffiFFI", path: "ScionHTTP3UniffiFFI.xcframework"),
    ]
)
"""


class PackageManifestTest(unittest.TestCase):
    def test_reads_the_platforms(self):
        self.assertEqual(apple.declared_platforms(MANIFEST), {"ios": "15.0", "macos": "12.0"})

    def test_reads_a_minor_version(self):
        self.assertEqual(
            apple.declared_platforms("platforms: [.iOS(.v15_1), .macOS( .v12 )]"),
            {"ios": "15.1", "macos": "12.0"},
        )

    def test_reads_the_binary_target(self):
        self.assertEqual(
            apple.declared_binary_target(MANIFEST),
            ("ScionHTTP3UniffiFFI", "ScionHTTP3UniffiFFI.xcframework"),
        )

    def test_reads_a_binary_target_split_over_lines(self):
        manifest = '.binaryTarget(\n    name: "A",\n    path: "A.xcframework"\n)'
        self.assertEqual(apple.declared_binary_target(manifest), ("A", "A.xcframework"))

    def test_ignores_a_release_binary_target(self):
        manifest = '.binaryTarget(name: "A", url: "https://example.org/A.zip", checksum: "0")'
        self.assertIsNone(apple.declared_binary_target(manifest))

    def check(self, manifest, module="ScionHTTP3UniffiFFI"):
        report = apple.Report()
        with unittest.mock.patch("builtins.print"):
            apple.check_manifest(report, manifest, module)
        return report.failures

    def test_accepts_what_the_tool_builds(self):
        self.assertEqual(self.check(MANIFEST), 0)

    def test_refuses_a_platform_above_the_slices(self):
        self.assertEqual(self.check(MANIFEST.replace(".v15", ".v16")), 1)

    def test_refuses_a_platform_below_the_slices(self):
        self.assertEqual(self.check(MANIFEST.replace(".v12", ".v11")), 1)

    def test_refuses_a_missing_platform(self):
        self.assertEqual(self.check(MANIFEST.replace(", .macOS(.v12)", "")), 1)

    def test_refuses_a_binary_target_named_after_another_module(self):
        self.assertEqual(self.check(MANIFEST, module="SomethingElseFFI"), 1)

    def test_refuses_a_binary_target_from_another_path(self):
        self.assertEqual(self.check(MANIFEST.replace("ScionHTTP3UniffiFFI.xcframework", "x")), 1)

    def test_skips_the_module_comparison_without_a_module(self):
        self.assertEqual(self.check(MANIFEST, module=None), 0)

    def test_the_checked_in_manifest_passes(self):
        self.assertEqual(self.check(apple.PACKAGE_MANIFEST.read_text()), 0)


class ReleaseManifestTest(unittest.TestCase):
    URL = "https://example.org/v1.2.3/ScionHTTP3UniffiFFI-1.2.3.xcframework.zip"
    CHECKSUM = "0" * 64

    def test_points_the_binary_target_at_the_zip(self):
        released = apple.release_manifest(MANIFEST, self.URL, self.CHECKSUM)
        self.assertIn(
            f'.binaryTarget(name: "ScionHTTP3UniffiFFI", url: "{self.URL}", '
            f'checksum: "{self.CHECKSUM}")',
            released,
        )
        self.assertNotIn("path:", released)

    def test_leaves_everything_else_alone(self):
        released = apple.release_manifest(MANIFEST, self.URL, self.CHECKSUM)
        self.assertEqual(apple.declared_platforms(released), apple.declared_platforms(MANIFEST))
        self.assertEqual(released.count("\n"), MANIFEST.count("\n"))

    def test_the_result_is_what_the_local_check_ignores(self):
        released = apple.release_manifest(MANIFEST, self.URL, self.CHECKSUM)
        self.assertIsNone(apple.declared_binary_target(released))

    def test_rewrites_a_binary_target_split_over_lines(self):
        manifest = '.binaryTarget(\n    name: "A",\n    path: "A.xcframework"\n)'
        self.assertEqual(
            apple.release_manifest(manifest, self.URL, self.CHECKSUM),
            f'.binaryTarget(\n    name: "A",\n    url: "{self.URL}", checksum: "{self.CHECKSUM}"\n)',
        )

    def test_refuses_a_manifest_without_a_local_binary_target(self):
        manifest = '.binaryTarget(name: "A", url: "https://example.org/A.zip", checksum: "0")'
        with self.assertRaises(apple.Failure):
            apple.release_manifest(manifest, self.URL, self.CHECKSUM)

    def test_refuses_two_local_binary_targets(self):
        manifest = MANIFEST + '.binaryTarget(name: "B", path: "B.xcframework")'
        with self.assertRaises(apple.Failure):
            apple.release_manifest(manifest, self.URL, self.CHECKSUM)

    def test_the_checked_in_manifest_can_be_released(self):
        released = apple.release_manifest(
            apple.PACKAGE_MANIFEST.read_text(), self.URL, self.CHECKSUM
        )
        self.assertIn(self.CHECKSUM, released)


class ChecksumsTextTest(unittest.TestCase):
    def test_writes_the_format_shasum_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "a.zip"
            path.write_bytes(b"abc")
            self.assertEqual(
                apple.checksums_text([path]),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a.zip\n",
            )
