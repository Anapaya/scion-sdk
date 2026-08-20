#!/usr/bin/env python3
# Copyright 2026 Anapaya Systems
"""Tests for the parsing in android.py.

Everything this tool reads out of another file, a Gradle script and a uniffi config, is pinned here
against a sample of the real thing. A format change then fails a test rather than silently returning
the wrong answer, which is the failure mode these parsers have.

Run with `python3 -m unittest discover bindings/android/tools`.
"""

import unittest
from pathlib import Path

import android

GRADLE_MODULE = """
android {
    namespace = "com.anapaya.scion.http3"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }
}
"""

# The comment above the key is what an unanchored pattern would read the wrong literal from. The name
# lives here rather than in the Kotlin: the generated bindings load the library, and they take the name
# from this file.
UNIFFI_CONFIG = """
[bindings.kotlin]
# Matches the `[lib] name` in Cargo.toml, so the generated code looks up
# libscion_http3_ffi.so.
cdylib_name = "scion_http3_ffi"

package_name = "com.anapaya.scion.http3.uniffi"
"""


class DeclaredLibraryName(unittest.TestCase):
    def test_reads_the_declaration(self):
        match = android.CDYLIB_NAME_DECLARATION.search(UNIFFI_CONFIG)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "scion_http3_ffi")

    def test_ignores_a_commented_out_key(self):
        # The likeliest way this file grows a second mention of the key, and the reason the pattern
        # requires it to open the line.
        commented = """
        [bindings.kotlin]
        # cdylib_name = "an_old_name"
        package_name = "com.anapaya.scion.http3.uniffi"
        """
        self.assertIsNone(android.CDYLIB_NAME_DECLARATION.search(commented))

    def test_does_not_cross_lines_into_a_later_literal(self):
        prose_only = """
        # cdylib_name is what the bindings load.
        package_name = "not the library"
        """
        self.assertIsNone(android.CDYLIB_NAME_DECLARATION.search(prose_only))

    def test_reads_the_name_the_real_config_declares(self):
        # The check this parser feeds compares the two, so an unparseable config would silently skip
        # it rather than fail.
        self.assertEqual(android.declared_library_name(), "scion_http3_ffi")


class MinSdk(unittest.TestCase):
    """minSdk is the single source of truth for the API level the libraries are compiled for."""

    def test_reads_min_sdk_and_not_compile_sdk(self):
        match = android.MIN_SDK_DECLARATION.search(GRADLE_MODULE)
        self.assertIsNotNone(match)
        self.assertEqual(int(match.group(1)), 24)

    def test_absent_min_sdk(self):
        self.assertIsNone(android.MIN_SDK_DECLARATION.search("android { compileSdk = 35 }"))

    def test_the_real_module_is_readable(self):
        # The build derives the clang target from this, so an unparseable module is fatal rather than
        # a silently wrong API level.
        self.assertGreaterEqual(android.android_api_level(), 21)

    def test_matches_the_declaration_in_the_real_module(self):
        declared = android.MIN_SDK_DECLARATION.search(android.GRADLE_MODULE.read_text())
        self.assertIsNotNone(declared)
        self.assertEqual(android.android_api_level(), int(declared.group(1)))


class Abis(unittest.TestCase):
    def test_every_abi_names_its_toolchain_prefixes(self):
        for abi in android.ABIS.values():
            self.assertTrue(abi.clang)
            self.assertTrue(abi.sysroot_dir)
            self.assertEqual(abi.env_suffix, abi.triple.replace("-", "_"))

    def test_the_page_size_is_the_android_requirement(self):
        self.assertEqual(android.MIN_PAGE_ALIGN, 16 * 1024)


# What `llvm-nm -u` prints when the C++ runtime is genuinely missing. Matching only the std:: mangling
# catches one of these seven, which is why the pattern covers operator new/delete, the __cxa_ entry
# points, the unwinder and __cxxabiv1's typeinfo and vtables as well.
NM_UNDEFINED_BROKEN = """\
                 U _Znwm
                 U _ZdlPv
                 U __cxa_throw
                 U __cxa_begin_catch
                 U _Unwind_Resume
                 U _ZTVN10__cxxabiv117__class_type_infoE
                 U _ZSt9terminatev
"""

# What it prints for a correctly linked library: the only C++-looking imports are the two that
# bionic's libc provides.
NM_UNDEFINED_HEALTHY = """\
                 U __cxa_atexit
                 U __cxa_finalize
                 U abort
                 U memcpy
                 U pthread_create
"""


class UndefinedCxxRuntime(unittest.TestCase):
    def test_catches_every_symbol_a_missing_runtime_leaves(self):
        found = android.undefined_cxx_runtime_symbols(NM_UNDEFINED_BROKEN)
        self.assertEqual(len(found), 7, f"missed some of the runtime symbols: {found}")

    def test_the_std_only_pattern_would_have_caught_almost_none(self):
        # Guards the reason the pattern is as wide as it is.
        import re

        narrow = re.compile(r"^(?:_ZNSt|_ZNKSt|_ZSt)")
        names = [line.split()[-1] for line in NM_UNDEFINED_BROKEN.splitlines() if line.split()]
        self.assertEqual(len([n for n in names if narrow.match(n)]), 1)

    def test_a_healthy_library_reports_nothing(self):
        self.assertEqual(android.undefined_cxx_runtime_symbols(NM_UNDEFINED_HEALTHY), [])

    def test_the_two_libc_provided_cxa_symbols_are_not_flagged(self):
        for name in ("__cxa_atexit", "__cxa_finalize"):
            self.assertEqual(android.undefined_cxx_runtime_symbols(f"    U {name}\n"), [])

    def test_other_cxa_symbols_are_flagged(self):
        self.assertEqual(
            android.undefined_cxx_runtime_symbols("    U __cxa_pure_virtual\n"),
            ["__cxa_pure_virtual"],
        )

    def test_empty_output(self):
        self.assertEqual(android.undefined_cxx_runtime_symbols(""), [])


class StagedLayout(unittest.TestCase):
    def test_unstripped_sits_beside_the_staged_libraries(self):
        # They have to be created and removed together, so neither can go stale against the other.
        self.assertEqual(android.UNSTRIPPED_DIR.parent, android.JNI_LIBS_DIR.parent)

    def test_unstripped_is_not_where_gradle_looks_for_libraries(self):
        self.assertNotEqual(android.UNSTRIPPED_DIR, android.JNI_LIBS_DIR)


class StagedSet(unittest.TestCase):
    """The manifest is what makes a passing run mean "these bytes came from this build"."""

    def test_the_manifest_sits_with_the_libraries_it_describes(self):
        self.assertEqual(android.BUILD_MANIFEST.parent, android.JNI_LIBS_DIR.parent)

    def test_the_manifest_is_not_an_abi_directory(self):
        # check_staged_set only rejects directories, so a file here must not be mistaken for one.
        self.assertFalse(android.BUILD_MANIFEST.is_dir())

    def test_hashing_is_content_addressed(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "a"
            second = Path(directory) / "b"
            first.write_bytes(b"same")
            second.write_bytes(b"same")
            self.assertEqual(android.sha256_of(first), android.sha256_of(second))
            second.write_bytes(b"different")
            self.assertNotEqual(android.sha256_of(first), android.sha256_of(second))


if __name__ == "__main__":
    unittest.main()
