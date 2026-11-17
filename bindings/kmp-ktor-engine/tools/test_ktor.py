#!/usr/bin/env python3
# Copyright 2026 Anapaya Systems
"""Tests for ktor.py.

Run with `python3 -m unittest discover -s tools -p 'test_*.py'` in the engine folder.
"""

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import ktor

# Lines of `objdump -T` for a Rust cdylib.
OBJDUMP = """
libktor_scion_core.so:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.2.5) memcpy
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.28) fcntl64
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.17) clock_gettime
0000000000000000  w   D  *UND*  0000000000000000  Base        __gmon_start__
00000000000a1b20 g    DF .text  0000000000000042  Base        uniffi_ktor_scion_core_fn_init
"""


class GlibcRequirement(unittest.TestCase):
    def test_takes_the_newest_version(self):
        self.assertEqual(ktor.glibc_requirement(OBJDUMP), (2, 28))

    def test_compares_numbers_not_text(self):
        self.assertEqual(ktor.glibc_requirement("(GLIBC_2.9) a\n(GLIBC_2.17) b"), (2, 17))

    def test_is_none_without_glibc_symbols(self):
        self.assertIsNone(ktor.glibc_requirement("DYNAMIC SYMBOL TABLE:\n"))

    def test_a_newer_glibc_exceeds_the_limit(self):
        self.assertGreater(ktor.glibc_requirement("(GLIBC_2.34) a"), ktor.MAX_GLIBC)


class SdkVersion(unittest.TestCase):
    def test_reads_the_version_crate(self):
        metadata = {
            "packages": [
                {"name": "ktor-scion-core", "version": "0.1.0"},
                {"name": "scion-stack", "version": "0.8.6"},
            ]
        }
        self.assertEqual(ktor.sdk_version(metadata), "0.8.6")

    def test_fails_without_the_version_crate(self):
        with self.assertRaises(ktor.Failure):
            ktor.sdk_version({"packages": []})


class ExpectedFiles(unittest.TestCase):
    def test_has_the_root_module_and_each_target(self):
        expected = ktor.expected_files("1.2.3")
        self.assertEqual(len(expected), len(ktor.MODULES) * (1 + len(ktor.TARGETS)))
        self.assertIn("ktor-client-scion-1.2.3.module", expected["ktor-client-scion"])
        self.assertIn(
            "ktor-client-scion-testing-iosarm64-1.2.3-cinterop-rust.klib",
            expected["ktor-client-scion-testing-iosarm64"],
        )

    def test_the_jvm_jar_has_the_macos_and_the_linux_library(self):
        entries = ktor.expected_files("1.2.3")["ktor-client-scion-jvm"][
            "ktor-client-scion-jvm-1.2.3.jar"
        ]
        self.assertEqual(
            entries,
            ["darwin-aarch64/libktor_scion_core.dylib", "linux-x86-64/libktor_scion_core.so"],
        )

    def test_the_aar_has_the_given_abis(self):
        files = ktor.expected_files("1.2.3", ("x86_64",))["ktor-client-scion-testing-android"]
        self.assertEqual(
            files["ktor-client-scion-testing-android-1.2.3.aar"],
            ["jni/x86_64/libktor_scion_testing.so"],
        )


def write_publication(repository: Path, version: str) -> None:
    """Writes a complete release publication with placeholder content."""
    pom = "".join(f"<{element}>x</{element}>" for element in ktor.POM_ELEMENTS)
    for artifact, files in ktor.expected_files(version).items():
        directory = repository / ktor.GROUP_PATH / artifact / version
        directory.mkdir(parents=True)
        for name, entries in files.items():
            path = directory / name
            if name.endswith(".pom"):
                path.write_text(pom)
            elif name.endswith((".jar", ".aar", ".klib")):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("placeholder", "x")
                    for entry in entries:
                        archive.writestr(entry, "x")
            else:
                path.write_text("x")
            path.with_name(name + ".sha1").write_text("x")
        (directory.parent / "maven-metadata.xml").write_text("x")


class VerifyPublication(unittest.TestCase):
    def setUp(self):
        self.repository = Path(self.enterContext(tempfile.TemporaryDirectory()))
        write_publication(self.repository, "1.2.3")

    def verify(self, version="1.2.3"):
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            try:
                ktor.verify_publication(self.repository, version)
            except ktor.Failure as failure:
                return f"{failure}\n{stderr.getvalue()}"
        return None

    def jar(self, artifact):
        return self.repository / ktor.GROUP_PATH / artifact / "1.2.3" / f"{artifact}-1.2.3.jar"

    def test_passes_a_complete_publication(self):
        self.assertIsNone(self.verify())

    def test_names_the_versions_of_another_tree(self):
        self.assertIn("The repository has: 1.2.3", self.verify("1.2.4"))

    def test_finds_a_missing_file(self):
        self.jar("ktor-client-scion").unlink()
        self.assertIn("missing", self.verify())

    def test_finds_a_missing_library_in_the_jvm_jar(self):
        with zipfile.ZipFile(self.jar("ktor-client-scion-jvm"), "w") as archive:
            archive.writestr("darwin-aarch64/libktor_scion_core.dylib", "x")
        self.assertIn("has no linux-x86-64/libktor_scion_core.so", self.verify())

    def test_finds_a_pom_without_metadata(self):
        pom = (
            self.repository
            / ktor.GROUP_PATH
            / "ktor-client-scion/1.2.3/ktor-client-scion-1.2.3.pom"
        )
        pom.write_text("<name>x</name>")
        self.assertIn("has no <scm>", self.verify())

    def test_finds_a_target_outside_the_release(self):
        (self.repository / ktor.GROUP_PATH / "ktor-client-scion-linuxx64/1.2.3").mkdir(parents=True)
        self.assertIn("unexpected artifact ktor-client-scion-linuxx64", self.verify())


class FilesToSign(unittest.TestCase):
    def test_skips_checksums_and_maven_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a.jar", "a.jar.md5", "a.jar.sha512", "a.pom", "maven-metadata.xml.sha1"):
                (root / name).write_text("x")
            self.assertEqual([path.name for path in ktor.files_to_sign(root)], ["a.jar", "a.pom"])


class DeploymentFinished(unittest.TestCase):
    def test_user_managed_ends_at_the_validation(self):
        self.assertTrue(ktor.deployment_finished("VALIDATED", "USER_MANAGED"))

    def test_automatic_waits_for_the_publication(self):
        self.assertFalse(ktor.deployment_finished("VALIDATED", "AUTOMATIC"))
        self.assertTrue(ktor.deployment_finished("PUBLISHING", "AUTOMATIC"))

    def test_waits_during_the_validation(self):
        for state in ("PENDING", "VALIDATING"):
            self.assertFalse(ktor.deployment_finished(state, "USER_MANAGED"))

    def test_raises_on_a_rejected_deployment(self):
        with self.assertRaises(ktor.Failure):
            ktor.deployment_finished("FAILED", "AUTOMATIC")


@unittest.skipUnless(shutil.which("gpg"), "gpg is not installed")
class Bundle(unittest.TestCase):
    def test_signs_every_file_and_leaves_out_maven_metadata(self):
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        repository = work / "repository"
        write_publication(repository, "1.2.3")

        gnupg = work / "gnupg"
        gnupg.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(gnupg)}
        gpg = ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", "secret"]
        subprocess.run(
            [*gpg, "--quick-gen-key", "Test <test@example.invalid>", "ed25519", "sign", "1d"],
            env=env,
            check=True,
        )
        key = subprocess.run(
            [*gpg, "--armor", "--export-secret-keys"],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        ).stdout

        out = work / "bundle.zip"
        variables = {"SIGNING_KEY": key, "SIGNING_KEY_PASSWORD": "secret"}
        with mock.patch.dict(os.environ, variables), contextlib.redirect_stdout(io.StringIO()):
            ktor.bundle(repository, out)

        with zipfile.ZipFile(out) as archive:
            names = set(archive.namelist())
        signed = [name for name in names if not name.endswith((".asc", *ktor.CHECKSUM_SUFFIXES))]
        self.assertTrue(signed)
        self.assertTrue(all(name.startswith("net/anapaya/scion/") for name in names))
        self.assertFalse([name for name in signed if f"{name}.asc" not in names])
        self.assertFalse([name for name in names if "maven-metadata" in name])

    def test_needs_the_key(self):
        with mock.patch.dict(os.environ, {"SIGNING_KEY": ""}), self.assertRaises(ktor.Failure):
            ktor.bundle(Path("."), Path("bundle.zip"))


if __name__ == "__main__":
    unittest.main()
