#!/usr/bin/env python3
# Copyright 2026 Anapaya Systems
"""Build, check, and upload the release publication of the Ktor SCION engine.

Subcommands:

    version             print the SDK version, which is also the version of the engine
    linux-libraries     build the desktop Linux libraries for the JVM jar
    publish             build the release publication into build/repository, and check it
    verify-publication  check a release publication
    bundle              sign a publication and pack it for the Maven Central Portal
    upload              upload a bundle to the Maven Central Portal

../docs/build.md, section "Releases", describes the release.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
ENGINE_DIR = TOOLS_DIR.parent
WORKSPACE_ROOT = ENGINE_DIR.parent.parent
REPOSITORY = ENGINE_DIR / "build/repository"

GROUP_PATH = "net/anapaya/scion"
# The engine has the version of the SDK, as the Android AAR of scion-http3 has.
VERSION_CRATE = "scion-stack"
CARGO_PROFILE = "kmp"


@dataclass(frozen=True)
class Module:
    """A Gradle module of the engine, with the Rust crate in its `rust/` folder."""

    artifact: str
    crate: str

    @property
    def library(self) -> str:
        return self.crate.replace("-", "_")


MODULES = (
    Module("ktor-client-scion", "ktor-scion-core"),
    Module("ktor-client-scion-testing", "ktor-scion-testing"),
)

# The targets of a release, as Gradle names their artifacts.
TARGETS = ("android", "jvm", "iosarm64", "iossimulatorarm64")
ANDROID_ABIS = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

LINUX_TRIPLE = "x86_64-unknown-linux-gnu"
# The JNA folders of the JVM jar, with the file name pattern of the library.
JVM_LIBRARIES = {"darwin-aarch64": "lib{}.dylib", "linux-x86-64": "lib{}.so"}
# The manylinux_2_28 image of the release has this glibc.
MAX_GLIBC = (2, 28)

CHECKSUM_SUFFIXES = (".md5", ".sha1", ".sha256", ".sha512")
POM_ELEMENTS = ("name", "description", "url", "license", "developer", "scm")

CENTRAL_API = "https://central.sonatype.com/api/v1/publisher"
CENTRAL_DEPLOYMENTS = "https://central.sonatype.com/publishing/deployments"
PUBLISHING_TYPES = ("USER_MANAGED", "AUTOMATIC")


class Failure(Exception):
    """A condition that the caller must fix, reported without a traceback."""


class Report:
    """Collects check results, so that one run reports every failure."""

    def __init__(self) -> None:
        self.failures = 0

    def fail(self, message: str) -> None:
        print(f"  FAIL  {message}", file=sys.stderr)
        self.failures += 1


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+ " + " ".join(command), flush=True)
    return subprocess.run(command, check=True, **kwargs)


@functools.cache
def cargo_metadata() -> dict:
    output = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=WORKSPACE_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(output)


def sdk_version(metadata: dict) -> str:
    for package in metadata["packages"]:
        if package["name"] == VERSION_CRATE:
            return package["version"]
    raise Failure(f"the Cargo workspace has no package {VERSION_CRATE}")


# Version names of the dynamic symbols, as `objdump -T` prints them.
GLIBC_VERSION = re.compile(r"\bGLIBC_(\d+(?:\.\d+)+)\b")


def glibc_requirement(objdump_output: str) -> tuple[int, ...] | None:
    """The newest glibc version that a library needs, from `objdump -T`."""
    versions = [
        tuple(int(part) for part in match.split("."))
        for match in GLIBC_VERSION.findall(objdump_output)
    ]
    return max(versions, default=None)


def format_version(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def linux_libraries(out_dir: Path) -> None:
    """Builds the desktop Linux x86-64 libraries for the JVM jar, in their JNA folder.

    Only for the JVM jar. Gradle builds the Android libraries with the NDK, on the Mac.
    """
    target_dir = Path(cargo_metadata()["target_directory"])
    folder = out_dir / "linux-x86-64"
    folder.mkdir(parents=True, exist_ok=True)
    for module in MODULES:
        # Only the cdylib. The staticlib serves Kotlin/Native, and a release has no Linux klib.
        run(
            [
                "cargo",
                "rustc",
                "--locked",
                "--profile",
                CARGO_PROFILE,
                "--target",
                LINUX_TRIPLE,
                "-p",
                module.crate,
                "--crate-type",
                "cdylib",
            ],
            cwd=WORKSPACE_ROOT,
        )
        library = (
            target_dir
            / LINUX_TRIPLE
            / CARGO_PROFILE
            / JVM_LIBRARIES["linux-x86-64"].format(module.library)
        )
        objdump = subprocess.run(
            ["objdump", "-T", str(library)], check=True, capture_output=True, text=True
        )
        needed = glibc_requirement(objdump.stdout)
        if needed is not None and needed > MAX_GLIBC:
            raise Failure(
                f"{library.name} needs glibc {format_version(needed)},"
                f" more than {format_version(MAX_GLIBC)}"
            )
        print(f"{library.name} needs glibc {format_version(needed) if needed else '(none)'}")
        shutil.copy2(library, folder / library.name)


def expected_files(
    version: str, android_abis: tuple[str, ...] = ANDROID_ABIS
) -> dict[str, dict[str, list[str]]]:
    """The files of a release publication.

    It maps each artifact to its file names, and each file name to the archive entries that the file
    must have.
    """
    expected: dict[str, dict[str, list[str]]] = {}
    for module in MODULES:
        root = module.artifact
        expected[root] = {
            f"{root}-{version}{suffix}": []
            for suffix in (
                ".module",
                ".pom",
                ".jar",
                "-sources.jar",
                "-javadoc.jar",
                "-kotlin-tooling-metadata.json",
            )
        }
        for target in TARGETS:
            artifact = f"{module.artifact}-{target}"
            files = {
                f"{artifact}-{version}{suffix}": []
                for suffix in (".module", ".pom", "-sources.jar", "-javadoc.jar")
            }
            if target == "android":
                files[f"{artifact}-{version}.aar"] = [
                    f"jni/{abi}/lib{module.library}.so" for abi in android_abis
                ]
            elif target == "jvm":
                files[f"{artifact}-{version}.jar"] = [
                    f"{folder}/{pattern.format(module.library)}"
                    for folder, pattern in JVM_LIBRARIES.items()
                ]
            else:
                for suffix in (".klib", "-cinterop-rust.klib", "-cinterop-uniffi.klib"):
                    files[f"{artifact}-{version}{suffix}"] = []
            expected[artifact] = files
    return expected


def verify_publication(
    repository: Path, version: str, android_abis: tuple[str, ...] = ANDROID_ABIS
) -> None:
    """Checks a release publication before the upload."""
    group_dir = repository / GROUP_PATH
    root_dir = group_dir / MODULES[0].artifact
    if not (root_dir / version).is_dir():
        found = (
            sorted(path.name for path in root_dir.iterdir() if path.is_dir())
            if root_dir.is_dir()
            else []
        )
        raise Failure(
            f"there is no publication of {version}. The build reads the version from the Cargo"
            " workspace, so the tag and the tree disagree."
            f" The repository has: {', '.join(found) or 'nothing'}"
        )

    report = Report()
    expected = expected_files(version, android_abis)
    for artifact, files in expected.items():
        for name, entries in files.items():
            path = group_dir / artifact / version / name
            if not path.is_file() or path.stat().st_size == 0:
                report.fail(f"missing {path}")
                continue
            if name.endswith(".pom"):
                pom = path.read_text()
                for element in POM_ELEMENTS:
                    if f"<{element}>" not in pom:
                        report.fail(f"{path} has no <{element}>")
            if entries:
                with zipfile.ZipFile(path) as archive:
                    names = set(archive.namelist())
                for entry in entries:
                    if entry not in names:
                        report.fail(f"{path} has no {entry}")

    # A target outside the release, for example from a build without -Pscion.release=true.
    for path in sorted(group_dir.iterdir()):
        if path.is_dir() and path.name not in expected:
            report.fail(f"unexpected artifact {path.name}")

    if report.failures:
        raise Failure(f"the publication of {version} has {report.failures} error(s)")
    print(f"The publication of {version} is complete: {len(expected)} artifacts.")


def publish(
    linux_libraries_dir: Path, version: str, android_abis: tuple[str, ...] | None, verify: bool
) -> None:
    """Builds the release publication on a Mac, into build/repository."""
    shutil.rmtree(REPOSITORY, ignore_errors=True)
    command = [
        "./gradlew",
        "--no-daemon",
        "-Pscion.release=true",
        "-Pscion.jvmHostOnly=true",
        f"-Pscion.jvmPrebuiltLibraries={linux_libraries_dir.resolve()}",
    ]
    if android_abis:
        command.append(f"-Pscion.androidAbis={','.join(android_abis)}")
    command += [
        f":{module.artifact}:publishAllPublicationsToLocalBuildRepository" for module in MODULES
    ]
    run(command, cwd=ENGINE_DIR)
    if verify:
        verify_publication(REPOSITORY, version, android_abis or ANDROID_ABIS)


def files_to_sign(repository: Path) -> list[Path]:
    """Every file of the bundle that needs a signature: all except checksums and Maven metadata."""
    return sorted(
        path
        for path in repository.rglob("*")
        if path.is_file()
        and not path.name.endswith(CHECKSUM_SUFFIXES)
        and not path.name.startswith("maven-metadata.xml")
    )


def bundle(repository: Path, out: Path) -> None:
    """Signs a publication with the key in SIGNING_KEY, and packs it for the Central Portal."""
    key = os.environ.get("SIGNING_KEY")
    password = os.environ.get("SIGNING_KEY_PASSWORD")
    if not key or not password:
        raise Failure("set SIGNING_KEY and SIGNING_KEY_PASSWORD")

    with tempfile.TemporaryDirectory() as work:
        work_dir = Path(work)
        gnupg = work_dir / "gnupg"
        gnupg.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(gnupg)}
        subprocess.run(
            ["gpg", "--batch", "--quiet", "--import"], input=key, text=True, env=env, check=True
        )

        copy = work_dir / "repository"
        shutil.copytree(repository, copy)
        # Central writes its own metadata.
        for path in copy.rglob("maven-metadata.xml*"):
            path.unlink()

        files = files_to_sign(copy)
        for path in files:
            subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--yes",
                    "--quiet",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase-fd",
                    "0",
                    "--armor",
                    "--detach-sign",
                    str(path),
                ],
                input=password,
                text=True,
                env=env,
                check=True,
            )
            subprocess.run(
                ["gpg", "--batch", "--quiet", "--verify", f"{path}.asc", str(path)],
                env=env,
                check=True,
                capture_output=True,
            )
        print(f"Signed {len(files)} files.")

        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(copy.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(copy).as_posix())
    print(f"Wrote {out}")


def deployment_finished(state: str, publishing_type: str) -> bool:
    """Whether the upload is done in this deployment state. Raises on a failed deployment."""
    if state == "FAILED":
        raise Failure("Central rejected the deployment")
    if state == "VALIDATED":
        return publishing_type == "USER_MANAGED"
    # Central needs up to 30 minutes more until a published version resolves.
    return state in ("PUBLISHING", "PUBLISHED")


def upload(bundle_path: Path, name: str, publishing_type: str, timeout: int) -> None:
    """Uploads a bundle to the Central Portal, and waits for the validation.

    The token is in CENTRAL_TOKEN_USERNAME and CENTRAL_TOKEN_PASSWORD.
    """
    username = os.environ.get("CENTRAL_TOKEN_USERNAME")
    password = os.environ.get("CENTRAL_TOKEN_PASSWORD")
    if not username or not password:
        raise Failure("set CENTRAL_TOKEN_USERNAME and CENTRAL_TOKEN_PASSWORD")
    authorization = "Bearer " + b64encode(f"{username}:{password}".encode()).decode()
    query = urllib.parse.urlencode({"name": name, "publishingType": publishing_type})

    # curl, because it streams the multipart body. The token goes through stdin, so that no error
    # message and no process list shows it.
    deployment = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--config",
            "-",
            "-F",
            f"bundle=@{bundle_path}",
            f"{CENTRAL_API}/upload?{query}",
        ],
        input=f'header = "Authorization: {authorization}"\n',
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(f"Deployment {deployment}: uploaded")

    deadline = time.monotonic() + timeout
    while True:
        request = urllib.request.Request(
            f"{CENTRAL_API}/status?{urllib.parse.urlencode({'id': deployment})}",
            method="POST",
            headers={"Authorization": authorization},
        )
        with urllib.request.urlopen(request) as response:
            status = json.load(response)
        state = status.get("deploymentState", "")
        print(f"Deployment {deployment}: {state}")
        try:
            if deployment_finished(state, publishing_type):
                break
        except Failure:
            print(json.dumps(status.get("errors"), indent=2), file=sys.stderr)
            raise
        if time.monotonic() > deadline:
            raise Failure(f"Central did not finish the validation in {timeout} s")
        time.sleep(15)
    if publishing_type == "USER_MANAGED":
        print(f"Publish or drop the deployment at {CENTRAL_DEPLOYMENTS}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ktor.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("version", help="print the SDK version")

    linux_parser = subcommands.add_parser(
        "linux-libraries", help="build the desktop Linux libraries for the JVM jar"
    )
    linux_parser.add_argument("out", type=Path, help="the folder for the JNA folders")

    abi_help = "the Android ABIs of the AAR (repeatable, default: all of a release)"
    publish_parser = subcommands.add_parser(
        "publish", help="build and check the release publication"
    )
    publish_parser.add_argument(
        "--linux-libraries",
        type=Path,
        required=True,
        help="the output of the linux-libraries subcommand",
    )
    publish_parser.add_argument(
        "--version", help="the version that it must have (default: the SDK version)"
    )
    publish_parser.add_argument(
        "--android-abi", action="append", choices=ANDROID_ABIS, help=abi_help
    )
    publish_parser.add_argument(
        "--skip-verify", action="store_true", help="do not check the result"
    )

    verify_parser = subcommands.add_parser("verify-publication", help="check a release publication")
    verify_parser.add_argument("repository", type=Path)
    verify_parser.add_argument("version")
    verify_parser.add_argument(
        "--android-abi", action="append", choices=ANDROID_ABIS, help=abi_help
    )

    bundle_parser = subcommands.add_parser(
        "bundle", help="sign a publication and pack it for Central"
    )
    bundle_parser.add_argument("repository", type=Path)
    bundle_parser.add_argument("out", type=Path, help="the bundle zip")

    upload_parser = subcommands.add_parser("upload", help="upload a bundle to the Central Portal")
    upload_parser.add_argument("bundle", type=Path)
    upload_parser.add_argument("name", help="the deployment name in the Portal")
    upload_parser.add_argument("publishing_type", choices=PUBLISHING_TYPES)
    upload_parser.add_argument(
        "--timeout", type=int, default=1800, help="seconds to wait for the validation"
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "version":
            print(sdk_version(cargo_metadata()))
        elif args.command == "linux-libraries":
            linux_libraries(args.out)
        elif args.command == "publish":
            abis = tuple(args.android_abi) if args.android_abi else None
            publish(
                args.linux_libraries,
                args.version or sdk_version(cargo_metadata()),
                abis,
                not args.skip_verify,
            )
        elif args.command == "verify-publication":
            abis = tuple(args.android_abi) if args.android_abi else ANDROID_ABIS
            verify_publication(args.repository, args.version, abis)
        elif args.command == "bundle":
            bundle(args.repository, args.out.resolve())
        else:
            upload(args.bundle, args.name, args.publishing_type, args.timeout)
    except Failure as failure:
        print(f"error: {failure}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"error: {' '.join(str(a) for a in error.cmd)} failed", file=sys.stderr)
        for output in (error.stdout, error.stderr):
            if output:
                print(output, file=sys.stderr)
        return error.returncode or 1
    except FileNotFoundError as error:
        print(f"error: {error.filename or error} is not installed or not on PATH", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
