#!/usr/bin/env python3
# Copyright 2026 Anapaya Systems
"""Build and check the SCION HTTP/3 static libraries for Apple platforms.

Four subcommands:

    build               cross-compile scion-http3-ffi as a static library for each Rust target
    verify              check the staged static libraries
    xcframework         fuse the fat slices, generate the bindings, assemble the XCFramework
                        into the Swift package, and check it
    verify-xcframework  check an assembled XCFramework, and the package manifest against it

Everything here needs macOS with Xcode. See ../README.md for prerequisites and troubleshooting.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
APPLE_DIR = TOOLS_DIR.parent
WORKSPACE_ROOT = APPLE_DIR.parent.parent

GENERATED_DIR = APPLE_DIR / "generated"
# One directory per Rust target, each holding the staged library and the manifest that records how
# it was built.
LIBS_DIR = GENERATED_DIR / "libs"
# One directory per XCFramework slice, holding the fused library.
SLICES_DIR = GENERATED_DIR / "slices"
# What uniffi-bindgen writes: the Swift source, the C header and the module map.
BINDINGS_DIR = GENERATED_DIR / "bindings"
# The header directory every slice carries.
HEADERS_DIR = GENERATED_DIR / "headers"

PACKAGE_DIR = APPLE_DIR / "scion-http3-swift"
PACKAGE_MANIFEST = PACKAGE_DIR / "Package.swift"
GENERATED_SWIFT_DIR = PACKAGE_DIR / "Sources" / "ScionHTTP3Uniffi"

CARGO_PACKAGE = "scion-http3-ffi"
CARGO_PROFILE = "mobile"
LIBRARY = "libscion_http3_ffi.a"
MANIFEST_NAME = "build-manifest.json"

UNIFFI_CONFIG = WORKSPACE_ROOT / "crates/libs/scion-http3-ffi/uniffi.toml"

# The version handshake uniffi's scaffolding exports.
EXPORTED_SYMBOL = "ffi_scion_http3_ffi_uniffi_contract_version"
# Mach-O symbol names carry a leading underscore.
EXPORTED_SYMBOL_MACHO = f"_{EXPORTED_SYMBOL}"


@dataclass(frozen=True)
class Platform:
    """An Apple platform."""

    name: str
    # The deployment target every slice of this platform is built for.
    deployment_target: str
    # The variable rustc and cc-rs both read to get the deployment target.
    deployment_env: str
    # `SupportedPlatform` and `SupportedPlatformVariant` in the XCFramework's Info.plist.
    xcframework_platform: str
    xcframework_variant: str | None
    # The platform in `LC_BUILD_VERSION`.
    macho_platform: str


IOS = Platform(
    name="ios",
    deployment_target="15.0",
    deployment_env="IPHONEOS_DEPLOYMENT_TARGET",
    xcframework_platform="ios",
    xcframework_variant=None,
    macho_platform="IOS",
)
IOS_SIMULATOR = Platform(
    name="ios-simulator",
    deployment_target="15.0",
    deployment_env="IPHONEOS_DEPLOYMENT_TARGET",
    xcframework_platform="ios",
    xcframework_variant="simulator",
    macho_platform="IOSSIMULATOR",
)
MACOS = Platform(
    name="macos",
    deployment_target="12.0",
    deployment_env="MACOSX_DEPLOYMENT_TARGET",
    xcframework_platform="macos",
    xcframework_variant=None,
    macho_platform="MACOS",
)

PLATFORMS = (IOS, IOS_SIMULATOR, MACOS)

# Every deployment-target variable that has to be out of the way while a slice is built. Only the
# one belonging to the slice is set and the other is removed, because cmake reads
# MACOSX_DEPLOYMENT_TARGET whatever platform it is configured for.
DEPLOYMENT_TARGET_VARS = frozenset(platform.deployment_env for platform in PLATFORMS)


@dataclass(frozen=True)
class Target:
    """A Rust target."""

    triple: str
    arch: str
    platform: Platform


TARGETS: dict[str, Target] = {
    "aarch64-apple-ios": Target("aarch64-apple-ios", "arm64", IOS),
    "aarch64-apple-ios-sim": Target("aarch64-apple-ios-sim", "arm64", IOS_SIMULATOR),
    "x86_64-apple-ios": Target("x86_64-apple-ios", "x86_64", IOS_SIMULATOR),
    "aarch64-apple-darwin": Target("aarch64-apple-darwin", "arm64", MACOS),
    "x86_64-apple-darwin": Target("x86_64-apple-darwin", "x86_64", MACOS),
}


@dataclass(frozen=True)
class Slice:
    """One slice of the XCFramework."""

    # The slice directory, and the `LibraryIdentifier` xcodebuild writes into Info.plist.
    identifier: str
    platform: Platform
    triples: tuple[str, ...]

    @property
    def targets(self) -> tuple[Target, ...]:
        return tuple(TARGETS[triple] for triple in self.triples)

    @property
    def archs(self) -> tuple[str, ...]:
        return tuple(target.arch for target in self.targets)


SLICES: tuple[Slice, ...] = (
    Slice("ios-arm64", IOS, ("aarch64-apple-ios",)),
    Slice(
        "ios-arm64_x86_64-simulator",
        IOS_SIMULATOR,
        ("aarch64-apple-ios-sim", "x86_64-apple-ios"),
    ),
    Slice("macos-arm64_x86_64", MACOS, ("aarch64-apple-darwin", "x86_64-apple-darwin")),
)

# Named after the C module uniffi generates, which is what `Package.swift` declares its
# `binaryTarget` as. Gitignored there.
XCFRAMEWORK = PACKAGE_DIR / "ScionHTTP3UniffiFFI.xcframework"

# Xcode reads a static library's module map from this name inside the slice's header directory,
# whatever uniffi called the file.
MODULE_MAP = "module.modulemap"


class Failure(Exception):
    """A condition the caller has to fix."""


def require_macos() -> None:
    """Refuses hosts that cannot cross-compile for Apple platforms."""
    if sys.platform != "darwin":
        raise Failure(f"this runs on macOS with Xcode only, not on {sys.platform}.")


MAX_REPORTED_LINES = 200


def reported_output(text: str) -> str:
    """A tool's output, indented for a report, with the middle dropped if it runs very long."""
    lines = text.strip().splitlines() or ["<no output>"]
    if len(lines) > MAX_REPORTED_LINES:
        half = MAX_REPORTED_LINES // 2
        omitted = len(lines) - 2 * half
        lines = lines[:half] + [f"... {omitted} line(s) omitted ..."] + lines[-half:]
    return "\n".join(f"      {line}" for line in lines)


def xcrun(*args: object) -> str:
    """Runs a tool from the selected Xcode, and returns its stdout. Raises Failure on error."""
    command = ["xcrun", *(str(a) for a in args)]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise Failure(
            f"{command[1]} exited {result.returncode}. The command was:\n"
            f"      {' '.join(command)}\n" + reported_output(result.stderr or result.stdout or "")
        )
    return result.stdout


@functools.cache
def cargo_target_dir() -> Path:
    """Where cargo puts build output, according to cargo."""
    metadata = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        check=True,
        capture_output=True,
        text=True,
        cwd=WORKSPACE_ROOT,
    ).stdout
    return Path(json.loads(metadata)["target_directory"])


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version_tuple(version: str) -> tuple[int, ...]:
    """A dotted version as numbers, so that 15.0 and 9.0 compare the way they read."""
    return tuple(int(part) for part in version.split(".") if part.isdigit())


def check_environment() -> None:
    """Refuses environments that would silently produce a wrong-platform BoringSSL"""
    for name in ("CMAKE_TOOLCHAIN_FILE", "TARGET_CMAKE_TOOLCHAIN_FILE"):
        if name in os.environ:
            raise Failure(
                f"{name} is set. boring-sys then skips its own CMAKE_OSX_ARCHITECTURES and\n"
                "      CMAKE_OSX_SYSROOT defines and builds BoringSSL for the host. Unset it and\n"
                "      re-run."
            )
    if "SDKROOT" in os.environ:
        raise Failure(
            "SDKROOT is set. clang and cmake both fall back to it, so it can override the SDK a\n"
            "      slice is supposed to be built against. Unset it and re-run."
        )


def cross_compile_env(target: Target) -> dict[str, str]:
    """The environment a build of this target needs, and nothing else."""
    env = dict(os.environ)

    for name in DEPLOYMENT_TARGET_VARS:
        env.pop(name, None)
    env[target.platform.deployment_env] = target.platform.deployment_target

    for base in ("CFLAGS", "CXXFLAGS"):
        underscored = target.triple.replace("-", "_")
        for name in (base, f"TARGET_{base}", f"{base}_{target.triple}", f"{base}_{underscored}"):
            env.pop(name, None)

    return env


def installed_rust_targets() -> set[str]:
    output = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return set(output.split())


# rustc prints this note when it is asked what a static library has to be linked against.
NATIVE_STATIC_LIBS = re.compile(r"native-static-libs:\s*(.*)")

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def native_static_libs(rustc_output: str) -> list[str] | None:
    """The link flags rustc reported, or None if it reported none.

    The last note wins, because one invocation can link more than one crate type.
    """
    matches = NATIVE_STATIC_LIBS.findall(ANSI_ESCAPE.sub("", rustc_output))
    if not matches:
        return None
    return checked_link_flags(matches[-1].split(), "rustc's note")


def checked_link_flags(flags: list[str], source: str) -> list[str]:
    """Refuses link flags carrying a control character, and says where they came from."""
    unprintable = [flag for flag in flags if not flag.isprintable()]
    if unprintable:
        raise Failure(
            f"{source} holds {len(unprintable)} link flag(s) with a control character in them: "
            f"{', '.join(repr(flag) for flag in unprintable)}.\n"
            "      Colour is the usual source. A manifest written before that was handled keeps\n"
            "      the flags it recorded, so build the target again."
        )
    return flags


def cross_compile(target: Target) -> list[str] | None:
    """Builds the static library for one target, and returns what it has to be linked against."""
    command = [
        "cargo",
        "rustc",
        "--locked",
        "--lib",
        "--crate-type",
        "staticlib",
        "-p",
        CARGO_PACKAGE,
        "--profile",
        CARGO_PROFILE,
        "--target",
        target.triple,
        "--",
        "--print",
        "native-static-libs",
    ]
    process = subprocess.Popen(
        command,
        cwd=WORKSPACE_ROOT,
        env=cross_compile_env(target),
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stderr is not None
    captured = []
    for line in process.stderr:
        sys.stderr.write(line)
        captured.append(line)
    if process.wait() != 0:
        raise subprocess.CalledProcessError(process.returncode, command)

    return native_static_libs("".join(captured))


def recorded_link_flags(target: Target) -> list[str] | None:
    """The link flags the last build of this target recorded, if there was one."""
    manifest_path = staged_manifest(target)
    if not manifest_path.is_file():
        return None
    return json.loads(manifest_path.read_text()).get("link_flags") or None


def staged_library(target: Target) -> Path:
    return LIBS_DIR / target.triple / LIBRARY


def staged_manifest(target: Target) -> Path:
    return LIBS_DIR / target.triple / MANIFEST_NAME


def build(targets: list[Target], skip_verify: bool) -> None:
    require_macos()
    check_environment()
    installed = installed_rust_targets()

    print(f"Using   {xcrun('xcodebuild', '-version').strip().splitlines()[0]}")
    print(f"        the {CARGO_PROFILE} cargo profile")

    for target in targets:
        if target.triple not in installed:
            raise Failure(
                f"the Rust standard library for {target.triple} is missing. Run:\n"
                f"    rustup target add {target.triple}"
            )

        deployment = target.platform.deployment_target
        print(f"==> Building {LIBRARY} for {target.triple} ({target.platform.name} {deployment})")
        # Read before the build overwrites it, so that a build with nothing to do keeps the answer
        # rustc gave the last time it linked.
        previous = recorded_link_flags(target)
        link_flags = cross_compile(target) or previous
        if link_flags is None:
            raise Failure(
                "rustc reported nothing to link the library against, and no earlier build did\n"
                "      either. Delete the staged library and build again."
            )

        built = cargo_target_dir() / target.triple / CARGO_PROFILE / LIBRARY
        if not built.is_file():
            raise Failure(f"cargo reported success but {built} does not exist")

        staged = staged_library(target)
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, staged)
        xcrun("strip", "-S", "-x", staged)

        staged_manifest(target).write_text(
            json.dumps(
                {
                    "triple": target.triple,
                    "arch": target.arch,
                    "platform": target.platform.name,
                    "deployment_target": deployment,
                    "profile": CARGO_PROFILE,
                    "library": LIBRARY,
                    "link_flags": link_flags,
                    "sha256": sha256_of(staged),
                    "size": staged.stat().st_size,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        print(f"    {staged.stat().st_size} bytes stripped, from {built.stat().st_size}")

    if not skip_verify:
        verify(targets)


class Report:
    """Collects check results so that every target is reported before failing."""

    def __init__(self) -> None:
        self.failures = 0
        self.skipped: list[str] = []

    def ok(self, message: str) -> None:
        print(f"  ok    {message}")

    def skip(self, what: str, why: str) -> None:
        """Records a check that did not run, so the summary cannot claim it passed."""
        self.skipped.append(what)
        print(f"  skip  {what}: {why}", file=sys.stderr)

    def fail(self, message: str) -> None:
        print(f"  FAIL  {message}", file=sys.stderr)
        self.failures += 1


MACHO_PLATFORM_NAMES = {"1": "MACOS", "2": "IOS", "7": "IOSSIMULATOR"}

IOS_FAMILY = "IOS or IOSSIMULATOR"

VERSION_MIN_PLATFORMS = {
    "LC_VERSION_MIN_MACOSX": "MACOS",
    "LC_VERSION_MIN_IPHONEOS": IOS_FAMILY,
}

ACCEPTED_MACHO_PLATFORMS = {
    "IOS": frozenset({"IOS", IOS_FAMILY}),
    "IOSSIMULATOR": frozenset({"IOSSIMULATOR", IOS_FAMILY}),
    "MACOS": frozenset({"MACOS"}),
}


def macho_platform_name(token: str) -> str:
    """What otool's platform field means, whether it printed the name or the number."""
    if not token.isdigit():
        return token.upper()
    return MACHO_PLATFORM_NAMES.get(token, f"platform {token}")


LOAD_COMMAND = re.compile(r"^\s*cmd (LC_\w+)")
LOAD_COMMAND_FIELD = re.compile(r"^\s*(platform|minos|version) (\S+)")


def build_versions(otool_output: str) -> dict[tuple[str, str], int]:
    """The platform and minimum OS version of each object in `otool -l` output."""
    counts: dict[tuple[str, str], int] = {}
    state: dict[str, str] = {}

    def flush() -> None:
        command = state.pop("cmd", "")
        platform = state.pop("platform", "")
        minos = state.pop("minos", "")
        version = state.pop("version", "")
        state.clear()
        if command == "LC_BUILD_VERSION" and platform and minos:
            key = (macho_platform_name(platform), minos)
        elif command in VERSION_MIN_PLATFORMS and version:
            key = (VERSION_MIN_PLATFORMS[command], version)
        else:
            return
        counts[key] = counts.get(key, 0) + 1

    for line in otool_output.splitlines():
        match = LOAD_COMMAND.match(line)
        if match:
            flush()
            state["cmd"] = match.group(1)
            continue
        match = LOAD_COMMAND_FIELD.match(line)
        if match and "cmd" in state:
            state[match.group(1)] = match.group(2)
    flush()
    return counts


def defined_symbols(nm_output: str) -> set[str]:
    """The symbols `nm` reports as defined, from its default output."""
    symbols = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        kind, name = fields[-2], fields[-1]
        if len(kind) == 1 and kind not in "Uu":
            symbols.add(name)
    return symbols


def defined_symbols_of(library: Path, arch: str) -> set[str]:
    """The symbols one architecture of a static library defines."""
    result = subprocess.run(
        ["xcrun", "nm", "-arch", arch, str(library)],
        check=False,
        capture_output=True,
        text=True,
    )
    if not result.stdout.strip():
        raise Failure("nm listed no symbol at all:\n" + reported_output(result.stderr or ""))
    return defined_symbols(result.stdout)


def highest_version(versions: dict[tuple[str, str], int]) -> str:
    """The newest OS any object needs, from what `build_versions` found."""
    return max((version for _, version in versions), key=version_tuple)


def check_objects(report: Report, library: Path, arch: str, platform: Platform) -> None:
    """Checks the objects of one architecture: their platform, their minimum, and their symbols."""
    try:
        versions = build_versions(xcrun("otool", "-arch", arch, "-l", library))
        symbols = defined_symbols_of(library, arch)
    except Failure as failure:
        report.fail(f"{library} cannot be read for {arch}: {failure}")
        return

    if not versions:
        report.fail(
            f"no {arch} object in {library} carries a platform load command, so the platform and\n"
            "      the minimum OS version cannot be checked."
        )
    else:
        expected = platform.macho_platform
        accepted = ACCEPTED_MACHO_PLATFORMS[expected]
        wrong = sorted({found for found, _ in versions if found not in accepted})
        if wrong:
            report.fail(
                f"{library} holds {arch} objects for {' '.join(wrong)}, not only {expected}.\n"
                "      Part of it was built against the wrong SDK."
            )
        else:
            report.ok(f"every {arch} object is {expected}")

        target = platform.deployment_target
        highest = highest_version(versions)
        if version_tuple(highest) == version_tuple(target):
            report.ok(f"no {arch} object needs more than {platform.name} {target}, one needs it")
        elif version_tuple(highest) > version_tuple(target):
            report.fail(
                f"{library} holds an {arch} object built for {platform.name} {highest}, above the\n"
                f"      {target} this slice promises. An application whose deployment target is\n"
                f"      {target} cannot link it."
            )
        else:
            report.fail(
                f"no {arch} object in {library} needs more than {platform.name} {highest}, below\n"
                f"      the {target} this slice is built for, so {platform.deployment_env} did\n"
                "      not reach the compiler."
            )

    if EXPORTED_SYMBOL_MACHO in symbols:
        report.ok(f"the {arch} objects define {EXPORTED_SYMBOL}")
    else:
        report.fail(
            f"{library} does not define {EXPORTED_SYMBOL} for {arch}; LTO or strip removed it,\n"
            "      and the generated Swift calls it before anything else."
        )


def check_archs(report: Report, library: Path, archs: tuple[str, ...]) -> None:
    found = xcrun("lipo", "-archs", library).split()
    if sorted(found) == sorted(archs):
        report.ok(f"holds exactly {' '.join(sorted(archs))}")
    else:
        report.fail(
            f"{library} holds {' '.join(found) or 'no architecture'}, not {' '.join(sorted(archs))}"
        )


def check_staged_set(report: Report) -> None:
    """Checks that nothing unrecognised is staged."""
    print("==> staged libraries")
    if not LIBS_DIR.is_dir():
        report.fail(f"{LIBS_DIR} does not exist. Build the libraries first.")
        return
    unknown = sorted(p.name for p in LIBS_DIR.iterdir() if p.is_dir() and p.name not in TARGETS)
    if unknown:
        report.fail(
            f"unrecognised target director{'y' if len(unknown) == 1 else 'ies'} in {LIBS_DIR}: "
            f"{' '.join(unknown)}.\n"
            "      They would be fused into the XCFramework without being checked."
        )
    else:
        report.ok("no unrecognised target directories")


def check_target(report: Report, target: Target) -> None:
    print(f"==> {target.triple}")
    library = staged_library(target)
    if not library.is_file():
        report.fail(f"{library} does not exist. Build it first.")
        return

    manifest_path = staged_manifest(target)
    if not manifest_path.is_file():
        report.skip(
            f"provenance ({target.triple})",
            f"no {MANIFEST_NAME}; the library was not built here",
        )
    else:
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("sha256") != sha256_of(library):
            report.fail(
                f"{library} does not match the hash {MANIFEST_NAME} recorded for it, so it is\n"
                "      stale. Run a full build."
            )
        elif manifest.get("deployment_target") != target.platform.deployment_target:
            report.fail(
                f"{library} was built for {target.platform.name} "
                f"{manifest.get('deployment_target')}, but this tool now asks for "
                f"{target.platform.deployment_target}.\n"
                "      Run a full build."
            )
        else:
            report.ok("is the library this build produced")

    check_archs(report, library, (target.arch,))
    check_objects(report, library, target.arch, target.platform)


def summarise(report: Report, what: str) -> None:
    print()
    if report.failures:
        raise Failure(f"{report.failures} check(s) failed")
    summary = f"All checks passed for {what}"
    if report.skipped:
        summary += f"\n{len(report.skipped)} check(s) skipped: {', '.join(report.skipped)}"
    print(summary)


def verify(targets: list[Target]) -> None:
    """Checks the staged static libraries."""
    require_macos()
    report = Report()
    check_staged_set(report)
    for target in targets:
        check_target(report, target)
    summarise(report, " ".join(target.triple for target in targets))


def fuse_slices() -> None:
    """Fuses the staged libraries into one archive per XCFramework slice."""
    for entry in SLICES:
        libraries = [staged_library(target) for target in entry.targets]
        missing = [str(library) for library in libraries if not library.is_file()]
        if missing:
            raise Failure(
                f"the {entry.identifier} slice needs {' and '.join(missing)}.\n"
                "      Build every target first."
            )
        output = SLICES_DIR / entry.identifier / LIBRARY
        output.parent.mkdir(parents=True, exist_ok=True)
        output.unlink(missing_ok=True)
        print(f"==> {entry.identifier} from {' '.join(entry.archs)}")
        if len(libraries) == 1:
            shutil.copy2(libraries[0], output)
        else:
            xcrun("lipo", "-create", *libraries, "-output", output)


def generate_bindings() -> tuple[Path, Path]:
    """Generates the Swift bindings and returns the header and module map the slices carry."""
    library = next(
        (staged_library(target) for target in TARGETS.values() if staged_library(target).is_file()),
        None,
    )
    if library is None:
        raise Failure(f"no staged library under {LIBS_DIR}. Build one first.")

    if BINDINGS_DIR.exists():
        shutil.rmtree(BINDINGS_DIR)
    BINDINGS_DIR.mkdir(parents=True)

    print(f"==> Generating the bindings from {library}")
    subprocess.run(
        [
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
            "swift",
            "--library",
            str(library),
            "--out-dir",
            str(BINDINGS_DIR),
            "--no-format",
        ],
        check=True,
        cwd=WORKSPACE_ROOT,
    )

    sources = sorted(BINDINGS_DIR.glob("*.swift"))
    headers = sorted(BINDINGS_DIR.glob("*.h"))
    module_maps = sorted(BINDINGS_DIR.glob("*.modulemap"))
    if len(sources) != 1 or len(headers) != 1 or len(module_maps) != 1:
        raise Failure(
            f"expected one .swift, one .h and one .modulemap in {BINDINGS_DIR}, found "
            f"{len(sources)}, {len(headers)} and {len(module_maps)}.\n"
            "      The library exports no UniFFI metadata, or the [bindings.swift] section in\n"
            f"      {UNIFFI_CONFIG} changed."
        )

    if GENERATED_SWIFT_DIR.exists():
        shutil.rmtree(GENERATED_SWIFT_DIR)
    GENERATED_SWIFT_DIR.mkdir(parents=True)
    source = GENERATED_SWIFT_DIR / sources[0].name
    shutil.copy2(sources[0], source)
    print(f"    {source.relative_to(APPLE_DIR)}")

    if HEADERS_DIR.exists():
        shutil.rmtree(HEADERS_DIR)
    HEADERS_DIR.mkdir(parents=True)
    header = HEADERS_DIR / headers[0].name
    shutil.copy2(headers[0], header)
    module_map = HEADERS_DIR / MODULE_MAP
    shutil.copy2(module_maps[0], module_map)
    print(f"    {header.name} and {module_map.name}")
    return header, module_map


MODULE_DECLARATION = re.compile(r"^\s*(?:framework\s+)?module\s+(\w+)", re.MULTILINE)


def module_name(module_map: str) -> str | None:
    """The module a module map declares, which is the name Swift imports."""
    match = MODULE_DECLARATION.search(module_map)
    return match.group(1) if match else None


# `.iOS(.v15)` or `.macOS(.v12_4)` in the `platforms:` list of Package.swift.
PLATFORM_DECLARATION = re.compile(r"\.(iOS|macOS)\(\s*\.v(\d+)(?:_(\d+))?\s*\)")

# A `binaryTarget` with a local path, as the manifest declares between releases.
BINARY_TARGET = re.compile(r'\.binaryTarget\(\s*name:\s*"([^"]+)"\s*,\s*path:\s*"([^"]+)"')


def declared_platforms(manifest: str) -> dict[str, str]:
    """The minimum OS version Package.swift declares per platform, keyed like the XCFramework."""
    found = {}
    for match in PLATFORM_DECLARATION.finditer(manifest):
        name, major, minor = match.groups()
        found[name.lower()] = f"{major}.{minor or 0}"
    return found


def declared_binary_target(manifest: str) -> tuple[str, str] | None:
    """The name and the local path of the binary target Package.swift declares, if any."""
    match = BINARY_TARGET.search(manifest)
    return (match.group(1), match.group(2)) if match else None


def check_manifest(report: Report, manifest: str, module: str | None) -> None:
    """Checks what Package.swift and this tool have to agree on.

    `module` is what the module map in the XCFramework declares, or None if no slice could be
    read.
    """
    print(f"==> {PACKAGE_MANIFEST.name}")
    declared = declared_platforms(manifest)
    expected = {platform.xcframework_platform: platform.deployment_target for platform in PLATFORMS}
    for name, floor in sorted(expected.items()):
        found = declared.get(name)
        if found is None:
            report.fail(
                f"{PACKAGE_MANIFEST} declares no {name} platform, so SwiftPM assumes its own\n"
                f"      default rather than the {floor} the slices are built for."
            )
        elif version_tuple(found) == version_tuple(floor):
            report.ok(f"declares {name} {found}, what the slices are built for")
        else:
            report.fail(
                f"{PACKAGE_MANIFEST} declares {name} {found}, but the slices are built for\n"
                f"      {floor}. Change both together: an application in between would either\n"
                "      link a library that cannot run there, or be refused one that could."
            )

    binary = declared_binary_target(manifest)
    if binary is None:
        report.fail(f"{PACKAGE_MANIFEST} declares no binaryTarget with a local path")
        return
    name, path = binary
    if module is not None and name != module:
        report.fail(
            f'{PACKAGE_MANIFEST} names the binary target "{name}", but the module map declares\n'
            f"      {module}, which is what the generated Swift imports."
        )
    elif path != XCFRAMEWORK.name:
        report.fail(
            f'{PACKAGE_MANIFEST} takes the binary target from "{path}", but this tool writes\n'
            f"      {XCFRAMEWORK.name}."
        )
    else:
        report.ok(f"takes {name} from {path}")


def xcframework(output: Path) -> None:
    """Assembles the XCFramework, and checks the result."""
    require_macos()
    fuse_slices()
    generate_bindings()

    if output.exists():
        shutil.rmtree(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    command = ["xcodebuild", "-create-xcframework"]
    for entry in SLICES:
        command += ["-library", str(SLICES_DIR / entry.identifier / LIBRARY)]
        command += ["-headers", str(HEADERS_DIR)]
    command += ["-output", str(output)]
    print(f"==> Assembling {output.name}")
    subprocess.run(command, check=True)

    verify_xcframework(output)


def check_xcframework_plist(report: Report, output: Path) -> dict[str, dict[str, object]]:
    """Checks Info.plist against the slice list this tool builds, and returns its entries."""
    print("==> Info.plist")
    plist_path = output / "Info.plist"
    if not plist_path.is_file():
        report.fail(f"{plist_path} does not exist, so this is not an XCFramework")
        return {}

    plist = plistlib.loads(plist_path.read_bytes())
    package_type = plist.get("CFBundlePackageType")
    if package_type != "XFWK":
        report.fail(f"{plist_path} says CFBundlePackageType {package_type!r}, not 'XFWK'")

    entries = plist.get("AvailableLibraries") or []
    found = sorted(str(entry.get("LibraryIdentifier")) for entry in entries)
    expected = sorted(entry.identifier for entry in SLICES)
    if found == expected:
        report.ok(f"carries exactly {' '.join(expected)}")
    else:
        report.fail(
            f"the slice list is {' '.join(found) or '<empty>'}, not {' '.join(expected)}.\n"
            "      An application cannot link a platform that is not there, and a slice nothing\n"
            "      declared shipped without being checked."
        )
    return {str(entry.get("LibraryIdentifier")): entry for entry in entries}


def check_xcframework_slice(
    report: Report,
    output: Path,
    entry: Slice,
    plist_entry: dict[str, object] | None,
) -> tuple[str, str | None] | None:
    """Checks one slice, and returns the header it carries and the module that header is."""
    print(f"==> {entry.identifier}")
    platform = entry.platform

    if plist_entry is None:
        report.fail(f"Info.plist has no entry for {entry.identifier}")
    else:
        archs = sorted(str(arch) for arch in plist_entry.get("SupportedArchitectures") or [])
        if archs == sorted(entry.archs):
            report.ok(f"Info.plist says {' '.join(archs)}")
        else:
            report.fail(
                f"Info.plist says {' '.join(archs) or '<none>'} for {entry.identifier}, not "
                f"{' '.join(sorted(entry.archs))}"
            )
        declared = (
            plist_entry.get("SupportedPlatform"),
            plist_entry.get("SupportedPlatformVariant"),
        )
        wanted = (platform.xcframework_platform, platform.xcframework_variant)
        if declared == wanted:
            report.ok(f"Info.plist says platform {declared[0]}, variant {declared[1]}")
        else:
            report.fail(
                f"Info.plist says platform {declared[0]!r} and variant {declared[1]!r} for "
                f"{entry.identifier},\n"
                f"      not {wanted[0]!r} and {wanted[1]!r}. Xcode picks a slice by those two, so\n"
                "      it would choose the wrong one."
            )

    library = output / entry.identifier / LIBRARY
    if not library.is_file():
        report.fail(f"{library} does not exist")
        return None

    check_archs(report, library, entry.archs)
    for arch in entry.archs:
        check_objects(report, library, arch, platform)

    headers = output / entry.identifier / "Headers"
    found = sorted(path.name for path in headers.glob("*.h")) if headers.is_dir() else []
    module_map = headers / MODULE_MAP
    if len(found) != 1 or not module_map.is_file():
        report.fail(
            f"{headers} holds {len(found)} header(s) and "
            f"{'a' if module_map.is_file() else 'no'} {MODULE_MAP}, not one of each.\n"
            "      Without both, the library cannot be imported and the slice ships as an\n"
            "      archive nothing can reach."
        )
        return None

    header_name = found[0]
    text = module_map.read_text()
    name = module_name(text)
    if name is None:
        report.fail(f"{module_map} declares no module")
    elif header_name not in text:
        report.fail(f"{module_map} declares module {name} but does not name {header_name}")
    else:
        report.ok(f"imports as {name}, through {header_name}")
    return header_name, name


def verify_xcframework(output: Path) -> None:
    """Checks an assembled XCFramework."""
    require_macos()
    if not output.is_dir():
        raise Failure(
            f"{output} does not exist.\n"
            "      Assemble it first with `apple.py xcframework`, or pass --xcframework to check\n"
            "      one somewhere else."
        )

    print(f"Checking {output}")
    report = Report()
    entries = check_xcframework_plist(report, output)
    carried = {
        check_xcframework_slice(report, output, entry, entries.get(entry.identifier))
        for entry in SLICES
    } - {None}

    headers = {header for header, _ in carried}
    if len(headers) > 1:
        report.fail(
            f"the slices carry different headers: {', '.join(sorted(headers))}.\n"
            "      They were not generated by one run."
        )
    modules = {module for _, module in carried if module}

    if not PACKAGE_MANIFEST.is_file():
        report.fail(f"{PACKAGE_MANIFEST} does not exist")
    else:
        check_manifest(report, PACKAGE_MANIFEST.read_text(), min(modules) if modules else None)
    summarise(report, output.name)


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(
        prog="apple.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    build_parser = subcommands.add_parser("build", help="cross-compile and stage the libraries")
    build_parser.add_argument(
        "-t",
        "--target",
        action="append",
        choices=list(TARGETS),
        help="build only this Rust target (repeatable)",
    )
    build_parser.add_argument(
        "--skip-verify", action="store_true", help="do not check the result afterwards"
    )

    verify_parser = subcommands.add_parser("verify", help="check the staged libraries")
    verify_parser.add_argument(
        "-t",
        "--target",
        action="append",
        choices=list(TARGETS),
        help="check only this Rust target (repeatable)",
    )

    xcframework_parser = subcommands.add_parser(
        "xcframework", help="fuse the slices and assemble the XCFramework"
    )
    xcframework_parser.add_argument(
        "--output",
        type=Path,
        default=XCFRAMEWORK,
        help="where to write it (default: inside the Swift package, where Package.swift looks)",
    )

    verify_xcframework_parser = subcommands.add_parser(
        "verify-xcframework", help="check an assembled XCFramework"
    )
    verify_xcframework_parser.add_argument(
        "--xcframework",
        type=Path,
        default=XCFRAMEWORK,
        help="the XCFramework to check (default: the one `xcframework` assembles)",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            build([TARGETS[name] for name in args.target or TARGETS], args.skip_verify)
        elif args.command == "verify":
            verify([TARGETS[name] for name in args.target or TARGETS])
        elif args.command == "xcframework":
            xcframework(args.output)
        else:
            verify_xcframework(args.xcframework)
    except Failure as failure:
        print(f"error: {failure}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"error: {' '.join(str(a) for a in error.cmd)} failed", file=sys.stderr)
        return error.returncode or 1
    except FileNotFoundError as error:
        # cargo, rustup or xcrun is not on PATH. Reported like any other prerequisite rather than
        # as a traceback.
        print(f"error: {error.filename or error} is not installed or not on PATH", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
