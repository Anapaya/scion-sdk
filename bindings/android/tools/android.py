#!/usr/bin/env python3
# Copyright 2026 Anapaya Systems
"""Build and check the SCION HTTP/3 native libraries for Android.

Two subcommands:

    build    cross-compile scion-http3-ffi for each ABI and stage the result
    verify   check the staged libraries, and the contracts they share with the Gradle module

See ../README.md for prerequisites and troubleshooting.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
ANDROID_DIR = TOOLS_DIR.parent
WORKSPACE_ROOT = ANDROID_DIR.parent.parent

MODULE_DIR = ANDROID_DIR / "scion-http3-android"
GRADLE_MODULE = MODULE_DIR / "build.gradle.kts"
KOTLIN_FACADE = MODULE_DIR / "src/main/kotlin/com/anapaya/scion/http3/ScionHttp3.kt"
JNI_LIBS_DIR = MODULE_DIR / "generated/jniLibs"

CARGO_PACKAGE = "scion-http3-ffi"
CARGO_PROFILE = "mobile"
LIBRARY = "libscion_http3_ffi.so"
EXPORTED_SYMBOL = "scion_http3_ffi_smoke"

# 16 KB, required for Android 15 and later on arm64.
MIN_PAGE_ALIGN = 16384

# Everything the library may link against dynamically. Anything else is either a host library that
# leaked into the cross compile or a BoringSSL linked dynamically by accident.
ALLOWED_NEEDED = frozenset({"libc.so", "libdl.so", "libm.so", "libc++_shared.so"})

NDK_VERSION_HINT = "27.0.12077973"


@dataclass(frozen=True)
class Abi:
    """An Android ABI and the several names the toolchain knows it by."""

    name: str
    triple: str
    elf_machine: str
    # armeabi-v7a is the one ABI whose Rust triple matches neither the clang driver prefix nor the
    # sysroot include directory. Every other ABI uses the triple for all three.
    clang_prefix: str | None = None
    sysroot_triple: str | None = None

    @property
    def clang(self) -> str:
        return self.clang_prefix or self.triple

    @property
    def sysroot_dir(self) -> str:
        return self.sysroot_triple or self.triple

    @property
    def env_suffix(self) -> str:
        """The form cc-rs and bindgen expect in a per-target variable name."""
        return self.triple.replace("-", "_")


# armeabi-v7a is deliberately not built. Adding it means one entry here and one in shippedAbis in
# the Gradle module.
ABIS: dict[str, Abi] = {
    "arm64-v8a": Abi("arm64-v8a", "aarch64-linux-android", "AArch64"),
    "x86_64": Abi("x86_64", "x86_64-linux-android", "X86-64"),
}


class Failure(Exception):
    """A condition the caller has to fix, reported without a traceback."""


@functools.cache
def cargo_target_dir() -> Path:
    """Where cargo puts build output, according to cargo.

    Asked rather than reconstructed: the directory can come from CARGO_TARGET_DIR, from
    `build.target-dir` in any of the `.cargo/config.toml` files cargo merges, or from the default,
    and a shared target directory is usually configured by one of the latter two.
    """
    metadata = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        check=True,
        capture_output=True,
        text=True,
        cwd=WORKSPACE_ROOT,
    ).stdout
    return Path(json.loads(metadata)["target_directory"])


# Written by `build` and read by `verify`, so that "all checks passed" means "these bytes came from
# this build" rather than "these bytes are well-formed". Without it every check is a property of the
# file and none of its provenance, so a stale library left by an earlier `--abi` run, or one copied in
# from elsewhere, would pass.
BUILD_MANIFEST = MODULE_DIR / "generated/build-manifest.json"

# Beside the staged libraries rather than under the cargo target directory, so the two are created
# and removed together. In cargo's tree a `cargo clean` would take the unstripped copies while the
# staged ones survived, after which the C++ runtime check silently downgrades to a skip; and in the
# other direction a stale copy could be checked against a freshly staged library. Still outside
# `build/`, so `gradle clean` cannot touch it, and deliberately not in `jniLibs.srcDirs`, so it
# cannot be packaged into the AAR.
UNSTRIPPED_DIR = MODULE_DIR / "generated/unstripped"


class Ndk:
    """An Android NDK installation, and the tools taken from it."""

    def __init__(self, home: Path):
        self.home = home
        toolchains = sorted((home / "toolchains/llvm/prebuilt").glob("*"))
        toolchain = next((t for t in toolchains if (t / "bin/clang").is_file()), None)
        if toolchain is None:
            raise Failure(f"no LLVM toolchain under {home}/toolchains/llvm/prebuilt")
        self.toolchain = toolchain
        self.bin = toolchain / "bin"
        self.sysroot = toolchain / "sysroot"

        # The clang builtin headers (stddef.h and friends) belonging to this NDK's clang.
        resource_includes = list((toolchain / "lib/clang").glob("*/include"))
        if not resource_includes:
            raise Failure(f"no clang resource headers under {toolchain}/lib/clang/*/include")
        # Ordered numerically, not lexically, which would rank clang 9 above 18. An NDK ships one,
        # so this only matters if that ever changes.
        self.resource_include = max(
            resource_includes,
            key=lambda path: tuple(
                int(part) for part in path.parent.name.split(".") if part.isdigit()
            ),
        )

    @classmethod
    def from_environment(cls) -> Ndk:
        """The NDK named by ANDROID_NDK_HOME.

        Required rather than searched for. boring-sys reads this variable itself and panics without
        it, so it has to be set regardless, and guessing between installations would only make it
        unclear which one a build actually used.
        """
        home = os.environ.get("ANDROID_NDK_HOME")
        if not home:
            raise Failure(
                "ANDROID_NDK_HOME is not set. Point it at an Android NDK, for example\n"
                f"    export ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/{NDK_VERSION_HINT}\n"
                f'installing it first with `sdkmanager --install "ndk;{NDK_VERSION_HINT}"` if needed.'
            )
        path = Path(home)
        if not path.is_dir():
            raise Failure(f"ANDROID_NDK_HOME points at {path}, which is not a directory")
        return cls(path)

    def tool(self, name: str) -> Path:
        path = self.bin / name
        if not path.is_file():
            raise Failure(f"{name} is missing from {self.bin}")
        return path

    def run_tool(self, name: str, *args: object) -> str:
        """Runs an inspection tool, raising if the tool itself fails.

        Counting matches in a tool's output cannot otherwise distinguish "no matches" from "the tool
        crashed and printed nothing", which would make a negative check pass on empty input.
        """
        command = [str(self.tool(name)), *(str(a) for a in args)]
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or "").strip().splitlines()
            raise Failure(
                f"{name} failed on {args[-1] if args else '<no arguments>'}"
                + (f": {detail[0]}" if detail else "")
            ) from error
        return result.stdout


def cross_compile_env(ndk: Ndk, abi: Abi) -> dict[str, str]:
    """The environment a cross compile of this ABI needs, and nothing else.

    Returned rather than exported, so that what reaches cargo is visible in one place.
    """
    env = dict(os.environ)

    # boring-sys reads this name only, does not fall back to ANDROID_NDK_ROOT, and panics without it.
    # From it, it derives CMAKE_TOOLCHAIN_FILE, ANDROID_ABI, ANDROID_STL and the API level itself,
    # which is why none of those are set here. See `check_environment`.
    env["ANDROID_NDK_HOME"] = str(ndk.home)

    clang = ndk.bin / f"{abi.clang}{android_api_level()}-clang"
    env[f"CC_{abi.env_suffix}"] = str(clang)
    env[f"CXX_{abi.env_suffix}"] = f"{clang}++"
    env[f"AR_{abi.env_suffix}"] = str(ndk.bin / "llvm-ar")
    env[f"RANLIB_{abi.env_suffix}"] = str(ndk.bin / "llvm-ranlib")
    env[f"CARGO_TARGET_{abi.triple.replace('-', '_').upper()}_LINKER"] = str(clang)

    # BoringSSL's libssl is C++, and boring-sys asks the Rust link for -lstdc++ on Android, which
    # there is a near-empty stub rather than a C++ runtime. Use the real one instead. In practice
    # this costs nothing: the NDK links libc++ statically, so every C++ symbol is resolved before
    # -lc++_shared is considered and the linker drops it, leaving a self-contained library with no
    # libc++ to ship. `verify` asserts that. The setting still matters, because without it the link
    # asks for the stub.
    env["BORING_BSSL_RUST_CPPLIB"] = "c++_shared"

    # A development environment may well point these at host libc headers, which must not reach a
    # cross compile: the NDK sysroot has its own, and mixing the two fails BoringSSL's C++ build with
    # "typedef redefinition with different types ('struct mbstate_t' vs '__mbstate_t')".
    #
    # They are removed rather than overridden, because cc-rs accumulates every form of the variable
    # onto one command line rather than letting the most specific one win, so an empty
    # CFLAGS_<target> would add nothing and change nothing.
    for base in ("CFLAGS", "CXXFLAGS"):
        for name in (base, f"TARGET_{base}", f"{base}_{abi.triple}", f"{base}_{abi.env_suffix}"):
            env.pop(name, None)

    # bindgen resolves headers through libclang, whose default include paths are a property of
    # whichever libclang is loaded rather than of --target or --sysroot. A host libclang therefore
    # searches host libc headers even though boring-sys passes the NDK sysroot. Pinning the include
    # path fixes this.
    env[f"BINDGEN_EXTRA_CLANG_ARGS_{abi.env_suffix}"] = " ".join(
        [
            "-nostdinc",
            f"-isystem {ndk.resource_include}",
            f"-isystem {ndk.sysroot}/usr/include",
            f"-isystem {ndk.sysroot}/usr/include/{abi.sysroot_dir}",
        ]
    )

    # boring-sys generates bindings for every target, so a dlopen-able libclang is needed for the host
    # build too and is normally already configured. Only fall back to the NDK's own copy when nothing
    # is.
    if not env.get("LIBCLANG_PATH"):
        for directory in ("lib", "lib64", "musl/lib"):
            candidate = ndk.toolchain / directory
            if any(candidate.glob("libclang.so*")):
                env["LIBCLANG_PATH"] = str(candidate)
                break
        else:
            print(
                "warning: LIBCLANG_PATH is unset and the NDK ships no libclang; bindgen may fail",
                file=sys.stderr,
            )

    return env


def check_environment() -> None:
    """Refuses environments that would silently produce a wrong-architecture BoringSSL.

    boring-sys returns an unconfigured cmake setup when CMAKE_TOOLCHAIN_FILE is set, skipping the
    ANDROID_ABI, ANDROID_STL and API level it would otherwise define. BoringSSL then builds for the
    NDK toolchain's default ABI instead of ours, and nothing fails until the link. It tests the
    variable for presence, so an empty value does not help; the only fix is to not set it.
    """
    for name in ("CMAKE_TOOLCHAIN_FILE", "TARGET_CMAKE_TOOLCHAIN_FILE"):
        if name in os.environ:
            raise Failure(
                f"{name} is set. boring-sys then skips its own ANDROID_ABI/ANDROID_STL/API-level\n"
                "defines and builds BoringSSL for the wrong ABI. Unset it and re-run."
            )


def installed_rust_targets() -> set[str]:
    output = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return set(output.split())


def build(abis: list[Abi], skip_verify: bool) -> None:
    check_environment()
    ndk = Ndk.from_environment()
    installed = installed_rust_targets()

    print(f"Using NDK       {ndk.home}")
    print(f"      toolchain {ndk.bin}")
    print(f"      profile   {CARGO_PROFILE}, API level {android_api_level()}")

    for abi in abis:
        if abi.triple not in installed:
            raise Failure(
                f"the Rust standard library for {abi.triple} is missing. Run:\n"
                f"    rustup target add {abi.triple}"
            )

        print(f"==> Building {LIBRARY} for {abi.name} ({abi.triple})")
        subprocess.run(
            [
                "cargo",
                "rustc",
                "--locked",
                "--lib",
                "-p",
                CARGO_PACKAGE,
                "--profile",
                CARGO_PROFILE,
                "--target",
                abi.triple,
                "--",
                "-C",
                f"link-arg=-Wl,-z,max-page-size={MIN_PAGE_ALIGN}",
            ],
            check=True,
            cwd=WORKSPACE_ROOT,
            env=cross_compile_env(ndk, abi),
        )

        built = cargo_target_dir() / abi.triple / CARGO_PROFILE / LIBRARY
        if not built.is_file():
            raise Failure(f"cargo reported success but {built} does not exist")

        unstripped = UNSTRIPPED_DIR / abi.name / LIBRARY
        unstripped.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, unstripped)

        staged_dir = JNI_LIBS_DIR / abi.name
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged = staged_dir / LIBRARY
        staged.unlink(missing_ok=True)
        (staged_dir / "libc++_shared.so").unlink(missing_ok=True)
        subprocess.run(
            [str(ndk.tool("llvm-strip")), "--strip-unneeded", "-o", str(staged), str(built)],
            check=True,
        )
        print(f"    {staged.stat().st_size} bytes stripped, unstripped in {unstripped.parent}")

    BUILD_MANIFEST.write_text(
        json.dumps(
            {
                "profile": CARGO_PROFILE,
                "api_level": android_api_level(),
                "libraries": {
                    abi.name: sha256_of(JNI_LIBS_DIR / abi.name / LIBRARY) for abi in abis
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    if not skip_verify:
        verify(abis, require_symbols=True)


class Report:
    """Collects check results so that every ABI is reported before failing."""

    def __init__(self) -> None:
        self.failures = 0
        self.skipped: list[str] = []

    def ok(self, message: str) -> None:
        print(f"  ok    {message}")

    def warn(self, message: str) -> None:
        print(f"  warn  {message}", file=sys.stderr)

    def skip(self, what: str, why: str) -> None:
        """Records a check that did not run, so the summary cannot claim it passed."""
        self.skipped.append(what)
        print(f"  skip  {what}: {why}", file=sys.stderr)

    def fail(self, message: str) -> None:
        print(f"  FAIL  {message}", file=sys.stderr)
        self.failures += 1


MIN_SDK_DECLARATION = re.compile(r"^\s*minSdk\s*=\s*(\d+)", re.MULTILINE)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@functools.cache
def android_api_level() -> int:
    """The API level to compile for, read from the Gradle module's minSdk.

    Taken from there rather than repeated here, so the two cannot disagree. Note that boring-sys pins
    BoringSSL itself to ANDROID_NATIVE_API_LEVEL=21 and offers no way to override that; anything at or
    above 21 links against its objects.
    """
    if not GRADLE_MODULE.is_file():
        raise Failure(f"{GRADLE_MODULE} does not exist, so the API level cannot be determined")
    match = MIN_SDK_DECLARATION.search(GRADLE_MODULE.read_text())
    if match is None:
        raise Failure(
            f"no `minSdk = <n>` in {GRADLE_MODULE}, so the API level cannot be determined"
        )
    return int(match.group(1))


# Anchored to the declaration, on one line, rather than to the first mention of the name: the KDoc
# above it refers to NATIVE_LIBRARY_NAME too, and a pattern that may cross newlines would start there
# and pick up whatever string literal came next.
LIBRARY_NAME_DECLARATION = re.compile(
    r'^\s*(?:public\s+)?const\s+val\s+NATIVE_LIBRARY_NAME\s*:\s*String\s*=\s*"([^"\n]*)"',
    re.MULTILINE,
)


def declared_library_name() -> str | None:
    if not KOTLIN_FACADE.is_file():
        return None
    match = LIBRARY_NAME_DECLARATION.search(KOTLIN_FACADE.read_text())
    return match.group(1) if match else None


# Undefined symbols that mean the C++ runtime was not linked in. Matching only the std:: mangling
# would miss nearly all of it: BoringSSL's use of std:: is mostly header-only templates that get
# emitted locally, whereas what actually goes missing when libc++, libc++abi or libunwind are absent
# is operator new and delete, the __cxa_ exception entry points, the unwinder, and __cxxabiv1's
# typeinfo and vtables.
CXX_RUNTIME_SYMBOL = re.compile(
    r"^(?:_ZNSt|_ZNKSt|_ZSt|_Znw|_Zna|_Zdl|_Zda|_ZTI|_ZTV|_ZTS|_Unwind_|__cxa_)"
)

# bionic's libc provides these two rather than libc++, so importing them is expected.
LIBC_PROVIDED_CXA = frozenset({"__cxa_atexit", "__cxa_finalize"})


def undefined_cxx_runtime_symbols(nm_undefined_output: str) -> list[str]:
    """The C++ runtime symbols left undefined, from `llvm-nm -u` output."""
    names = [line.split()[-1] for line in nm_undefined_output.splitlines() if line.split()]
    return [
        name for name in names if CXX_RUNTIME_SYMBOL.match(name) and name not in LIBC_PROVIDED_CXA
    ]


def check_staged_set(report: Report) -> None:
    """Checks that the staging directory holds exactly what the AAR should ship.

    The Gradle module packages every ABI directory it finds, and the checks below only ever look at
    the ABIs this tool knows about, so an unrecognised directory would ship uninspected. A stale or
    foreign library is caught by comparing against the manifest `build` writes.
    """
    print("==> staged libraries")

    unknown = sorted(p.name for p in JNI_LIBS_DIR.glob("*") if p.is_dir() and p.name not in ABIS)
    if unknown:
        report.fail(
            f"unrecognised ABI director{'y' if len(unknown) == 1 else 'ies'} in {JNI_LIBS_DIR}: "
            f"{' '.join(unknown)}.\n"
            "      Gradle would package these into the AAR without them being checked."
        )
    else:
        report.ok("no unrecognised ABI directories")

    if not BUILD_MANIFEST.is_file():
        report.skip("provenance", f"no {BUILD_MANIFEST.name}; the libraries were not built here")
        return

    manifest = json.loads(BUILD_MANIFEST.read_text())
    recorded = manifest.get("libraries", {})
    for abi in ABIS.values():
        library = JNI_LIBS_DIR / abi.name / LIBRARY
        if not library.is_file():
            continue
        if abi.name not in recorded:
            report.fail(
                f"{library} is not in {BUILD_MANIFEST.name}, so it is left over from an earlier\n"
                f"      build or was copied in. Run a full build."
            )
        elif recorded[abi.name] != sha256_of(library):
            report.fail(
                f"{library} does not match the hash {BUILD_MANIFEST.name} recorded for it, so it is\n"
                f"      stale. Run a full build."
            )
        else:
            report.ok(f"{abi.name} is the library this build produced")


def check_contracts(report: Report) -> None:
    """Checks what the Gradle module and the native build have to agree on.

    Only the library name is left: the API level is read from the Gradle module rather than repeated,
    so there is nothing there to disagree about.
    """
    print("==> cross-layer contracts")

    declared = declared_library_name()
    expected = LIBRARY.removeprefix("lib").removesuffix(".so")
    if declared is None:
        report.skip("library name", f"no NATIVE_LIBRARY_NAME declaration in {KOTLIN_FACADE}")
    elif declared == expected:
        report.ok(f'Kotlin loads "{declared}", matching {LIBRARY}')
    else:
        report.fail(
            f'{KOTLIN_FACADE} loads "{declared}" but the library is {LIBRARY}.\n'
            "      System.loadLibrary would fail at run time."
        )


def check_abi(report: Report, ndk: Ndk, abi: Abi, require_symbols: bool) -> None:
    print(f"==> {abi.name}")
    library = JNI_LIBS_DIR / abi.name / LIBRARY
    if not library.is_file():
        report.fail(f"{library} does not exist. Build it first.")
        return

    header = ndk.run_tool("llvm-readelf", "-hW", library)
    if re.search(rf"Machine:.*{re.escape(abi.elf_machine)}", header):
        report.ok(f"ELF machine is {abi.elf_machine}")
    else:
        machine = re.search(r"Machine: *(.+)", header)
        report.fail(f"{library} is not {abi.elf_machine}: {machine.group(1) if machine else '?'}")

    # Checked as >= rather than == so that a future NDK aligning more coarsely by default still
    # passes.
    segments = ndk.run_tool("llvm-readelf", "-lW", library)
    aligns = [
        int(line.split()[-1], 0)
        for line in segments.splitlines()
        if line.strip().startswith("LOAD")
    ]
    if not aligns:
        report.fail(f"{library} has no LOAD segments")
    elif all(align >= MIN_PAGE_ALIGN for align in aligns):
        report.ok(f"every LOAD segment is aligned to at least {MIN_PAGE_ALIGN}")
    else:
        report.fail(
            f"{library} has LOAD segments below {MIN_PAGE_ALIGN}: "
            f"{', '.join(hex(a) for a in aligns)}.\n"
            "      Was the max-page-size link argument dropped from the build?"
        )

    dyn_syms = ndk.run_tool("llvm-readelf", "--dyn-syms", "-W", library)
    if EXPORTED_SYMBOL in dyn_syms:
        report.ok(f"exports {EXPORTED_SYMBOL}")
    else:
        report.fail(f"{library} does not export {EXPORTED_SYMBOL}; LTO or strip removed it")

    # Two libraries in one process both exporting SSL_* is a classic and very hard to debug crash.
    # rustc's cdylib version script should already hide them; assert it rather than assume it.
    leaked = re.findall(r" (?:SSL|EVP|CRYPTO)_[A-Za-z0-9_]+$", dyn_syms, re.MULTILINE)
    if not leaked:
        report.ok("re-exports no BoringSSL symbols")
    else:
        report.fail(
            f"{library} re-exports {len(leaked)} BoringSSL symbol(s); they will collide with other "
            "native libraries"
        )

    dynamic = ndk.run_tool("llvm-readelf", "-dW", library)
    needed = set(re.findall(r"\(NEEDED\).*Shared library: \[(.*)\]", dynamic))
    unexpected = sorted(needed - ALLOWED_NEEDED)
    if not unexpected:
        report.ok(f"links only against {' '.join(sorted(ALLOWED_NEEDED))}")
    else:
        report.fail(
            f"{library} has unexpected DT_NEEDED entries: {' '.join(unexpected)}\n"
            f"      Allowed: {' '.join(sorted(ALLOWED_NEEDED))}. Widen the allowlist only "
            "deliberately."
        )

    # The NDK satisfies the C++ runtime statically, which is why nothing is shipped alongside. If a
    # future toolchain produces a real dependency on libc++_shared.so instead, it has to be staged
    # next to the library, and this catches the transition.
    if (
        "libc++_shared.so" in needed
        and not (JNI_LIBS_DIR / abi.name / "libc++_shared.so").is_file()
    ):
        report.fail(
            f"{library} depends on libc++_shared.so but it is not staged in "
            f"{JNI_LIBS_DIR / abi.name}.\n"
            "      The library will fail to load on device."
        )

    # Read from the unstripped library, because llvm-nm reports "no symbols" for a stripped one and
    # the check would then pass on empty input. After a build it must be there, so its absence is a
    # failure.
    unstripped_library = UNSTRIPPED_DIR / abi.name / LIBRARY
    if not unstripped_library.is_file():
        message = f"no unstripped library at {unstripped_library}"
        if require_symbols:
            report.fail(f"{message}, so the C++ runtime could not be checked")
        else:
            report.skip(f"C++ runtime ({abi.name})", message)
        return

    undefined_cxx = undefined_cxx_runtime_symbols(ndk.run_tool("llvm-nm", "-u", unstripped_library))
    if not undefined_cxx:
        report.ok("the C++ runtime is fully linked in")
    else:
        shown = ", ".join(undefined_cxx[:4])
        report.fail(
            f"{library} leaves {len(undefined_cxx)} C++ runtime symbol(s) undefined: {shown}.\n"
            "      Either link the runtime statically, or stage libc++_shared.so beside it."
        )


def verify(abis: list[Abi], require_symbols: bool = False) -> None:
    """Checks the staged libraries.

    `require_symbols` is set when a build has just produced them, where the checks that need an
    unstripped library cannot legitimately be skipped.
    """
    ndk = Ndk.from_environment()
    report = Report()

    check_staged_set(report)
    check_contracts(report)
    for abi in abis:
        check_abi(report, ndk, abi, require_symbols)

    print()
    if report.failures:
        raise Failure(f"{report.failures} check(s) failed")
    summary = f"All checks passed for: {' '.join(abi.name for abi in abis)}"
    if report.skipped:
        summary += f"\n{len(report.skipped)} check(s) skipped: {', '.join(report.skipped)}"
    print(summary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="android.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    build_parser = subcommands.add_parser("build", help="cross-compile and stage the libraries")
    build_parser.add_argument(
        "-a", "--abi", action="append", choices=list(ABIS), help="build only this ABI (repeatable)"
    )
    build_parser.add_argument(
        "--skip-verify", action="store_true", help="do not check the result afterwards"
    )

    subcommands.add_parser("verify", help="check the staged libraries")

    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            build([ABIS[name] for name in args.abi or ABIS], args.skip_verify)
        else:
            verify(list(ABIS.values()))
    except Failure as failure:
        print(f"error: {failure}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"error: {' '.join(str(a) for a in error.cmd)} failed", file=sys.stderr)
        return error.returncode or 1
    except FileNotFoundError as error:
        # cargo, rustup or an NDK tool is not on PATH. Reported like any other prerequisite rather
        # than as a traceback.
        print(f"error: {error.filename or error} is not installed or not on PATH", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
