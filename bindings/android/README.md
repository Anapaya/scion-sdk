# SCION HTTP/3 for Android

A Gradle project that packages the Rust SCION HTTP/3 client into an Android library (AAR). The Rust
code itself lives in [`crates/`](../../crates): this directory cross-compiles
[`scion-http3-ffi`](../../crates/libs/scion-http3-ffi) for Android, generates the Kotlin bindings for
it, and wraps the result.

**Using the library rather than building it?** See
[`scion-http3-android/README.md`](scion-http3-android/README.md), which is the documentation for
consumers. This file is about the build.

ABIs: `arm64-v8a` and `x86_64` (the emulator). `armeabi-v7a` is deliberately not built.

Three modules, and the tools that feed them:

| | |
| --- | --- |
| `scion-http3-android` | The Android library: the Kotlin API, the generated bindings, and the cross-compiled libraries, packaged into the AAR. |
| `scion-http3-jvm-test` | Tests for the bindings, on a desktop JVM. Not published, and not part of the AAR. |
| `hello-scion` | The sample app: an Android application that sends one request. Not published. |
| `tools/android.py` | Cross-compiles the shared library for each ABI, and checks both the result and the AAR it ends up in. |
| `tools/e2e.sh` | Runs the end-to-end tests on an emulator. |
| `../../tools/uniffi-bindgen` | The binding generator, built from the workspace's pinned `uniffi`. |

Gradle owns the bindings; `android.py` owns the cross-compile. The split follows what needs an NDK:
the bindings come from a host build, which needs only cargo, while the libraries need the whole
NDK and cmake toolchain and are therefore produced outside Gradle.

## Prerequisites

- **JDK 17**, and an **Android SDK** with `platforms;android-35` and `build-tools;35.0.0`.
- **Android NDK r27** (`27.0.12077973`), for example
  `sdkmanager --install "ndk;27.0.12077973"`.
- **cmake** and a **libclang**, both of which BoringSSL and its bindings generator need.
- **Python 3.9 or newer**, which `tools/android.py` runs under. No third-party packages.
- A **Linux or macOS host**. The cross-compiled libraries would build anywhere the NDK runs, but the
  host build that the bindings are generated from, and the JVM-host tests that load it, name the
  shared library per platform and cover those two only. Windows is not (yet) supported.
- For the emulator tests only: **KVM** (`/dev/kvm`, on Linux), and a writable Android SDK, since
  Gradle downloads the emulator and its system image into it on the first run.
- The two Rust targets:

  ```bash
  rustup target add aarch64-linux-android x86_64-linux-android
  ```

Everything above has to be installed and on `PATH`; the build does not fetch any of it. If you use
the repository's nix development shell, it already provides cmake, libclang, Python and the Rust
toolchain, leaving the JDK, the Android SDK and the NDK to install yourself.

## Building

From `endhost/public`:

```bash
export ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/27.0.12077973   # or wherever yours lives
./bindings/android/tools/android.py build                     # both ABIs, then checks them
cd bindings/android && ./gradlew :scion-http3-android:assembleRelease
```

Assembling generates the Kotlin bindings on the way (`generateBindings`), from a **host** build of
`scion-http3-ffi` rather than from either cross-compiled library. UniFFI reads its metadata out of
the built library, and that metadata says nothing about the target, so one host compile produces the
Kotlin that ships in the AAR and the Kotlin the JVM tests run against.

`build` takes `--abi arm64-v8a` to build a single ABI, which roughly halves the time when you are
iterating on the cross-build itself, and `--skip-verify` to leave the checks to you. Note that
`verify` always checks both ABIs, so run it through `build` while a set is incomplete.

Checking is a subcommand of its own, so it can be re-run without rebuilding:

```bash
./bindings/android/tools/android.py verify
```

It takes no options and checks every ABI the AAR ships. `build` records what it produced in
`generated/build-manifest.json`, and `verify` compares the staged libraries against it, so a passing
run means these bytes came from this build rather than merely that they are well-formed: a library
left behind by an earlier `--abi` run, or one copied in from elsewhere, is reported instead of
shipped. To check libraries built elsewhere, copy them into
`scion-http3-android/generated/jniLibs/<abi>/`; the provenance check is then skipped, and the
summary says so.

`verify` runs before Gradle has packaged anything, so it can only speak for the staging directory.
The AAR itself is a third subcommand:

```bash
./bindings/android/tools/android.py verify-aar
```

It checks that the AAR carries a library for every ABI, that each one is byte for byte the library
that was built, and that `classes.jar` holds both the generated bindings and the hand-written
facade. That last pair is what a `sourceSets` regression takes away while leaving every other check
green:
the result still assembles, still weighs megabytes, and has no way to reach the native code. Pass
`--aar` to check a file somewhere else, a published or downloaded one say; it needs neither an NDK
nor a Rust toolchain.

Outputs:

Paths below are relative to this directory, except where they are under cargo's target directory,
written `<cargo target>`. That location is configurable, through `CARGO_TARGET_DIR`, through
`build.target-dir` in a `.cargo/config.toml`, or left at the default `target/`, and CI moves it out
of the workspace to share one cache between jobs. Nothing here assumes it: `android.py` and
`settings.gradle.kts` both ask cargo. To see where it is:

```bash
cargo metadata --format-version 1 --no-deps | jq -r '.target_directory'
```

| Path | Contents |
| --- | --- |
| `scion-http3-android/generated/jniLibs/<abi>/libscion_http3_ffi.so` | Stripped, what ships |
| `scion-http3-android/generated/unstripped/<abi>/` | Unstripped, for symbolicating a native crash |
| `scion-http3-android/generated/build-manifest.json` | What the build produced, checked by `verify` |
| `scion-http3-android/generated/kotlin/` | The generated bindings, compiled by both modules |
| `scion-http3-android/build/outputs/aar/scion-http3-android-release.aar` | The AAR |
| `<cargo target>/release/libscion_http3_ffi.{so,dylib}` | The host library, which the JVM tests load |
| `<cargo target>/release/scion-h3-test-server` | The test server those tests run as a child process |
| `<cargo target>/<triple>/mobile/` | The cross-compiled libraries, before staging |

`generated/` is gitignored and sits outside `build/`, so `gradle clean` does not delete artifacts
Gradle did not produce. The unstripped libraries live there too, beside the stripped ones they
correspond to, so a `cargo clean` cannot take one and leave the other.

## Testing the bindings

```bash
cd bindings/android && ./gradlew :scion-http3-jvm-test:test
```

Ordinary JUnit tests on a desktop JVM, with no emulator and no Android SDK involved: UniFFI's Kotlin
binds through JNA, which is not Android-specific, and the FFI layer touches no Android API. Gradle
builds everything they need, including
[`scion-h3-test-server`](../../tools/scion-h3-test-server), which the tests run as a child process:
it is a PocketSCION topology with an HTTP/3 server in it, and requests really cross the SCION data
plane.

The module resolves the bindings as an artifact the Android module offers, then compiles them as its
own main source set rather than depending on the compiled classes. That is what lets its tests reach
UniFFI's `internal` declarations, which is how the cancellation test can assert that a cancelled
call left nothing behind. The library it loads is the same file the bindings were generated from,
taken from cargo's output rather than staged, so the two cannot come from different builds.

Anything that touches an Android API belongs to the instrumented tier instead, which the Kotlin
library brings with it.

## Testing the Kotlin library

```bash
cd bindings/android && ./gradlew :scion-http3-android:testReleaseUnitTest
```

Also plain JUnit on a desktop JVM, but against a fake of the FFI seam rather than the real library,
so these tests load no native code and start no SCION network. What they cover is the part of this
library that decides anything: when connectivity is rebuilt after a network change, what a client
does and does not do while being built, the lifecycle, and the mapping in both directions.

Unlike the bindings tests above, this needs the Android SDK, because the tests compile against
`android.jar`. Everything they exercise reaches the framework through an interface in
`internal/Seams.kt`, so nothing in them actually calls it: `testOptions.unitTests` deliberately
leaves `isReturnDefaultValues` off, which makes a test that bypassed a seam fail with "not mocked"
rather than quietly succeed on a stubbed zero.

What that tier cannot show is whether the framework behaves the way those seams assume, or whether a
cancelled call really reaches the Rust future. The first is the instrumented tests' job, the second
is covered above.

## Testing on an emulator

```bash
cd bindings/android && ./tools/e2e.sh            # everything
cd bindings/android && ./tools/e2e.sh ResetTest  # one class
```

End-to-end tests using and Android emulator.

The script builds the test server and the `x86_64` library, starts the server on this machine, runs
`:scion-http3-android:emulatorX64DebugAndroidTest`, and stops the server again however the run ends.
The emulator is a Gradle managed device declared in the module's build file, so the first run
downloads an API 34 `aosp-atd` image and every run after it boots the same one.

The tests read everything, the endhost API, the token, the server's SCION address, and its
certificate, from the server's own `GET /info`. Only where this machine is and which port its
control API listens on are agreed in advance, as instrumentation arguments with defaults in the
build file.

Outputs:

| Path | Contents |
| --- | --- |
| `scion-http3-android/build/outputs/androidTest-results/managedDevice/` | JUnit XML, and logcat per test |
| `scion-http3-android/build/reports/androidTests/managedDevice/` | The same run as HTML |
| `build/e2e/fixture-snap.log` | The test server's own output, which is where a topology that failed says why |
| `build/e2e/fixture-info.json` | The line it printed on start-up, which is what the tests read over the control API |

## Consuming the AAR

The library is published as `com.anapaya.scion:scion-http3-android`, under the version of the SDK
release it belongs to. The module reads that version from the Cargo workspace, so nothing here has
to be bumped by hand and the AAR always carries the same number as the crates released beside it.

For local development, publish it into your own Maven repository and add `mavenLocal()` to your
repositories:

```bash
./gradlew :scion-http3-android:publishToMavenLocal
```

Releases carry the same publication as assets: the `.aar`, its sources jar, its POM, and a
`-maven.zip` holding the whole Maven layout. Unpack that zip and name it as a repository to resolve
the coordinates with their dependencies. Consumers who only want the file are documented in
[`scion-http3-android/README.md`](scion-http3-android/README.md).

The library declares the `INTERNET` and `ACCESS_NETWORK_STATE` permissions, which merge into the
consuming application's manifest.

## Environment

> [!WARNING]
> **Never set `CMAKE_TOOLCHAIN_FILE`.** `boring-sys` returns an unconfigured cmake setup when that
> variable is set, skipping the `ANDROID_ABI`, `ANDROID_STL` and API level it would otherwise
> define. BoringSSL then builds for the NDK toolchain's default ABI rather than the one being
> targeted, and nothing fails until the link. Setting it empty does not help.
> `android.py` refuses to run when it is set.

`ANDROID_NDK_HOME` must be exported, and is the only variable that has to be. Nothing is guessed:
the tool fails with an explicit message if it is unset, so a build cannot silently pick up a
different NDK than you meant. `boring-sys` reads that same variable, does not fall back to
`ANDROID_NDK_ROOT`, and panics without it.

`android.py` deliberately takes control of the C, C++ and bindgen include paths, so that
host-toolchain settings in the ambient environment cannot reach the cross compile and collide with
the NDK sysroot. Run the build through the tool rather than invoking `cargo` directly.

## Notes

- The API level the Rust and link steps target is read from the Gradle module's `minSdk`, so the two
  cannot disagree. `boring-sys` pins BoringSSL itself to API 21 and offers no way to override that,
  which is harmless for any `minSdk` at or above 21.
- The libraries are self-contained: the NDK links the C++ runtime statically, so there is no
  `libc++_shared.so` to ship alongside them.
- 16 KB page alignment, required by Android 15 and later on arm64, is applied at link time and
  checked by `verify`.
- The `mobile` cargo profile keeps unwinding enabled; `scion-http3-ffi` fails to compile without it
  and says why.

## Troubleshooting

| Message | Cause |
| --- | --- |
| `Please set ANDROID_NDK_HOME for Android build` | `boring-sys` cannot find the NDK. Export `ANDROID_NDK_HOME`. |
| `CMAKE_TOOLCHAIN_FILE is set` | See the warning above. Unset it. |
| `'gnu/stubs-32.h' file not found` | The bindings generator is reading host headers. Build through `android.py`. |
| `typedef redefinition ... mbstate_t` | Host C++ flags reached BoringSSL's cmake build. As above. |
| `Missing prebuilt native libraries` | Gradle's `checkNativeLibraries` task. Run `tools/android.py build`, or pass `-PskipNativeCheck` for lint-only work. |
| `No Kotlin was generated under ...` | Gradle's `generateBindings` task. The library exports no UniFFI metadata: usually `uniffi::setup_scaffolding!` is gone, or the package name in `uniffi.toml` changed. |
| `scion.test.server is not set` | A JVM test was run outside Gradle. It is the Gradle task that builds the test server and passes its path. |
| `the Rust standard library for <target> is missing` | `rustup target add <target>`. |
| cmake warns that `ANDROID_ABI` and friends "were not used by the project" | A stale BoringSSL build directory is being reused, and cmake honours its own cache over the defines passed to it. Delete `<cargo target>/<triple>` and build again. Do this after changing the NDK or the API level. |
