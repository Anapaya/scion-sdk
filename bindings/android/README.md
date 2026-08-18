# SCION HTTP/3 for Android

A Gradle project that packages the Rust SCION HTTP/3 client into an Android library (AAR). The Rust
code itself lives in [`crates/`](../../crates): this directory cross-compiles
[`scion-http3-ffi`](../../crates/libs/scion-http3-ffi) for Android and wraps the result.

ABIs: `arm64-v8a` and `x86_64` (the emulator). `armeabi-v7a` is deliberately not built.

## Prerequisites

- **JDK 17**, and an **Android SDK** with `platforms;android-35` and `build-tools;35.0.0`.
- **Android NDK r27** (`27.0.12077973`), for example
  `sdkmanager --install "ndk;27.0.12077973"`.
- **cmake** and a **libclang**, both of which BoringSSL and its bindings generator need.
- **Python 3.9 or newer**, which `tools/android.py` runs under. No third-party packages.
- The two Rust targets:

  ```bash
  rustup target add aarch64-linux-android x86_64-linux-android
  ```

Everything above has to be installed and on `PATH`; the build does not fetch any of it. If you use
the repository's nix development shell, it already provides cmake, libclang, Python and the Rust
toolchain, leaving the JDK, the Android SDK and the NDK to install yourself.

## Building

From the repository root:

```bash
export ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/27.0.12077973   # or wherever yours lives
./bindings/android/tools/android.py build                     # both ABIs, then checks them
cd bindings/android && ./gradlew :scion-http3-android:assembleRelease
```

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

Outputs:

| Path | Contents |
| --- | --- |
| `scion-http3-android/generated/jniLibs/<abi>/libscion_http3_ffi.so` | Stripped, what ships |
| `scion-http3-android/generated/unstripped/<abi>/` | Unstripped, for symbolicating a native crash |
| `scion-http3-android/generated/build-manifest.json` | What the build produced, checked by `verify` |
| `scion-http3-android/build/outputs/aar/scion-http3-android-release.aar` | The AAR |

`generated/` is gitignored and sits outside `build/`, so `gradle clean` does not delete artifacts
Gradle did not produce.

## Consuming the AAR

Either point at the file directly:

```kotlin
dependencies {
    implementation(files("<path>/scion-http3-android-release.aar"))
}
```

or publish it locally with `./gradlew :scion-http3-android:publishToMavenLocal` and add
`mavenLocal()` to your repositories.

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
| `the Rust standard library for <target> is missing` | `rustup target add <target>`. |
| cmake warns that `ANDROID_ABI` and friends "were not used by the project" | A stale BoringSSL build directory is being reused, and cmake honours its own cache over the defines passed to it. Delete `$CARGO_TARGET_DIR/<triple>` and build again. Do this after changing the NDK or the API level. |
