# SCION HTTP/3 for Apple platforms

The native half of the Swift client: this directory cross-compiles
[`scion-http3-ffi`](../../crates/libs/scion-http3-ffi) as a static library for five Apple targets,
generates the C header and the module map for it, and assembles the three slices into an
XCFramework.

| | |
| --- | --- |
| `tools/apple.py` | Cross-compiles a static library per target, checks them, assembles the XCFramework, and checks that too. |
| `tools/test_apple.py` | Tests for the formats `apple.py` parses. No Xcode needed. |
| `../../tools/uniffi-bindgen` | The binding generator, built from the workspace's pinned `uniffi`. |

## Slices and deployment targets

Five Rust targets become three XCFramework slices.

| Slice | Rust targets | Minimum OS |
| --- | --- | --- |
| `ios-arm64` | `aarch64-apple-ios` | iOS 15.0 |
| `ios-arm64_x86_64-simulator` | `aarch64-apple-ios-sim`, `x86_64-apple-ios` | iOS 15.0 |
| `macos-arm64_x86_64` | `aarch64-apple-darwin`, `x86_64-apple-darwin` | macOS 12.0 |

## Prerequisites

- **macOS with Xcode** and the iOS SDK it ships.
- **cmake**, which that BoringSSL build needs.
- **Python 3.9 or newer**, which `tools/apple.py` runs under. No third-party packages.
- The five Rust targets:

  ```bash
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
      aarch64-apple-darwin x86_64-apple-darwin
  ```

Around 15 GB of free disk, if you build all five in one go. Each target gets a directory of its own
under cargo's target directory and a cross-compiled BoringSSL in it.

## Building

From `endhost/public`:

```bash
./bindings/apple/tools/apple.py build         # all five targets, then checks them
./bindings/apple/tools/apple.py xcframework   # fuses, generates, assembles, then checks
```

`build` takes `--target aarch64-apple-darwin` to build a single target, which is what to use while
iterating on anything but the cross-build itself, and `--skip-verify` to leave the checks to you.
`verify` takes the same `--target`.

Checking is a subcommand of its own, so it can be re-run without rebuilding:

```bash
./bindings/apple/tools/apple.py verify
./bindings/apple/tools/apple.py verify-xcframework --xcframework /path/to/ScionHTTP3UniffiFFI.xcframework
```

Outputs:

Paths below are relative to this directory, except where they are under cargo's target directory,
written `<cargo target>`. That location is configurable, through `CARGO_TARGET_DIR`, through
`build.target-dir` in a `.cargo/config.toml`, or left at the default `target/`. Nothing here
assumes it; `apple.py` asks cargo. To see where it is:

```bash
cargo metadata --format-version 1 --no-deps | jq -r '.target_directory'
```

| Path | Contents |
| --- | --- |
| `generated/libs/<triple>/libscion_http3_ffi.a` | Stripped, one per Rust target |
| `generated/libs/<triple>/build-manifest.json` | What the build produced, checked by `verify` |
| `generated/slices/<slice>/libscion_http3_ffi.a` | The same libraries, fused per slice by `lipo` |
| `generated/bindings/` | What uniffi-bindgen wrote: the Swift source, the header, the module map |
| `generated/headers/` | The header and `module.modulemap`, as every slice carries them |
| `generated/ScionHTTP3UniffiFFI.xcframework` | The XCFramework |
| `<cargo target>/<triple>/mobile/libscion_http3_ffi.a` | Before staging and stripping |

`generated/` is gitignored, and sits outside any Xcode or SwiftPM build directory so that neither
can delete artifacts it did not produce.

## Environment

> [!WARNING]
> **Never set `CMAKE_TOOLCHAIN_FILE`.** `boring-sys` returns an unconfigured cmake setup when that
> variable is set, skipping the `CMAKE_OSX_ARCHITECTURES` and `CMAKE_OSX_SYSROOT` it would
> otherwise define. BoringSSL then builds for the host rather than for the slice and nothing fails
> until the link. Setting it empty does not help. `apple.py` refuses to run when it is set, and for
> `SDKROOT` as well, which clang and cmake both fall back to.

Nothing else has to be exported. `apple.py` sets the deployment target itself, per slice, and
removes every other Apple deployment-target variable.

Run the build through the tool rather than invoking `cargo` directly.

## CI

[`endhost-public-apple.yml`](../../../../.github/workflows/endhost-public-apple.yml) builds one
target per job, on `macos-15`, and then assembles and checks the XCFramework in a job of its own.
It runs nightly, on a pull request that touches the paths it lists, and on manual dispatch.

## Troubleshooting

| Message | Cause |
| --- | --- |
| `this runs on macOS with Xcode only` | There is no Linux cross-build. See *Prerequisites*. |
| `CMAKE_TOOLCHAIN_FILE is set` | See the warning above. Unset it. |
| `SDKROOT is set` | As above. It overrides the SDK a slice is built against. |
| `the Rust standard library for <target> is missing` | `rustup target add <target>`. |
| `holds objects for MACOS, not only IOS` | Part of the build used the host SDK. Usually `CMAKE_TOOLCHAIN_FILE` or `SDKROOT`; otherwise a stale BoringSSL build directory, which cmake honours over the defines passed to it. Delete `<cargo target>/<triple>` and build again. |
| `so IPHONEOS_DEPLOYMENT_TARGET did not reach the compiler` | The build did not go through `apple.py`, or a stale BoringSSL build directory was reused. As above. |
| `rustc reported nothing to link the library against` | The build had nothing to relink and there is no earlier record. Delete `generated/libs/<triple>/` and build again. |
| `expected one .h and one .modulemap` | The library exports no UniFFI metadata, or `[bindings.swift]` in `uniffi.toml` changed. |
