# SCION HTTP/3 for Apple platforms

The Swift client's package, and the native half under it: this directory cross-compiles
[`scion-http3-ffi`](../../crates/libs/scion-http3-ffi) as a static library for five Apple targets,
generates the Swift bindings with the C header and the module map, assembles the three slices into
an XCFramework, and builds the Swift package that consumes it.

| | |
| --- | --- |
| `scion-http3-swift/` | The Swift package: the facade, the generated bindings, and the tests. See [its README](scion-http3-swift/README.md). |
| `hello-scion/` | The sample app: an iOS application that sends one HTTP request. See [its README](hello-scion/README.md). |
| `tools/apple.py` | Cross-compiles a static library per target, checks them, assembles the XCFramework into the package, and checks that too. |
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
./bindings/apple/tools/apple.py xcframework   # fuses, generates, assembles into the package, checks
./bindings/apple/tools/apple.py release       # zips the XCFramework and the package for a release
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
| `scion-http3-swift/Sources/ScionHTTP3Uniffi/` | The generated Swift, compiled as the package's bindings target |
| `scion-http3-swift/ScionHTTP3UniffiFFI.xcframework` | The XCFramework, where `Package.swift` looks for it |
| `generated/release/` | What `release` writes: the assets a GitHub release carries, see *Releases* |
| `<cargo target>/<triple>/mobile/libscion_http3_ffi.a` | Before staging and stripping |

`generated/`, the generated Swift and the XCFramework are gitignored, as the Kotlin and the native
libraries are on Android. The last two sit inside the package, because SwiftPM compiles a target
from under `Sources/` and accepts a local binary target from inside the package only, and outside
`.build/`, so `swift package clean` cannot delete artifacts SwiftPM did not produce.

## The Swift package

`scion-http3-swift/` is a plain SwiftPM package. Once the XCFramework is in place, everything else
is `swift`:

```bash
cd bindings/apple/scion-http3-swift
swift build
swift test
```

The package has two test targets. `ScionHTTP3Tests` runs the facade against a fake backend, with no
server and no call into the native library, in seconds. `ScionHTTP3HostTests` runs the raw bindings
and the facade against the real library: it starts `scion-h3-test-server`, a PocketSCION topology
with an HTTP/3 server in it, as a child process. To use a server built elsewhere, set
`SCION_H3_TEST_SERVER` to its path. To run one target only:

```bash
swift test --filter ScionHTTP3Tests
```

The host tests can also attach to a server that is already running instead of starting one: set
`SCION_H3_TEST_SERVER_CONTROL_URL` to its control API, for example `http://127.0.0.1:7443` for a
server started with `--control-port 7443`. The two tests that need a server with other options
are skipped then.

## Testing on the simulator

```bash
./bindings/apple/tools/e2e.sh                           # everything
./bindings/apple/tools/e2e.sh FacadeCancellationTests   # one class
```

The host tests, `ScionHTTP3HostTests`, run in an iOS simulator. The unit tests are left to
`swift test`.

A test in the simulator cannot start a process, so the script starts the test server on this
machine, boots a simulator, and runs `xcodebuild test` with the package scheme in it. The tests
read everything, the endhost API, the token, the server's SCION address, and its certificate,
from the server's `GET /info` at `http://127.0.0.1:7443`. The simulator shares this machine's
network, so no address translation is involved. Only the port is agreed in advance;
`FIXTURE_CONTROL_PORT` changes it for a second run beside a first one and the tests learn the new
one from the environment `xcodebuild` hands them.

The script needs the XCFramework and the generated bindings in the package, which
`apple.py xcframework` writes and it builds the test server with cargo unless
`SCION_H3_TEST_SERVER` names one. It picks an iPhone on the newest installed iOS runtime, or the
simulator `SIMULATOR_UDID` names.

## Testing on a device

You need a Mac and an iPhone on the same network, a signing team, and the LAN address of the Mac,
`<lan-ip>` below.

1. Start the test server on the Mac, on the LAN address, so that the phone can reach every
   component of the topology:

   ```bash
   cargo run --release -p scion-h3-test-server -- --bind-ip <lan-ip> --control-port 7443
   ```

2. Run the suite on the phone, telling it where the control API is:

   ```bash
   cd bindings/apple/scion-http3-swift
   TEST_RUNNER_SCION_H3_TEST_SERVER_CONTROL_URL=http://<lan-ip>:7443 \
       xcodebuild test -scheme scion-http3-swift-Package \
       -destination 'platform=iOS,id=<device-udid>' \
       -allowProvisioningUpdates DEVELOPMENT_TEAM=<team-id>
   ```

   iOS asks once whether the test host may find and connect to devices on the local network.
   Accept it. iOS drops the traffic of an application that was refused.

3. Handover. With the phone on Wi-Fi, run the suite once so that connectivity exists, then turn
   Wi-Fi off in Control Center while a request is in flight. The expected outcome: the request in
   flight fails with a retryable error, the facade logs `the network path changed`, and the next
   request succeeds over cellular without any call to `reset()`. Cellular must be able to reach
   `<lan-ip>` for this; a phone hotspot with the Mac on it is the simplest arrangement.

4. Suspension. Make a request, press the home button, wait five minutes, and return. The expected
   outcome: the first request either succeeds or fails with a retryable error and the request
   after it succeeds. Nothing hangs for longer than the connect timeout.

5. MTU. Over cellular, fetch `/big?bytes=1048576` and compare the byte count to the request. The
   expected outcome: the full body arrives, and the facade's log shows no retries.

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
That job also builds the package for macOS and for the iOS simulator, and runs the Swift tests
against a test server the `aarch64-apple-darwin` job built. Additionally, itassembles the release
assets with `apple.py release`, so that a break there shows on a pull request and not at release
time. A third job runs `tools/e2e.sh`: the same tests in an iOS simulator, against the XCFramework
zip from those assets. On a failure it uploads `build/e2e/` without the derived data. The workflow
runs nightly, on a pull request that touches the paths it lists, and on manual dispatch.

## Releases

Every SDK release carries the Swift package as assets, next to the Android library and the crates.
Pushing a release tag runs [`release-apple.yml`](../../.github/workflows/release-apple.yml), which
checks that the workspace version matches the tag, cross-compiles the five targets, assembles the
XCFramework, builds the package against it, runs `apple.py release`, and uploads what it wrote:

| Asset | Contents |
| --- | --- |
| `ScionHTTP3UniffiFFI-<version>.xcframework.zip` | The XCFramework, zipped the way a SwiftPM binary target downloads it |
| `scion-http3-swift-<version>.zip` | This package with the generated bindings in it, and `Package.swift` pointing at the zip above by URL and SwiftPM checksum |
| `SHA256SUMS-apple` | Checksums of both. |

The package carries no version of its own. It is released under the version of the Cargo
workspace, read from the `scion-stack` crate, so a tag that does not match the tree fails the
workflow.

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
| `expected one .swift, one .h and one .modulemap` | The library exports no UniFFI metadata, or `[bindings.swift]` in `uniffi.toml` changed. |
| `Source files for target ScionHTTP3Uniffi should be located under` (SwiftPM) | The generated Swift is not in the package. Run `apple.py xcframework`. |
| `declares ios 16.0, but the slices are built for 15.0` | `Package.swift` and `apple.py` disagree on a minimum OS. Change both together. |
| `invalid local binary target path` or `does not contain a binary artifact` (SwiftPM) | The XCFramework is not in the package. Run `apple.py xcframework`. |
| `did not report its endpoints within 120 s` | The test server did not start. Its standard error is in the test output; run the binary by hand to see more. |
| `cargo build ... exited` (Swift tests) | The tests could not build the test server. Build it yourself and set `SCION_H3_TEST_SERVER`. |
| `could not be reached, and stayed unreachable for 10 s` | The tests were told to attach to a server, and nothing answers at that control API. On the simulator, run the tests through `tools/e2e.sh`, which starts one. |
| `needs a server started with ...` (a skipped test) | Expected when attached: that test needs a server with other options and runs on the host only. |
| `The XCFramework or the generated bindings are missing` | `tools/e2e.sh` does not assemble the XCFramework. Run `apple.py xcframework`. |
| `scheme scion-http3-swift-Package not found` | SwiftPM's synthesized scheme has another name in this Xcode. The message lists what it found; pass it by editing `SCHEME` in `tools/e2e.sh`. |
| `no available iPhone simulator` | Install an iOS runtime in Xcode's Settings, or name a simulator in `SIMULATOR_UDID`. |
