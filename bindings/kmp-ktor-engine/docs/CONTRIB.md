# Contributing

Requests run on the [`scion-http3`](../../../crates/libs/scion-http3) crate.
[Gobley](https://gobley.dev) generates the bindings between Kotlin and Rust
and builds the Rust library for every Kotlin Multiplatform target.

## Layout

| Part                             | Holds                                                                                   |
| -------------------------------- | --------------------------------------------------------------------------------------- |
| `ktor-client-scion`              | the Ktor engine, all of it in `commonMain`                                              |
| `ktor-client-scion/rust`         | `ktor-scion-core`: `scion-http3` and the WebGateway transport behind a UniFFI interface |
| `ktor-client-scion-testing`      | the topology for JVM, Android, and native tests of an app                               |
| `ktor-client-scion-testing/rust` | `ktor-scion-testing`: the topology, as a UniFFI library                                 |
| `build-logic`                    | the Gradle plugin that puts the native libraries into the JVM jars                      |
| `samples/hello-scion`            | one program, run over each binding                                                      |
| `samples/app-testing`            | an app client and its test with `ktor-client-scion-testing`                             |

`ktor-client-scion/rust/src/lib.rs` defines the interface. Gobley generates the
Kotlin that calls it into `ktor-client-scion/build/generated/uniffi`, so the
two sides always match.

The only platform-specific code initializes the certificate verifier on
Android.

## Build

Each host needs these tools:

| Host    | Tools                                                                      |
| ------- | -------------------------------------------------------------------------- |
| Linux   | `nix develop` supplies all of them                                         |
| Mac     | Xcode with an iOS simulator runtime, and `nix develop` on Apple Silicon    |
| Windows | no dev shell: a JDK, rustup, cmake, nasm, LLVM, MinGW-w64, the Android SDK |

[Tools per host](build.md#tools-per-host) in build.md gives the versions and
the setup.

```bash
nix develop
./gradlew build                                  # every target this host can build
./gradlew :ktor-client-scion:assembleRelease     # the Android AAR
```

On a Mac, `./gradlew build` also builds the Apple targets. It runs the tests
of `iosSimulatorArm64` and `macosArm64` only. These tasks run one of them:

```bash
./gradlew :ktor-client-scion:iosSimulatorArm64Test
./gradlew :ktor-client-scion:macosArm64Test
```

## Tests

The tests send real requests over SCION to a PocketSCION topology with an
HTTP/3 server in it. `ktor-client-scion-testing` runs the topology in the
test process. All tests of a process share one topology.

Both bindings run the same tests from `commonTest`. On Android, the tests run
as instrumented tests on an emulator or a device.

Gradle links the `mingwX64` tests on a Linux host, but it does not run them.
Copy `ktor-client-scion/build/bin/mingwX64/debugTest/test.exe` to a Windows
machine and run it there. It needs nothing else.

## How it fits together

1. The engine turns the Ktor request into a `CoreRequest`.
2. It calls `ScionCore.execute`, a generated `suspend` function.
3. The Rust library spawns the request onto its own multi-thread tokio
   runtime. The future that UniFFI polls only waits for that task.

UniFFI does not promise that a cancelled coroutine drops the Rust future, so
the engine has its own channel. It takes a request ID before the call and
calls `ScionCore.release` with that ID after the call. A release during the
call aborts the spawned task, and so does a dropped future. The abort resets
the HTTP/3 stream.

## Another platform

Add the Kotlin target in `build-logic/src/main/kotlin/rust-kmp-library.gradle.kts`.
Gobley derives the Rust target from it and builds the library. For a native
target, also add its Rust triple to `nativeTargets` in
`rust-staticlib-isolation.gradle.kts`. The Kotlin sources do not change.
