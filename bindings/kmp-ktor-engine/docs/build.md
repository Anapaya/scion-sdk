# Build

This document describes what each build host produces, the tools that each
host needs, the shape of the artifacts, and the steps from the Rust crates to
the artifacts.

## Results per platform

| Platform                                    | Binding  | Built on            | State                                      |
| ------------------------------------------- | -------- | ------------------- | ------------------------------------------ |
| Linux x86-64 (`linuxX64`)                   | cinterop | Linux, Mac          | tests pass, sample runs                    |
| Windows x86-64 (`mingwX64`)                 | cinterop | Linux, Windows, Mac | tests pass on Windows 11                   |
| JVM                                         | JNA      | Linux, Windows, Mac | tests pass on Linux, Windows 11, and macOS |
| Android arm64-v8a, armeabi-v7a, x86, x86-64 | JNA      | Linux, Windows, Mac | tests pass on x86-64 and arm64 emulators   |
| iOS arm64 device (`iosArm64`)               | cinterop | Mac                 | builds, tests not run                      |
| iOS arm64 simulator (`iosSimulatorArm64`)   | cinterop | Mac                 | tests pass                                 |
| iOS x64 simulator (`iosX64`)                | cinterop | Mac                 | builds, tests not run                      |
| macOS arm64 (`macosArm64`)                  | cinterop | Mac                 | tests pass, sample runs                    |

Each host builds these native targets:

| Host    | Kotlin/Native targets                                                           | Libraries in the JVM jar                    |
| ------- | ------------------------------------------------------------------------------- | ------------------------------------------- |
| Linux   | `linuxX64`, `mingwX64`                                                          | Linux `.so`, Windows `.dll`                 |
| Windows | `mingwX64`                                                                      | Windows `.dll`                              |
| Mac     | `iosArm64`, `iosSimulatorArm64`, `iosX64`, `macosArm64`, `linuxX64`, `mingwX64` | macOS `.dylib`, Linux `.so`, Windows `.dll` |

`NativeTarget` in `build-logic` holds this mapping. Every Windows binary uses
the Rust target `x86_64-pc-windows-gnu`, because Kotlin/Native has only the
MinGW target for Windows. The JVM DLL uses the same target, so no artifact
needs MSVC. A Linux host cross compiles the Windows binaries. A Mac cross
compiles the Linux and the Windows binaries, so it builds every artifact.
The Linux library from a Mac needs glibc 2.17 or later. Android builds on
every host.

## Tools per host

Gradle downloads the Kotlin/Native toolchain. rustup installs the Rust
toolchain from `rust-toolchain.toml` and the Rust targets. BoringSSL, from
`scion-http3`, needs cmake and libclang for every Rust target.

### Linux

`nix develop` supplies everything, from `flake.nix`:

- Temurin JDK 21, rustup, cmake, and libclang.
- The Android SDK with the NDK version from `androidNdk` in
  `gradle/libs.versions.toml`, the emulator, and a system image with the
  ABI of the host.
- zig and nasm, for the cross build to Windows. On a Mac also to Linux.
- binutils: `ld`, `objcopy`, `nm`, and `ar`. They read ELF and COFF.

### Mac

- Xcode, with an iOS simulator runtime: `xcodebuild -downloadPlatform iOS`.
  Xcode supplies the C toolchain, libclang, and the Apple SDKs.
- `nix develop`, for Apple Silicon only. It supplies the tools of the Linux
  shell, except libclang. The binutils carry a target prefix, for example
  `x86_64-unknown-linux-gnu-ld`, because `ld` and `ar` stay those of Xcode.

The Nix installer writes `/etc/fstab`. In an SSH session, macOS blocks that
unless `sshd-keygen-wrapper` has Full Disk Access.

### Windows

There is no dev shell. Install these and put them on `PATH`:

- Temurin JDK 21.
- rustup, with the GNU host: `rustup set default-host x86_64-pc-windows-gnu`.
  cargo builds the build scripts and the proc macros for the host target.
  With the MSVC host, that needs the Visual Studio Build Tools.
- cmake, nasm, and LLVM. bindgen loads libclang from LLVM.
- A MinGW-w64 toolchain with `gcc`, `ar`, `nm`, and `objcopy`. The tested
  build used the WinLibs toolchain from Strawberry Perl.
- The Android SDK with platform 35, build-tools 35, and the NDK version from
  `androidNdk`. Set `ANDROID_HOME`. Gobley reads the NDK when Gradle
  configures the project, also for a build without Android tasks.

## Artifacts

Each Kotlin Multiplatform target publishes its own module. The engine and
`ktor-client-scion-testing` have the same shape.

| Target        | Artifact        | Native code inside                                                          |
| ------------- | --------------- | --------------------------------------------------------------------------- |
| Kotlin/Native | klib per target | the Rust static library, in the cinterop klib                               |
| JVM           | jar             | one Rust shared library per platform, in the JNA resource folder            |
| Android       | AAR             | one Rust shared library per ABI under `jni/`, and the platform verifier jar |

- **klib.** The cinterop klib holds the Rust static library under
  `default/targets/<target>/included/`. On Windows, two import libraries
  from the cargo registry sit next to it. The manifest names only system
  libraries. Kotlin/Native links it into the final
  binary. Only the UniFFI functions, `uniffi_<library>_*` and
  `ffi_<library>_*`, keep their names. So a binary can also link other Rust
  static libraries.
- **JVM jar.** One jar holds the libraries of several platforms. It has one
  folder per platform, named `<os>-<arch>` as JNA expects. Each folder holds the shared library
  for that platform. A jar from a Linux host has these:

  ```text
  linux-x86-64/libktor_scion_core.so
  win32-x86-64/ktor_scion_core.dll
  ```

  When the JVM loads the engine, JNA takes the folder for its own OS and
  architecture. The table under "Results per platform" says which folders
  each host writes. A jar for all platforms needs the folders from each
  host in one jar. Gobley also writes one jar per platform, with the
  platform as classifier.
- **AAR.** `jni/<abi>/libktor_scion_core.so` for each ABI. `libs/` holds the
  Kotlin side of `rustls-platform-verifier`, which the Rust code calls on
  Android.

## Steps

1. **Rust build.** For each Rust target, Gobley runs cargo on the crate in
   `rust/`. The crate builds a `staticlib` for Kotlin/Native and a `cdylib`
   for the JVM and Android.
2. **Symbols.** `rust-staticlib-isolation` in `build-logic` rewrites each
   static library right after the cargo build. On ELF and Mach-O, it makes every
   symbol local except the UniFFI ones. On COFF, it renames them to
   `<library>_rs_<name>`. The DLL import members stay as they are. Then it
   rewrites the def file of cinterop: a library from a build script, for
   example an import library from the cargo registry, goes into the klib,
   and the absolute `-L` paths of the build machine go away.
3. **Bindings.** UniFFI generates the Kotlin side from the metadata of the
   host library. The metadata is the same for every target.
4. **Kotlin/Native.** cinterop reads the C header of the bindings and packs
   the static library into the cinterop klib. Kotlin compiles the main klib.
5. **JVM.** Gobley packs the shared library of each JVM target into a jar of
   its own. `native-jar-combiner` in `build-logic` copies the libraries from
   those jars into the main jar, each into its JNA folder.
6. **Android.** Gobley builds one shared library per ABI with the NDK and
   puts it into the AAR. If `-Pscion.androidAbis` names a list of ABIs,
   Gobley builds only those.

## Tests on an Android emulator

`commonTest` also runs as an Android instrumented test, in the release
variant. The test network runs in the test app, as on the other targets.
The dev shell supplies the emulator and a system image with the ABI of the
host: `x86_64` on Linux, `arm64-v8a` on a Mac. Set `ABI` to that value:

```sh
echo no | avdmanager create avd -n ktor-scion -k "system-images;android-35;google_apis;$ABI"
emulator -avd ktor-scion -no-window -no-audio -no-snapshot &
adb wait-for-device
./gradlew connectedAndroidTest -Pscion.androidAbis=$ABI
```

On Linux, the emulator needs KVM: the user must be able to open `/dev/kvm`.
The emulator of an Android Studio SDK does not start on NixOS, because it
finds no X11 libraries. On a Mac, the emulator uses the Hypervisor
framework. Inside a macOS VM, that needs nested virtualization, which Apple
offers from M3 on.
