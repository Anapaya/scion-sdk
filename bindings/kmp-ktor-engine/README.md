# ktor-client-scion

A Ktor `HttpClientEngine` that sends HTTP over SCION: HTTP/3 to the origin, or
HTTP/1.1 through a WebGateway.

Status: preview. The API can change between releases.

The guide on learn.anapaya.net shows how to use the engine in an app:
[Kotlin Multiplatform](https://learn.anapaya.net/docs/academy/scion-sdk/platforms/kotlin-multiplatform).
It covers the Maven coordinates, the settings, the WebGateway, the errors, the
limits, and the tests over SCION. This README covers the build from source and
the samples.

## Platforms

The engine targets Linux, Windows, the JVM, Android, iOS, and macOS. A release
on Maven Central has Android, iOS, and the JVM.
[docs/build.md](docs/build.md) describes the state per platform and the
artifacts.

## Build from source

For Windows, and for the targets that a release does not have, build the
artifacts into a Maven repository in `build/repository`:

```bash
./gradlew publishAllPublicationsToLocalBuildRepository
```

The build needs the tools in [Tools per host](docs/build.md#tools-per-host).
The repository only contains the targets that the build host can build.
[Results per platform](docs/build.md#results-per-platform) lists the targets
per host. Add the repository to your project:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven(url = "<path to kmp-ktor-engine>/build/repository")
        mavenCentral()
        google()
    }
}
```

The local build has the coordinates of a release, and the version of the SDK
in the source tree. Alternatively, `./gradlew publishToMavenLocal` writes to
`~/.m2/repository`. Then use `mavenLocal()` in place of the `maven(url = ...)`
line.

## Samples

### Hello SCION

`samples/hello-scion` sends requests over SCION to the origin at `<url>`. It
authenticates with an API key of the AA. The same `main` runs on the JVM and
on Kotlin/Native:

```bash
./gradlew :hello-scion:runJvm --args="<api-key> <url>"
./gradlew :hello-scion:linkReleaseExecutableLinuxX64
samples/hello-scion/build/bin/linuxX64/releaseExecutable/hello-scion.kexe <api-key> <url>
```

A third argument sets a fixed endhost API URL. Without it, the client
discovers the endhost APIs.

To send the requests through a WebGateway, add `--gateway`. If the request
host has no TSAR record, give the SCION address of the gateway with
`--gateway-address`. That option also sets `--gateway`.
`--gateway-port` sets a port other than 443:

```bash
./gradlew :hello-scion:runJvm \
  --args="--gateway-address 1-ff00:0:110,192.0.2.10 <api-key> https://api.example.com/"
```

### Android app

The Android app (`./gradlew :hello-scion:installRelease`) has three fields: the
endhost API URL, the AA API key, and the request URL. The app saves them
between launches. For the origin, it trusts the system and user CAs of the
device. For the AA and the control plane, it uses the Mozilla root set in the
library. If the endhost API field is empty, the app discovers the endhost
APIs.

If the API key field is empty, the app starts a `ScionTestNetwork` in its own
process on the first run, and sends the requests to its test API. This needs
no server on the host. It works on an emulator and on a device.

### iOS app

The iOS app has the same fields and works the same way as the Android app.
It is UIKit in Kotlin, with no Swift and no Xcode project. Build it on a Mac.
With the launch argument `-autorun YES`, the app taps "Run sample" itself
when the screen opens.

On the simulator:

```bash
./gradlew :hello-scion:assembleIosAppIosSimulatorArm64
xcrun simctl boot "iPhone 17 Pro"
xcrun simctl install booted samples/hello-scion/build/ios/iosSimulatorArm64/HelloScion.app
xcrun simctl launch booted net.anapaya.ktor.scion.sample
```

For an iPhone, `./gradlew :hello-scion:assembleIosAppIosArm64` writes
`samples/hello-scion/build/ios/iosArm64/HelloScion.app`. Without an Xcode
project, Xcode does not sign it. Sign it with `codesign` and your
provisioning profile. The bundle ID is in `src/iosMain/Info.plist`.

### App testing

`samples/app-testing` is an app with an API behind a WebGateway, and a test
that sends requests to the API over SCION. The page "Testing your app" of the
guide explains it. The test is in `commonTest`, so it runs on the JVM, as an
Android host test, and on the native targets of the host:

```bash
./gradlew :app-testing:allTests :app-testing:testReleaseUnitTest
```

## Contributing

[docs/CONTRIB.md](docs/CONTRIB.md) describes the layout, the build, the tests,
and the inner workings of the engine.
