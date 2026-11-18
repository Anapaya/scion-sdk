---
title: Testing your app
sidebar_position: 3
description: Test a Ktor app over SCION, with a SCION network in the test process.
---

import ApiBehindGateway from './fig/api-behind-gateway.drawio.svg';

`ktor-client-scion-testing` starts a SCION network in the test process. Your tests send real
requests over SCION, but they need no SCION network, no server, and no Rust toolchain. The same test
runs on the JVM, as an Android host test, on the iOS simulator, and on an Android device.

[Add the engine to your project](ktor-client.md#add-the-engine-to-your-project) adds the library to
`commonTest`.

## The test network

`ScionTestNetwork.start()` starts a PocketSCION topology, and returns when the topology serves:

- **AS `1-ff00:0:132`** is for the client. The engine attaches to it.
- **AS `2-ff00:0:212`** is for the servers. A built-in server in this AS serves a test API, and
  plays a WebGateway. Your own server can also attach to this AS.

Each network has its own ports, its own token, and its own CA, so the tests can run at the same
time. `close()` stops the network. The garbage collector also stops a network that nothing refers
to, so keep a reference while your tests use it.

The network gives you these values:

| Value                 | What it is                                                       |
| --------------------- | ---------------------------------------------------------------- |
| `testApiUrl`          | `https://localhost:<port>`, the test API of the built-in server. |
| `testApiCaPem`        | The CA of the test API.                                          |
| `gatewayPort`         | The port of the gateway, for `ScionWebGateway(port = ...)`.      |
| `endhostApiUrl`       | The endhost API of the client AS.                                |
| `serverEndhostApiUrl` | The endhost API of the server AS, for your own server.           |
| `authToken`           | The token for both endhost APIs and the control plane.           |
| `serverAddress`       | The SCION address of a server in the server AS on this host.     |

By default, the client and the server reach their AS over UDP, through a router. With
`ScionTestNetwork.start { underlay = ScionUnderlay.Snap }`, they use a SNAP instead.

## Attach the engine

`useTestNetwork(network)` in the engine block attaches the engine to the network:

- It sets `endhostApiUrl` and a static token.
- It sets the SCION address of `localhost`, and of each host of a gateway backend, to
  `serverAddress`. To add other hosts, give them as more arguments:
  `useTestNetwork(network, "api.example.com")`.

It does not set `caCertificatesPem`, because your server has its own CA. For the test API, set it to
`testApiCaPem`, as the [first request](ktor-client.md#send-your-first-request) does.

## Test an API behind a gateway

In production, many APIs stay on TCP behind a WebGateway. The sample `app-testing` tests the API
client from the [WebGateway](webgateway.md) page in the same way. The test runs the API on TCP, and
the network connects the gateway to it:

<ApiBehindGateway
  className="svg-diagram"
  role="img"
  aria-label="A tunnel from the client over two ASes to the gateway, and TCP to the API"
/>

First, the test starts the API on a free port:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/app-testing/src/commonTest/kotlin/net/anapaya/ktor/scion/sample/testing/GreetingApiTest.kt#api-server" title="GreetingApiTest.kt"
```

Then it starts the network. `gatewayBackend` connects each tunnel for the API host to the API:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/app-testing/src/commonTest/kotlin/net/anapaya/ktor/scion/sample/testing/GreetingApiTest.kt#network" title="GreetingApiTest.kt"
```

The client attaches to the network, and sends each request through the gateway:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/app-testing/src/commonTest/kotlin/net/anapaya/ktor/scion/sample/testing/GreetingApiTest.kt#client" title="GreetingApiTest.kt"
```

The test calls the API client of the app, and gets its answer over SCION:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/app-testing/src/commonTest/kotlin/net/anapaya/ktor/scion/sample/testing/GreetingApiTest.kt#test" title="GreetingApiTest.kt"
```

Compare the client in the test with the production client: the test network replaces the AA and
the TSAR record, and the gateway listens on `gatewayPort`, not on 443. The API client of the app
stays the same.

## Test an HTTP/3 server

Your own SCION server can attach to the server AS. It opens a SCION socket with
`serverEndhostApiUrl` and `authToken`, and gets the address `serverAddress`. To send the requests of
the engine to it, give its host to `useTestNetwork`, and set `caCertificatesPem` to the CA of your
server.

## Where the tests run

| Platform          | Gradle task                                             | Notes                                                       |
| ----------------- | ------------------------------------------------------- | ----------------------------------------------------------- |
| JVM               | `jvmTest`                                               | On macOS arm64 and on Linux x86-64.                         |
| Android host test | `testAndroidHostTest`, or `testReleaseUnitTest`         | Needs the setup below.                                      |
| iOS simulator     | `iosSimulatorArm64Test`                                 | On a Mac.                                                   |
| Android device    | `connectedAndroidDeviceTest`, or `connectedAndroidTest` | Needs the setup below. The network runs in the app process. |

`testAndroidHostTest` and `connectedAndroidDeviceTest` are the task names with the plugin
`com.android.kotlin.multiplatform.library`. With `com.android.library`, the host test task has the
name of the build variant, for example `testReleaseUnitTest`, and the device test task is
`connectedAndroidTest`.

### Android host tests

An Android host test runs on the desktop JVM of your computer or your CI. But it gets the Android
artifacts of the engine, which contain only the Android libraries. Without more setup, the test
fails with:

```text
java.lang.UnsatisfiedLinkError: Unable to load library 'ktor_scion_testing'
```

To fix this, add the JVM artifacts to the host test. They contain the desktop libraries for macOS
arm64 and Linux x86-64. Use the same version as for the engine:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/tests/consumer/build.gradle.kts#android-host-test" title="build.gradle.kts"
```

With the plugin `com.android.library`, the source set has the name `androidUnitTest`, not
`androidHostTest`.

### Android device tests

With the plugin `com.android.kotlin.multiplatform.library`, a device test runs only the tests in
`androidDeviceTest`, not the tests in `commonTest`. To run `commonTest` on a device, set the source
set tree of the device test to `test`, and set the AndroidX test runner:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/tests/consumer/build.gradle.kts#android-library" title="build.gradle.kts"
```

The device test also needs the dependency on the runner:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/tests/consumer/build.gradle.kts#android-device-test" title="build.gradle.kts"
```

The test network runs in the process of the test app on the device. So the device test needs no
setup on the computer, and it works on an emulator and on a phone.

With the plugin `com.android.library`, set
`instrumentedTestVariant.sourceSetTree.set(KotlinSourceSetTree.test)` in `androidTarget`, and
`testInstrumentationRunner` in `defaultConfig`.

## Where to go next

- **The sample `app-testing`** at
  [`bindings/kmp-ktor-engine/samples/app-testing`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/kmp-ktor-engine/samples/app-testing)
  is the test of this page, ready to run.
- **The app `tests/consumer`** at
  [`bindings/kmp-ktor-engine/tests/consumer`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/kmp-ktor-engine/tests/consumer)
  has the Gradle setup of this page, with the plugin `com.android.kotlin.multiplatform.library`.
