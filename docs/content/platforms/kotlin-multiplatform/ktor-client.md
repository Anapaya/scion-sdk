---
title: Ktor client
sidebar_position: 1
description: From nothing to a Ktor request over SCION in a Kotlin Multiplatform project.
---

This guide takes you from nothing to a Ktor client that sends HTTP requests over SCION. You do
**not** need access to a real SCION network, and you do not need to know SCION yet. The first
request runs in a test, against a SCION network in the test process.

`ScionHttp` is a Ktor engine. Your app keeps its Ktor code: the requests, the plugins, and the
serialization stay the same. Only the engine changes. The same engine runs on Android, on iOS, and
on the JVM.

## Prerequisites

- **Kotlin**, with the version of the engine release or a newer one. The `kotlin` entry in
  `bindings/kmp-ktor-engine/gradle/libs.versions.toml` at the release tag gives that version. An
  older compiler cannot read the klibs of the engine.
- **JDK 17** or newer.
- **The Android SDK**, for the Android target.
- **A Mac with Xcode**, for the iOS targets.

Your project needs no Rust toolchain. The artifacts contain the native code of the engine.

## Targets

| Target              | Native code                                            |
| ------------------- | ------------------------------------------------------ |
| Android             | arm64-v8a, armeabi-v7a, x86, x86-64                    |
| `iosArm64`          | iOS devices                                            |
| `iosSimulatorArm64` | the iOS simulator on Apple Silicon                     |
| JVM                 | macOS arm64, and Linux x86-64 with glibc 2.28 or later |

The JVM target serves desktop apps, servers, and Android host tests. It has no library for
Windows. For Windows and for the other Kotlin/Native targets, build the engine from source. The
[engine README](https://github.com/Anapaya/scion-sdk/tree/main/bindings/kmp-ktor-engine) tells you
how.

## Add the engine to your project

Maven Central has the engine. The engine has the version of the SDK: the SDK release `vX.Y.Z`
publishes the engine version `X.Y.Z`. Add the engine to `commonMain`, and the test network to
`commonTest`:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/tests/consumer/build.gradle.kts#dependencies" title="build.gradle.kts"
```

- `sdkVersion` is the SDK version.
- `ktor-client-scion-testing` is the SCION network for the tests. Your app does not ship it.
- The `androidHostTest` and `androidDeviceTest` blocks are for the Android tests.
  [Testing your app](testing.md#where-the-tests-run) explains them.

This build file is from `tests/consumer`, an app that CI builds against the artifacts of each
release.

## Send your first request

`ktor-client-scion-testing` runs a SCION network in the test process. The network has two
autonomous systems (ASes), and an HTTPS server with a test API. Write this test in `commonTest`:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/tests/consumer/src/commonTest/kotlin/net/anapaya/ktor/scion/consumer/ConsumerTest.kt#first-request" title="ConsumerTest.kt"
```

- `useTestNetwork(network)` attaches the engine to the network. It sets the endhost API, a token,
  and the SCION address of `localhost`.
- `caCertificatesPem` makes the engine trust the CA of the test API. Each network creates a new
  CA.

Run the test on the JVM:

```bash
./gradlew jvmTest
```

The test passes. That is a full SCION round trip: an HTTP/3 request from the engine, across a SCION
network, to a server in a different AS. The same test also runs as an Android host test, on the iOS
simulator, and on an Android device. [Testing your app](testing.md) shows how.

## Connect to the SCION network

On the SCION network, the engine authenticates with an API key. To get an API key, fill out the form
in [Get an API key](../../concepts/access-and-authentication.md#get-an-api-key).

The sample `hello-scion` configures the engine with an API key:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/hello-scion/src/commonMain/kotlin/net/anapaya/ktor/scion/sample/Main.kt#engine-config" title="Main.kt"
```

- `ScionTokenSource.AnapayaAa` sends the API key to the Anapaya AA, and gets a SNAP token. It
  renews the token before the token expires. Its `url` selects a different AA. That URL is the HTTPS
  URL of the AA, not a SCION address. [Access and
  authentication](../../concepts/access-and-authentication.md) explains the AA and the tokens.
- `endhostApiUrl` sets a fixed endhost API. If it is `null`, the engine discovers the endhost APIs:
  through the URL that the AA sends with the token, or else through the global discovery service.
  See [the endhost API](../../concepts/endhost-api.md).
- The `webGateway` and `dnsOverride` lines send the requests through a WebGateway.
  [WebGateway](webgateway.md) explains them.

`runSample` gives this configuration to the engine, and builds the client:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/hello-scion/src/commonMain/kotlin/net/anapaya/ktor/scion/sample/Sample.kt#build-client" title="Sample.kt"
```

Build one client and keep it. A client owns its SCION connectivity and its connections. The first
request brings up the connectivity, so it takes longer than the next requests.

## How the engine finds the origin

The origin needs a SCION address. The engine resolves the host of the request URL in one of two
ways:

- **TSAR** (TXT-based SCION Address Resolution). A DNS TXT record of the host holds its SCION
  address.
- **`dnsOverride(host, addresses)`** sets the SCION addresses of a host in the app. Use it for a
  host without a TSAR record. Each address has the form `<ISD>-<AS>,<IP>`, for example
  `1-ff00:0:110,192.0.2.10`, without brackets and without a port. With several addresses, the
  engine starts an attempt to each address, with the delay `connectionAttemptDelayMillis` between
  the attempts.

The port and the name that the certificate must match come from the request URL.
[Addressing](../../concepts/addressing.md) explains SCION addresses.

## Engine settings

`ScionEngineConfig` has these settings. A setting that you do not set keeps the default of the
engine.

| Setting                         | What it does                                                        |
| ------------------------------- | ------------------------------------------------------------------- |
| `tokenSource`                   | Where the engine gets its token. Without it, the engine sends none. |
| `endhostApiUrl`                 | A fixed endhost API. Without it, the engine discovers one.          |
| `preferredUnderlay`             | `ScionUnderlay.Udp` (the default) or `ScionUnderlay.Snap`.          |
| `webGateway`                    | Sends each request through a WebGateway.                            |
| `dnsOverride(host, addresses)`  | Sets the SCION addresses of a host.                                 |
| `caCertificatesPem`             | The CAs for the origin certificates, as a PEM bundle.               |
| `controlPlaneCaCertificatesPem` | The CAs for the AA, the discovery service, and the control plane.   |
| `acceptInvalidCertificates`     | Turns off the origin certificate checks. Use it for tests only.     |
| `connectTimeoutMillis`          | The time for the name resolution and the connection to an origin.   |
| `requestTimeoutMillis`          | The time for a whole request.                                       |
| `idleConnectionTimeoutMillis`   | The time that an idle connection stays open.                        |
| `maxOrigins`                    | The number of origins that the engine keeps a connection to.        |
| `connectionAttemptDelayMillis`  | The delay between the attempts to the addresses of one origin.      |
| `maxResponseBodyBytes`          | The largest response body. The default is 16 MiB.                   |

The engine rejects a time or a number that is 0 or less. Only `connectionAttemptDelayMillis` accepts
0: then all attempts start at the same time. The engine reads the settings once, when the client
starts. The Ktor setting `proxy` has no effect.

## Certificates

The engine checks the certificate of the origin. If `caCertificatesPem` is `null`, the engine uses
the platform verifier, which trusts the CAs of the device. To trust an internal CA, set
`caCertificatesPem` to its PEM.

On Android, the platform verifier has these properties:

- It trusts the system CAs and the user CAs. The Network Security Config of the app has no effect
  on it, so the config cannot remove the user CAs or pin a certificate.
- It checks if an origin certificate is revoked. If the certificate has no OCSP URL, Android gets
  the CRL of the CA over plain HTTP. If the Network Security Config of the app blocks plain HTTP to
  the CRL host, the request fails with `Revoked`, also for a valid certificate. To prevent this,
  allow plain HTTP to the CRL hosts of the CAs of your origins. The Android component of
  `rustls-platform-verifier` publishes a config with all known CRL hosts.
- The engine starts the verifier through `ScionTrustProvider`, a content provider in the manifest of
  the library. An app that removes the provider cannot use the engine.

The AA, the discovery service, the endhost API, and the control plane use their own CAs:
`controlPlaneCaCertificatesPem`. On Android, the default is the Mozilla root set in the library,
without a revocation check. So these connections do not depend on the Network Security Config of
the app, and the user CAs do not apply to them. On the other platforms, the default is the platform
verifier.

## Timeouts

- `connectTimeoutMillis` limits the name resolution and all connection attempts to an origin. On
  the first request, it also includes the discovery. If the time passes, the request fails with the
  Ktor `ConnectTimeoutException`.
- `requestTimeoutMillis` limits a whole request. The `requestTimeoutMillis` of the Ktor
  `HttpTimeout` plugin replaces it for each request. If the time of the plugin passes, the request
  fails with the Ktor `HttpRequestTimeoutException`.

## Errors

A status that is not 2xx is a response, not an exception. An exception means that the request got
no response.

The engine reports a failure as a `ScionEngineException`, which is an `IOException`. Its `cause` is
a `CoreException`, from the package `uniffi.ktor_scion_core`, and names the kind of the failure:

| Kind              | Meaning                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------- |
| `InvalidArgument` | The engine rejected a setting or a request.                                                 |
| `Connectivity`    | The engine cannot build its SCION connectivity, for example with a bad API key.             |
| `Resolution`      | The engine cannot resolve the host to a SCION address.                                      |
| `Connect`         | The engine cannot connect to the origin. Over HTTP/3, this includes a rejected certificate. |
| `Tls`             | The TLS handshake in a WebGateway tunnel failed, for example because of the certificate.    |
| `Timeout`         | The request took longer than `requestTimeoutMillis`.                                        |
| `Protocol`        | The HTTP exchange failed.                                                                   |
| `BodyTooLarge`    | The response body is larger than `maxResponseBodyBytes`.                                    |
| `Closed`          | The client is closed.                                                                       |
| `Cancelled`       | The request was cancelled.                                                                  |
| `Internal`        | A failure inside the engine.                                                                |

The two timeouts above are the exceptions to this rule. They arrive as the Ktor timeout exceptions.

## The lifetime of the client

- Close the client when your app does not need it anymore, with `close()` or with `use`, as the
  samples do.
- If you cancel the coroutine of a request, the engine stops the request and resets its HTTP/3
  stream.
- A token from `ScionTokenSource.Static` stays for the life of the client. A new token needs a new
  client. Use `Static` for tests only. The token from `ScionTokenSource.AnapayaAa` renews itself.

## Limits

- The engine keeps each body in memory. It does not stream a body, in either direction.
  `maxResponseBodyBytes` limits a response body.
- The engine has no WebSocket, no server-sent events, no protocol upgrade, and no `CONNECT` tunnel
  for the app.
- The engine follows no redirects. The Ktor `HttpRedirect` plugin follows them.
- The engine drops the trailers of a response.

## Where to go next

- **[WebGateway](webgateway.md)** sends the requests to an HTTP API that has no SCION address of its
  own.
- **[Testing your app](testing.md)** tests your app over SCION on each platform.
- **The concepts pages** explain [the endhost API](../../concepts/endhost-api.md),
  [addressing](../../concepts/addressing.md), and
  [transport underlays](../../concepts/transport-underlays.md).
- **The engine README** at
  [`bindings/kmp-ktor-engine`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/kmp-ktor-engine)
  shows how to build the engine from source, and how to run the samples.
