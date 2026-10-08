# ktor-client-scion

A Ktor `HttpClientEngine` that sends HTTP over SCION: HTTP/3 to the origin, or
HTTP/1.1 through a WebGateway.

Status: preview. The API can change between releases.

## Platforms

The engine targets Linux, Windows, the JVM, Android, iOS, and macOS.
[docs/build.md](docs/build.md) describes the state per platform and the
artifacts.

## Install

The artifacts are not on Maven Central yet. Build them into a Maven
repository in `build/repository`:

```bash
./gradlew publishAllPublicationsToLocalBuildRepository
```

The build needs the tools in [Tools per host](docs/build.md#tools-per-host).
The repository only contains the targets that the build host can build.
[Results per platform](docs/build.md#results-per-platform) lists the targets per host.

Add the repository to your project:

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

Then add the engine as a dependency:

```kotlin
implementation("net.anapaya.ktor:ktor-client-scion:0.1.0")
```

Alternatively, `./gradlew publishToMavenLocal` writes to `~/.m2/repository`.
Then use `mavenLocal()` in place of the `maven(url = ...)` line.

## Use

The engine is a Ktor `HttpClientEngine` that sends HTTP over SCION. So it can be
initialized drop-in in a Ktor `HttpClient`:

```kotlin
val client = HttpClient(ScionHttp) {
    engine { tokenSource = ScionTokenSource.AnapayaAa(apiKey = key) }
}

val response = client.get("https://example.org/")
```

With `ScionTokenSource.AnapayaAa`, the client gets a SNAP token from the
Anapaya AA and renews it before it expires. The token authenticates with the
endhost API and the SNAP control plane.

If the AA answer carries an endhost API discovery URL, the client discovers
its endhost APIs there. Otherwise, it uses the global discovery service.

`endhostApiUrl` replaces discovery with one fixed endhost API.
`ScionTokenSource.Static` replaces the AA with a fixed token.

`ScionEngineConfig` lists every engine setting.

If you cancel the coroutine of a request, the engine aborts the request and
resets its HTTP/3 stream.

## Transports

The engine has two transports:

| Transport  | Setting      | Wire                                                                                      |
| ---------- | ------------ | ----------------------------------------------------------------------------------------- |
| HTTP/3     | default      | HTTP/3 over QUIC over SCION, to the origin                                                |
| WebGateway | `webGateway` | HTTP/1.1 over TLS, inside an HTTP/3 `CONNECT` tunnel over SCION to a PathGuard WebGateway |

```kotlin
val client = HttpClient(ScionHttp) {
    engine {
        tokenSource = ScionTokenSource.AnapayaAa(apiKey = key)
        webGateway = ScionWebGateway()
    }
}
```

The gateway is transparent. TSAR (TXT-based SCION Address Resolution)
publishes the SCION address of a host as a DNS TXT record. The engine
resolves the request host through TSAR and expects the gateway at that
address, on port 443 by default (`ScionWebGateway(port = ...)`).

The engine opens the tunnel with `CONNECT <request host>:<request port>`. It
does not check the certificate of the gateway.

The gateway selects the backend by that authority and connects the tunnel to it
over TCP.

TLS to the origin runs end to end inside the tunnel.
`caCertificatesPem` and the platform verifier apply to that TLS session.

## Testing an app

`ktor-client-scion-testing` runs a PocketSCION topology in the test process,
on the JVM and on the native targets:

```kotlin
testImplementation("net.anapaya.ktor:ktor-client-scion-testing:0.1.0")
```

```kotlin
ScionTestNetwork.start {
    gatewayBackend("api.example.com", "127.0.0.1:8080")
}.use { network ->
    val client = HttpClient(ScionHttp) {
        engine { useTestNetwork(network, "api.example.com") }
    }
}
```

`useTestNetwork` sets `endhostApiUrl`, `tokenSource`, and DNS overrides to the
server AS. It does not set `caCertificatesPem`, because your app's server has
its own CA.

The topology reaches your app's server in one of two ways:

| Transport  | Your app's server                                                                                                       |
| ---------- | ----------------------------------------------------------------------------------------------------------------------- |
| HTTP/3     | opens a SCION socket in AS 2-ff00:0:212 with `serverEndhostApiUrl` and `authToken`. It gets the address `serverAddress` |
| WebGateway | listens on TCP. `gatewayBackend` maps the `CONNECT` authority to it. Set `ScionWebGateway(port = network.gatewayPort)`  |

[`samples/app-testing`](samples/app-testing) shows the WebGateway case: a
Ktor server on TCP as the API of the app, and a test that sends requests to it
over SCION. The test is in `commonTest`, so it runs on the JVM and on the
native targets of the host: `./gradlew :app-testing:allTests`.

The built-in server also serves a test API at `testApiUrl`, with the CA
`testApiCaPem`.

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

### Android app

The Android app (`./gradlew :hello-scion:installRelease`) has three fields: the
endhost API URL, the AA API key, and the request URL. The app saves them
between launches. It trusts the system and user CAs of the device, for the
origin, the AA, and the control plane. If the endhost API field is empty,
the app discovers the endhost APIs.

If the API key field is empty, the app starts a `ScionTestNetwork` in its own
process on the first run, and sends the requests to its test API. This needs
no server on the host. It works on an emulator and on a device.

## Limits

- The engine buffers each body in memory. No streaming yet, in either
  direction. `maxResponseBodyBytes` bounds a response body, 16 MiB by default.
- No WebSocket, no SSE, no protocol upgrade, no `CONNECT` tunnel for the app.
- `HttpClientEngineConfig.proxy` has no effect.
- The engine follows no redirects. The Ktor `HttpRedirect` plugin does.
- The engine drops response trailers.
- On Android, the platform verifier trusts the system CAs and the user CAs.
  It ignores the Network Security Config of the app, so the config cannot
  remove the user CAs or pin a certificate. The library initializes the
  verifier through `ScionTrustProvider`, a content provider in its manifest.
  An app that removes the provider cannot use the engine.
- A `ScionTokenSource.Static` token stays for the life of the client. A new
  token needs a new client. The AA token from `ScionTokenSource.AnapayaAa`
  renews itself.

## Contributing

[docs/CONTRIB.md](docs/CONTRIB.md) describes the layout, the build, the tests,
and the inner workings of the engine.
