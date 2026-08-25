---
title: Android
sidebar_position: 3
description: From nothing to an HTTP/3 request over SCION from an Android emulator.
---

This guide takes you from nothing to an Android app that sends an HTTP request over SCION. You do
**not** need access to a real SCION network, and you do not need to know anything about SCION yet.
Everything runs against a test network on your own machine.

The SDK reaches Android as a prebuilt AAR, so your own build needs no Rust toolchain and no NDK.

By the end you will have an app with one button that sends `GET /hello` over HTTP/3 and shows what
came back.

## Prerequisites

- **Android Studio**, and an **x86_64 emulator** on API 24 or later.
- **JDK 17**.
- **Rust**, for the test network alone. The SDK pins its toolchain in `rust-toolchain.toml`, so if
  you have [`rustup`](https://rustup.rs/) installed the right version is fetched automatically.
- **git**, to clone the repository.

Your app needs none of the Rust side: it depends on the AAR and nothing else.

## Start a local SCION network

`scion-h3-test-server` is a whole SCION network in one process, with an HTTP/3 server inside it.
Clone the SDK and start it:

```bash
git clone https://github.com/Anapaya/scion-sdk.git
cd scion-sdk
cargo run -p scion-h3-test-server -- \
    --underlay snap --advertise-ip 10.0.2.2 --control-port 7443
```

It prints one line of JSON describing everything a client needs, and then runs until its standard
input closes:

```text
{"endhost_api_url":"http://10.0.2.2:35395/","auth_token":"eyJ0eXAiOiJKV1Qi...",
 "base_url":"https://localhost:41013","target":"2-ff00:0:212,127.0.0.1",
 "ca_pem":"-----BEGIN CERTIFICATE-----\n...","control_url":"http://127.0.0.1:7443",
 "underlay":"snap"}
```

Five of those fields are what an app has to know:

- `endhost_api_url` is where a client discovers its SCION connectivity.
- `auth_token` authenticates it there.
- `base_url` is where the HTTP/3 server is.
- `target` is that server's SCION address, without a port.
- `ca_pem` is the authority that signed the certificate the server presents.

## Add the SDK to your app

Starting with release `v0.7.0`, every [release](https://github.com/Anapaya/scion-sdk/releases)
carries `scion-http3-android-<version>-maven.zip`, a Maven repository holding the library and its
POM. Unpack it anywhere and name that directory as a repository:

```kotlin
repositories {
    maven { url = uri("libs/maven") }
}

dependencies {
    implementation("com.anapaya.scion:scion-http3-android:<version>")

    // Only for calling the library from a coroutine tied to the UI.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
```

The library brings the `INTERNET` and `ACCESS_NETWORK_STATE` permissions with it, so you declare
neither. Add `android:usesCleartextTraffic="true"` while you work against the test network, whose
control API is plain HTTP; the SCION request itself is HTTP/3 over QUIC and unaffected.

The library README covers the other ways to depend on it, and the sources jar and checksums each
release carries.

## Build a client

Build one client and keep it. A client owns the connections it establishes, so an app builds it once
and closes it when it is done:

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/HelloScion.kt#build-client" title="HelloScion.kt"
```

`endhostApi` is the setting that says which SCION network this app is on, and the only one that
changes between a test network and a real one. `build()` does no I/O: the first request is what
brings connectivity up.

The sample reads those five values from the test network's control API, in
[`LocalNetwork.kt`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/LocalNetwork.kt),
because the network chooses them when it starts. Your own app has them in its configuration
instead.

## Send your first request

A request is built, executed, and read:

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/HelloScion.kt#request" title="HelloScion.kt"
```

`target` is for a server that has no SCION address records to look up. It sets the address the
request is sent to and nothing else: the port and the name the certificate has to match still come
from the URL, so the URL stays truthful about where the request went. Call it more than once to
offer several addresses, which are then raced.

Run the app and press the button. You should see:

```text
200

world
```

That is a full SCION round trip: an HTTP/3 request from the emulator, across a SCION network, to a
server in a different autonomous system.

## Timeouts

The client above sets two limits. `connectTimeout` bounds establishing connectivity to an origin,
which on a first request includes discovering it. `requestTimeout` bounds a whole request, from
sending it to holding the body.

Raise or lower the second one for a single request with `requestTimeout` on the request builder,
for a call you know is slower than the rest. A limit that is passed arrives as `Timeout`, which
carries the phase it was in and the value it passed, so an app can report which limit stopped it
rather than guessing.

## Certificates

The client verifies the server's certificate, and `trust` decides against which authorities.

`TrustAnchors.systemDefault()` is the default, and it is what a server with a publicly trusted
certificate needs. It uses the device's own authorities and deliberately excludes ones a user has
installed.

`TrustAnchors.pinned(pem)` is for an internal authority, and is what the sample uses above. The only
reason the sample reads the PEM at run time is that the test network generates a fresh authority on
every run; an app ships its own, usually from `assets/`.

There is also `TrustAnchors.insecureNoVerify()`. It logs an error every time a client is built with
it, and it is only for testing. A real app should never use it!

## Handling errors

Every failure the client reports is a `ScionHttp3Exception`. The arms are a sealed hierarchy, so
a `when` covers them:

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/MainActivity.kt#errors" title="MainActivity.kt"
```

Two things are worth knowing before you write that `when`:

- **A non-2xx status is a response, not an exception.** It arrives with a code and a body.Exceptions
  are for requests that produced no response at all.
- **`isRetryable` says whether retrying can help.** The client does not retry for you, because
  only your app knows whether the request is safe to send twice.

Some arms carry what an app needs to act: `Connect` has the host and port it could not reach,
`Timeout` has the phase and the limit it passed, and `BodyTooLarge` has the limit, which is the one
you set with `maxResponseBody`.

## When the network changes

Nothing here is yours to handle. When the device moves between Wi-Fi and mobile data, the library
notices, rebuilds connectivity, and authenticates again. A request already in flight fails, and
`isRetryable` is true for it.

One case is worth naming: a VPN coming up or going down changes which addresses work without
changing the network the library sees. Call `reset()` when your app knows that happened.

If your SNAP token expires, renew it in place with `setAuthToken(refreshed)` rather than building a
new client. The next request picks it up and the connections already established survive.

## The client's lifetime

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/HelloScion.kt#lifetime" title="HelloScion.kt"
```

`close()` returns at once and leaves the shutdown to finish on its own, which is what an
`onDestroy` wants. `shutdown()` is the suspending form, for a process that must not exit until the
connections are gone.

Cancellation needs nothing special: cancel the coroutine, and the request is cancelled with it.

## Where to go next

- **The library README** —
  [`bindings/android/scion-http3-android/README.md`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/android/scion-http3-android)
  is the reference for the whole API, including request bodies, headers and trailers.
- **The concepts pages** — [addressing](concepts/addressing.md) explains what
  `2-ff00:0:212,127.0.0.1` means, and [transport underlays](concepts/transport-underlays.md)
  explains the `--underlay` option above.
- **The sample app** —
  [`bindings/android/hello-scion`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/android/hello-scion)
  is the app this page is built from, ready to run.

## Full sample

The complete class, for reference. It lives in the SDK repo at
[`bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/HelloScion.kt`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/HelloScion.kt).

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/HelloScion.kt#full-sample" title="HelloScion.kt"
```
