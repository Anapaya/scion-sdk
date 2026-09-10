---
title: iOS
sidebar_position: 2
description: From nothing to an HTTP/3 request over SCION from the iOS simulator.
---

This guide takes you from nothing to an iOS app that sends an HTTP request over SCION. You do
**not** need access to a real SCION network, and you do not need to know SCION yet. Everything runs
against a test network on your own Mac.

The SDK reaches iOS as a Swift package with a prebuilt binary XCFramework. The same package runs on
macOS 12 and later.

At the end you have an app with one button. The button sends `GET /hello` over HTTP/3 and shows the
response.

## Prerequisites

- **Xcode 16** or newer, with an iOS simulator runtime. The library runs on iOS 15 or later.
- **Rust**, for the test network only. The SDK pins its toolchain in `rust-toolchain.toml`. If you
  have [`rustup`](https://rustup.rs/), it gets the correct version for you.
- **git**, to clone the repository.

Your app does not need the Rust side. It depends on the package and on nothing else.

## Start a local SCION network

`scion-h3-test-server` is a whole SCION network in one process, with an HTTP/3 server inside it.
Clone the SDK and start it:

```bash
git clone https://github.com/Anapaya/scion-sdk.git
cd scion-sdk
cargo run -p scion-h3-test-server -- --control-port 7443
```

The simulator shares the network of your Mac, so the test network needs no options for it. An
address on the loopback interface of the Mac is the same address inside the simulator.

The server prints one line of JSON that describes everything a client needs. Then it runs until its
standard input closes:

```text
{"endhost_api_url":"http://127.0.0.1:35395/","auth_token":"eyJ0eXAiOiJKV1Qi...",
 "base_url":"https://localhost:41013","target":"2-ff00:0:212,127.0.0.1",
 "ca_pem":"-----BEGIN CERTIFICATE-----\n...","control_url":"http://127.0.0.1:7443",
 "underlay":"udp"}
```

An app has to know five of these fields:

- `endhost_api_url` is where a client discovers its SCION connectivity.
- `auth_token` authenticates the client there.
- `base_url` is where the HTTP/3 server is.
- `target` is the SCION address of that server.
- `ca_pem` is the authority that signed the certificate of the server.

## Add the SDK to your app

Every [release](https://github.com/Anapaya/scion-sdk/releases) carries the Swift package as
`scion-http3-swift-<version>.zip`. Its `Package.swift` names the XCFramework on the same release by
URL and checksum, and SwiftPM downloads it. Download the package zip and unpack it. In Xcode, choose
**File > Add Package Dependencies > Add Local...** and select the unpacked package. In a
`Package.swift`, the same dependency is:

```swift
dependencies: [
    .package(path: "libs/scion-http3-swift"),
],
targets: [
    .target(name: "App", dependencies: [.product(name: "ScionHTTP3", package: "scion-http3-swift")]),
]
```

`ScionHTTP3` is the one module you import. The XCFramework carries slices for iOS devices, the iOS
simulator and macOS, so the same package serves all three.

The client opens its own UDP sockets. App Transport Security does not govern these sockets, so the
SCION request needs no exception and no entitlement. Add `NSAllowsLocalNetworking` under
`NSAppTransportSecurity` while you work against the test network. The control API of the test
network is plain HTTP.

The library README covers the other ways to depend on the library.

## Build a client

Build one client and keep it. A client owns the connections it establishes. An app builds the
client once and shuts it down when the app is done:

```swift reference="@sdk/bindings/apple/hello-scion/HelloScion/HelloScion.swift#build-client" title="HelloScion.swift"
```

`endhostApi` is the setting that says which SCION network this app is on. The initializer does no
I/O. The first request is what brings connectivity up. The initializer throws
`ScionHttp3Error.invalidConfiguration` for a setting that cannot be correct, for example a timeout
that is not positive.

The sample reads the five values from the control API of the test network, in
[`LocalNetwork.swift`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/apple/hello-scion/HelloScion/LocalNetwork.swift),
because the network selects them when it starts. Your own app has them in its configuration.

## Send your first request

A request is a value. Build it, execute it, and read the response:

```swift reference="@sdk/bindings/apple/hello-scion/HelloScion/HelloScion.swift#request" title="HelloScion.swift"
```

`target` is for a server that has no SCION address records. It sets the address the client sends
the request to, and nothing else. The port and the name that the certificate must match still come
from the URL. To offer several addresses, set `targets` instead. The client then races them.

Run the app and press the button. You see:

```text
200

world
```

That is a full SCION round trip: an HTTP/3 request from the simulator, across a SCION network, to a
server in a different SCION AS.

## Timeouts

The client above sets two limits, in seconds. `connectTimeout` limits the time to establish
connectivity to an origin. On a first request, this includes the discovery of the origin.
`requestTimeout` limits a whole request, from the send to the receipt of the body.

To change the second limit for one request, set `requestTimeout` on the request. This is for a call
that you know is slower than the rest. A passed limit arrives as `.timeout`. This error carries the
phase it was in and the value it passed, so an app can report which limit stopped the request.

## Certificates

The client verifies the certificate of the server. `trust` decides which authorities it verifies
against.

`TrustAnchors.systemDefault` is the default. It is what a server with a publicly trusted certificate
needs. It checks the certificate the way `URLSession` does, against the authorities of the system
and with the policy of the system. This includes authorities that the user or a device profile
installed and trusted.

`TrustAnchors.pinned(pem)` is for an internal authority. The sample above uses it. It throws
`invalidConfiguration` if the bundle holds no certificate. The sample reads the PEM at run time
only because the test network generates a new authority on every run. An app ships its own PEM,
usually as a bundle resource.

There is also `TrustAnchors.insecureNoVerify`. It logs an error every time a client is built with
it, and it is only for tests. A real app must never use it!

## Handling errors

Every failure the client reports is a `ScionHttp3Error`. It is an enum, so a `switch` covers it:

```swift reference="@sdk/bindings/apple/hello-scion/HelloScion/ContentView.swift#errors" title="ContentView.swift"
```

Know three things before you write that `switch`:

- **A non-2xx status is a response, not an error.** It arrives with a code and a body. Errors are
  for requests that produced no response.
- **`isRetryable` says whether a retry can help.** The client does not retry for you, because only
  your app knows whether the request is safe to send twice.
- **A cancelled request throws `CancellationError`**, as every cancelled task does. It never throws
  one of these cases.

Some cases carry what an app needs to act. `.connect` has the host and the port the client could
not reach. `.timeout` has the phase and the limit it passed. `.bodyTooLarge` has the limit, which is
the one you set with `maxResponseBodyBytes`. Every case has `detail`, the underlying failure for a
log.

One case is not obvious. A certificate that the pinned anchors reject arrives as `.connect`,
because the handshake fails before the client learns the cause. A certificate that the system
rejects arrives as `.tls`.

## Cancelling a request

Requests are ordinary `async` functions, so cancellation needs nothing from the library. Cancel the
`Task` that awaits the request. The library then cancels the request, down to the HTTP/3 stream.
This test from the SDK shows it against the test network:

```swift reference="@sdk/bindings/apple/scion-http3-swift/Tests/ScionHTTP3HostTests/FacadeCancellationTests.swift#cancel" title="FacadeCancellationTests.swift"
```

The helpers around it belong to the test. `facadeRequest` builds a request like the one above.
`assertCancelled` checks that the call threw `CancellationError`. `assertHelloWorks` sends a request
over the same connection afterwards. That last line is what matters: the connection stays usable,
so a cancelled request does not slow down the next one.

## When the network changes

You do not have to handle a network change. When the device moves between Wi-Fi and cellular, the
library notices the change, rebuilds connectivity, and authenticates again. A request that is in
flight fails, and `isRetryable` is true for it. If the app was suspended during the change, the
first request after a long idle gap checks the network itself.

One case needs your help. A VPN that comes up or goes down changes which addresses work, but it
does not change the network the library sees. Call `reset()` when your app knows that this
happened.

If your SNAP token expires, renew it in place with `setAuthToken(refreshed)`. Do not build a new
client. The next request uses the new token, and the established connections survive.

## What this version does not do

- **No `URLSession` or Alamofire drop-in.** `URLSession` has no pluggable transport. Its one hook,
  `URLProtocol`, hides the transport behind an interface for HTTP/1, so an adapter on it cannot
  expose what HTTP/3 over SCION offers. Such an adapter is a possible later module. Alamofire sits
  on `URLSession`, so the same applies.
- **No background transfers.** A background `URLSession` hands its transfers to a system process
  that runs while the app does not, and that process speaks only the transports of the system.
  SCION is not one of them, so a transfer here runs while the app runs.

## The client's lifetime

```swift reference="@sdk/bindings/apple/hello-scion/HelloScion/HelloScion.swift#lifetime" title="HelloScion.swift"
```

`shutdown()` waits until each connection has told its peer that it closes. A request issued after
it fails with `.closed`. It is idempotent. A client that is dropped without `shutdown()` still
closes its connections, but in the background and whenever ARC releases the client. Do not rely on
that where the timing matters.

The sample never calls `shutdown()`, because its client lives as long as the app. Call it when your
app is done with a client before then, for example on sign-out.

## Where to go next

- **The library README** —
  [`bindings/apple/scion-http3-swift/README.md`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/apple/scion-http3-swift)
  is the reference for the whole API, including request bodies, headers and trailers.
- **The concepts pages** — [addressing](../concepts/addressing.md) explains what
  `2-ff00:0:212,127.0.0.1` means, and [transport underlays](../concepts/transport-underlays.md)
  explains the `underlay` field above.
- **The sample app** —
  [`bindings/apple/hello-scion`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/apple/hello-scion)
  is the app this page is built from, ready to run.

## Full sample

The complete class, for reference. It lives in the SDK repo at
[`bindings/apple/hello-scion/HelloScion/HelloScion.swift`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/apple/hello-scion/HelloScion/HelloScion.swift).

```swift reference="@sdk/bindings/apple/hello-scion/HelloScion/HelloScion.swift#full-sample" title="HelloScion.swift"
```
