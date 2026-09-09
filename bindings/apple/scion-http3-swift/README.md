# SCION HTTP/3 for Swift

An HTTP client for iOS and macOS that sends its requests over [SCION](https://scion.org) instead of
the public internet's routing, speaking HTTP/3 end to end.

If you have used `URLSession`, this will look familiar: build a client once, build a request value,
execute it, read the response.

```swift
import ScionHTTP3

let client = try ScionHttp3Client(
    endhostApi: "https://endhost-api.example.org",
    authToken: token)

let rooms = try await client.get("https://chat.example.org/rooms").body.string()
```

## Adding it

Every [release](https://github.com/Anapaya/scion-sdk/releases) carries the Swift package with a
binary XCFramework, and `Package.swift` points at that release:

```swift
dependencies: [
    .package(url: "https://github.com/Anapaya/scion-http3-swift", from: "<version>"),
],
targets: [
    .target(name: "App", dependencies: [.product(name: "ScionHTTP3", package: "scion-http3-swift")]),
]
```

Requirements: iOS 15 or macOS 12, Xcode with Swift 6. The XCFramework carries slices for iOS devices
(arm64), the iOS simulator (arm64 and x86_64) and macOS (arm64 and x86_64). No entitlements are
needed: the client opens its own UDP sockets, which App Transport Security does not govern.

## Your first request against a local network

You do not need access to a real SCION network to try this. PocketSCION is a whole SCION network in
one process, and the iOS simulator shares your machine's network, so it reaches one running on your
machine at `127.0.0.1` directly.

```bash
cargo run -p scion-h3-test-server -- --control-port 7443
```

The server prints one line of JSON with everything a client needs: `endhost_api_url`, `auth_token`,
`base_url`, `target`, and `ca_pem`. The same JSON is served on `http://127.0.0.1:7443/info`, which
is how an app on the simulator can read it.

```swift
var configuration = ScionHttp3Client.Configuration(
    endhostApi: info.endhostApiUrl,          // http://127.0.0.1:<port>
    authToken: info.authToken)
configuration.trust = try .pinned(Data(info.caPem.utf8))
let client = try ScionHttp3Client(configuration: configuration)
```

Everything else is the same as against a real network. That is the point of `endhostApi` being the
only setting that changes: it is what tells the client where to find SCION connectivity.

A server on a local topology has no address records to look up, so address it directly:

```swift
var request = ScionHttp3Request(url: info.baseUrl + "/hello")   // https://localhost:<port>/hello
request.target = try ScionAddress(info.target)                   // 1-ff00:0:212,127.0.0.1
let response = try await client.execute(request)
print(response.code, try await response.body.string())           // 200 world
```

If your token expires, renew it in place rather than building a new client:

```swift
try client.setAuthToken(refreshed)
```

Connectivity is rebuilt whenever the network changes and each rebuild authenticates again, so a
token set once at construction eventually stops being accepted. A renewal is picked up by the next
request and keeps the connections already established. A client built without a token cannot be
given one later, so build it once you have one.

## Requests and responses

```swift
var request = ScionHttp3Request(url: "https://chat.example.org/messages")
request.method = .post
request.body = .json(#"{"room":"general","text":"hi"}"#)
request.headers.add("authorization", "Bearer \(token)")
request.requestTimeout = 60

let response = try await client.execute(request)
if response.isSuccessful {
    let body = try await response.body.string()
}
```

A non-2xx status is a response, not an error. Errors are for requests that produced no response at
all.

Requests are values. Change one and send it again. A copy already sent is not affected. The body's
media type goes out as `content-type` unless you set that header yourself. A URL that is not
`https`, a method that is not a token, or a header line HTTP cannot carry fails the request with
`ScionHttp3Error.invalidRequest` before anything is sent.

The body's accessors are `async` and the body is a class, because both will matter when bodies
stream. In the current version the whole body is in hand when the response returns.

`client.get(url)` and `client.post(url, body:)` are shorthands for the common two.

## Cancellation and the client's lifetime

Requests are ordinary `async` functions. Cancel the `Task` and the request is cancelled, all the way
down to the HTTP/3 stream. The connection stays usable for the next one. The cancelled call throws
`CancellationError`.

```swift
let task = Task { try await client.get(url) }
task.cancel()   // the request stops, nothing is left behind
```

Build one client and keep it. It holds the connections your requests reuse. Building it costs
nothing. The first request is what establishes connectivity.

Shut it down when the application is done with it, which also stops it watching for network changes:

```swift
await client.shutdown()
```

`shutdown()` lets each connection tell its peer it is going away. A client that is dropped without
it still closes its connections, but in the background and whenever ARC gets to it, so do not rely
on that where the timing matters.

## When the network changes

Nothing to handle. After the device moves between Wi-Fi and cellular, the client notices and
rebuilds its connectivity on the next request. If the application was suspended and no update
arrived, the first request after a long idle gap checks the network itself.

What you do see is that requests in flight when the network went away fail. Those failures are
marked retryable:

```swift
do {
    return try await client.get(url)
} catch let error as ScionHttp3Error where error.isRetryable {
    retryLater()
}
```

Automatic retries are deliberately not built in: retrying a request that is not idempotent is a
decision only your application can make.

`reset()` is there for what the platform does not report. It marks connectivity stale and returns;
the next request does the work.

## Errors

`ScionHttp3Error` is an enum. A `switch` over it is exhaustive:

```swift
switch error {
case .connectivity:      // discovery or the SNAP handshake failed
case .resolution:        // the host has no SCION address records
case .connect:           // the origin could not be reached
case .tls:               // its certificate was rejected
case .timeout(let phase, _, _, _):   // a deadline expired; phase says which
case .bodyTooLarge:      // the response was larger than the limit
default:                 // see the type for the rest
}
```

Every case carries a `detail` worth putting in a log. `isRetryable` says whether sending the
same request again may succeed. A misconfiguration is `invalidConfiguration`, thrown by the
initializer, before any I/O.

## Certificates

By default a server's certificate is checked by the system, against the same authorities and with
the same policy `URLSession` applies. That includes authorities the user or a device profile
installed and trusted.

A deployment with its own authority needs its bundle of one or more PEM `CERTIFICATE` blocks:

```swift
configuration.trust = try .pinned(pemBundle)
```

A bundle without a certificate fails at that call.

There is also `TrustAnchors.insecureNoVerify`, which checks nothing. It exists for testing purposes
and it logs an error every time a client is built with it.

## What this version does not do

- **No HTTP/1.1 or HTTP/2 fallback.** If SCION cannot carry the request, it fails.
- **Bodies are held in memory**, in both directions, which suits REST and JSON. Streaming is coming,
  and the API is shaped so that it can arrive without breaking anything.
- **No `URLSession` integration.** A `URLProtocol` adapter is a possible later module; this library
  is the core it would be built on.
- **No background transfers.** A transfer runs while the application does.
- No WebSockets, no server push, no `CONNECT`.

## Testing your own code

`ScionHttp3Client` is a class, not a protocol, so fake the layer above it: put your requests behind
a protocol of your own and substitute that in tests. Its own behaviour is covered by the tests in
this package, including a suite that runs against a real SCION topology.

## Working on the package

| | |
| --- | --- |
| `Sources/ScionHTTP3` | The hand-written facade and the only module an adopter imports. |
| `Sources/ScionHTTP3Uniffi` | The Swift that `uniffi-bindgen` generates from `scion-http3-ffi`. Not checked in; `apple.py xcframework` writes it. |
| `ScionHTTP3UniffiFFI.xcframework` | The static library with its C header, one slice per platform. Not checked in; `apple.py xcframework` writes it. |
| `Tests/ScionHTTP3Tests` | The facade against a fake backend: configuration mapping, cancellation plumbing, staleness rules, lifecycle. No server, no native call. |
| `Tests/ScionHTTP3HostTests` | The raw bindings and the facade against the real library and a `scion-h3-test-server` the tests start themselves. |

`ScionHTTP3Uniffi` is not a product of this package, and the facade imports it with
`internal import`, so no generated type can appear in the facade's API. Inside the facade, only
`Internal/Mapping.swift` and `Internal/UniffiHttp3Backend.swift` name generated types.

To build the XCFramework, run the tests, or regenerate the bindings, see [the build
README](../README.md).
