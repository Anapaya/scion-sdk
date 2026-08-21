# SCION HTTP/3 for Android

An HTTP client for Android that sends its requests over [SCION](https://scion.org) instead of the
public internet's routing, speaking HTTP/3 end to end.

If you have used OkHttp, this will look familiar: build a client once, build a request, execute it,
read the response.

```kotlin
val client = ScionHttp3Client.Builder(context)
    .endhostApi("https://endhost-api.example.org")
    .authToken(token)
    .build()

val rooms = client.get("https://chat.example.org/rooms").use { it.body.string() }
```

## Adding it

Every [release](https://github.com/Anapaya/scion-sdk/releases) carries the library as an asset, in
two forms. Take the one that suits how you want to depend on it. It is not on Maven Central yet.

### As a repository

`scion-http3-android-<version>-maven.zip` is a Maven repository holding the library and its POM.
Unpack it anywhere and name that directory as a repository:

```kotlin
repositories {
    maven { url = uri("libs/maven") }
}

dependencies {
    implementation("com.anapaya.scion:scion-http3-android:<version>")

    // Only for calling the library from a coroutine tied to the UI. JNA and kotlinx-coroutines-core
    // arrive with the library, because the POM declares them.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
```

### As a file

`scion-http3-android-<version>.aar` is the library on its own. Put it in your project and point at
it:

```kotlin
dependencies {
    implementation(files("libs/scion-http3-android-<version>.aar"))

    // An AAR consumed as a file carries no dependency information, so these three are yours to
    // declare. The library needs the first two at run time; the third is only for calling it from a
    // coroutine tied to the UI.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
```

The `@aar` on JNA matters: that artifact carries JNA's native libraries for each Android ABI, and the
plain jar does not.

Each release also carries a sources jar, and a `SHA256SUMS` covering every asset.

Requirements: `minSdk` 24, JDK 17 to build. The AAR ships `arm64-v8a` and `x86_64`, so it runs on
current devices and on the emulator, but not on a 32-bit-only ARM device. It brings the `INTERNET` and
`ACCESS_NETWORK_STATE` permissions with it; you do not have to declare either.

## Your first request, against a local network

You do not need access to a real SCION network to try this. PocketSCION is a whole SCION network in
one process, and the emulator can reach one running on your machine at `10.0.2.2`, which is how the
emulator sees its host's loopback:

```kotlin
val client = ScionHttp3Client.Builder(context)
    .endhostApi("http://10.0.2.2:8041")
    .build()
```

Everything else is the same as against a real network. That is the point of `endhostApi` being the
only setting that changes: it is what tells the client where to find SCION connectivity.

A server on a local topology usually has no address records to look up, so address it directly:

```kotlin
val response = client.newCall(
    ScionHttp3Request.Builder()
        .url("https://chat.example.org:54321/rooms")
        .target(ScionAddress.parse("1-ff00:0:110,10.0.0.1"))
        .build(),
).execute()
```

The target carries no port on purpose. The port comes from the URL, so the URL stays truthful about
where the request went.

If your token expires, renew it in place rather than building a new client:

```kotlin
client.setAuthToken(refreshed)
```

Connectivity is rebuilt whenever the network changes, and each rebuild authenticates again, so a
token set once at build time eventually stops being accepted. A renewal is picked up by the next
request and keeps the connections already established.

## Requests and responses

```kotlin
val response = client.newCall(
    ScionHttp3Request.Builder()
        .url("https://chat.example.org/messages")
        .post(ScionHttp3RequestBody.json("""{"room":"general","text":"hi"}"""))
        .header("authorization", "Bearer $token")
        .requestTimeout(60.seconds)
        .build(),
).execute()

if (response.isSuccessful) {
    val body = response.body.string()
}
```

A non-2xx status is a response, not an exception. Exceptions are for requests that produced no
response at all.

Responses hold their body, so close them. `use { }` is the easy way; the body's accessors are
`suspend` and the body is `Closeable` because both will matter when bodies stream, and adding either
later would break every call site that had been written without them.

`client.get(url)` and `client.post(url, body)` are shorthands for the common two.

## Cancellation, and the client's lifetime

Requests are ordinary `suspend` functions. Cancel the coroutine and the request is cancelled, all the
way down to the HTTP/3 stream; the connection stays usable for the next one.

```kotlin
val job = scope.launch { client.get(url) }
job.cancel()   // the request stops, nothing is left behind
```

Build **one client and keep it**. It holds the connections your requests reuse, so one per request
would throw away the connection every time. Building it costs nothing: no traffic, no disk, no
threads, so `Application.onCreate` is a fine place for it. The first request is what establishes
connectivity.

Close it when the application is done with it, which also stops it watching for network changes.
`close()` is immediate; `shutdown()` first lets each connection tell its peer it is going away.

## When the network changes

Nothing to handle. After the device moves between Wi-Fi and cellular, the client notices and rebuilds
its connectivity on the next request.

What you do see is that requests in flight when the network went away fail. Those failures are
marked retryable:

```kotlin
try {
    client.get(url)
} catch (e: ScionHttp3Exception) {
    if (e.isRetryable) retryLater() else giveUp(e)
}
```

Automatic retries are deliberately not built in: retrying a request that is not idempotent is a
decision only you can make.

`reset()` is there for what the platform does not report, such as a VPN coming up. It marks
connectivity stale and returns; the next request does the work.

## Errors

`ScionHttp3Exception` is an `IOException`, so it fits the error handling you already have, and it is
sealed, so a `when` over it is exhaustive:

```kotlin
when (e) {
    is ScionHttp3Exception.Connectivity  -> // discovery or the SNAP handshake failed
    is ScionHttp3Exception.Resolution    -> // the host has no SCION address records
    is ScionHttp3Exception.Connect       -> // the origin could not be reached
    is ScionHttp3Exception.Tls           -> // its certificate was rejected
    is ScionHttp3Exception.Timeout       -> // a deadline expired; e.phase says which
    is ScionHttp3Exception.BodyTooLarge  -> // the response was larger than the limit
    else                                 -> // see the class for the rest
}
```

Every one of them carries `isRetryable` and a `detail` worth putting in a log.

## Certificates

By default a server's certificate is checked against the device's own authorities, exactly as any
other HTTP client on the device would check it. Authorities the user installed are not included: an
application targeting API 24 or later does not trust those by default, and this client does not widen
that.

A deployment with its own authority needs its bundle:

```kotlin
.trust(TrustAnchors.pinned(assets.open("internal-ca.pem").readBytes()))
```

There is also `TrustAnchors.insecureNoVerify()`, which checks nothing. It exists for a throwaway test
server, it logs an error every time a client is built with it, and it must never ship.

## What this version does not do

- **No HTTP/1.1 or HTTP/2 fallback.** If SCION cannot carry the request, it fails.
- **Bodies are held in memory**, in both directions, which suits REST and JSON. Streaming is coming,
  and the API is shaped so that it can arrive without breaking anything.
- **Kotlin, not Java.** Requests are `suspend` functions, which Java cannot call comfortably. The
  builders and exceptions are already Java-friendly, and a `Future`-based facade can be added when
  there is a need for it.
- No WebSockets, no server push, no `CONNECT`.

## Testing your own code

`ScionHttp3Client` is a class, not an interface, so fake the layer above it: put your requests behind
a repository interface of your own and substitute that in tests. Its own behaviour is covered by the
tests in this repository, including a suite that runs against a real SCION topology.
