---
title: The mobile clients
sidebar_position: 4
description: How the Android and iOS clients of the chat use the SDK, and the transport that they share with the Rust client.
---

The chat has an Android client and an iOS client. Each client uses the SDK library for its
platform. The platform pages explain each library:
[Android HTTP/3 client](../platforms/android/http3-client.md) and [iOS](../platforms/ios.md). This
page shows how the chat uses the libraries, and how the mobile clients match
[the Rust client](./client.md).

## One transport in three languages

The Rust transport has three parts: it builds the client, sends a request, and maps the errors. The
Android transport and the iOS transport have the same three parts:

| Part | Rust | Kotlin | Swift |
| --- | --- | --- | --- |
| Build the client | `ScionTransport::new` | `ScionTransport.open` | `ScionTransport.init` |
| Send a request | `request` | `send` | `send` |
| Map the errors | `failure` | `failure` | `failure` |

In each app, the transport is the only file that imports the SDK. These sections show how each
mobile transport adds the library, trusts the server, maps the errors and holds its client:

- **Android:** [The Android client](#the-android-client) on this page.
- **iOS:** [The iOS client](#the-ios-client) on this page.

In all three languages, the SDK renews the token.

## The Android client

The Android client keeps all of its SCION code in one class,
[`ScionTransport.kt`](https://github.com/Anapaya/scion-sdk-chat/blob/main/android/chat-client/src/main/kotlin/com/anapaya/chat/client/ScionTransport.kt).
[Android HTTP/3 client](../platforms/android/http3-client.md) explains the library that the class
uses.

### Add the library

The chat does the steps of
[Add the SDK to your app](../platforms/android/http3-client.md#add-the-sdk-to-your-app) in its
[`settings.gradle.kts`](https://github.com/Anapaya/scion-sdk-chat/blob/main/android/settings.gradle.kts).
The build downloads the Maven archive of a release, checks the archive against the checksums of the
release, and unpacks it into `libs/maven`.

### Trust the server

The chat offers the three trust choices on its connect screen, and turns the choice into a
`TrustAnchors` value. [Certificates](../platforms/android/http3-client.md#certificates) explains
each choice:

```kotlin reference="@chat/android/chat-client/src/main/kotlin/com/anapaya/chat/client/ScionTransport.kt#trust" title="ScionTransport.kt"
```

### Map the errors

The chat sorts each arm of `ScionHttp3Exception` into the errors of the app.
[Handling errors](../platforms/android/http3-client.md#handling-errors) explains each arm:

```kotlin reference="@chat/android/chat-client/src/main/kotlin/com/anapaya/chat/client/ScionTransport.kt#errors" title="ScionTransport.kt"
```

### The lifetime of the client

The chat holds one transport at a time. Each Connect on its connect screen builds a new transport
and closes the old one.
[The client's lifetime](../platforms/android/http3-client.md#the-clients-lifetime) explains when to
close a client. The SDK renews the token.

## The iOS client

The iOS client keeps all of its SCION code in one class,
[`ScionTransport.swift`](https://github.com/Anapaya/scion-sdk-chat/blob/main/ios/ChatClient/Sources/ChatClient/ScionTransport.swift).
[iOS](../platforms/ios.md) explains the library that the class uses.

### Add the library

The chat does the steps of [Add the SDK to your app](../platforms/ios.md#add-the-sdk-to-your-app) in
[`fetch-sdk.sh`](https://github.com/Anapaya/scion-sdk-chat/blob/main/ios/fetch-sdk.sh). The script
downloads the package of the release that
[`sdk.version`](https://github.com/Anapaya/scion-sdk-chat/blob/main/ios/sdk.version) names, checks
the package against the checksums of the release, and unpacks it into `ios/libs`.

### Trust the server

The chat offers the three trust choices on its connect screen, and sets `trust` from the choice.
[Certificates](../platforms/ios.md#certificates) explains each choice:

```swift reference="@chat/ios/ChatClient/Sources/ChatClient/ScionTransport.swift#trust" title="ScionTransport.swift"
```

### Map the errors

The chat sorts each case of `ScionHttp3Error` into the errors of the app.
[Handling errors](../platforms/ios.md#handling-errors) explains each case:

```swift reference="@chat/ios/ChatClient/Sources/ChatClient/ScionTransport.swift#errors" title="ScionTransport.swift"
```

### The lifetime of the client

The chat holds one transport at a time. Each Connect on its connect screen builds a new transport
and shuts down the old one. [The client's lifetime](../platforms/ios.md#the-clients-lifetime)
explains when to shut down a client. The SDK renews the token.

## Reach a server without a TSAR record

A server in a local SCION network has no TSAR record. The Rust client answers for the host of the
server with `with_override`, as [The client](./client.md#reach-a-server-without-a-tsar-record)
shows. The mobile clients do the same:

- The Android client calls `dnsOverride` on the client builder.
- The iOS client sets `dnsOverrides` in the client settings.

Each maps the host of the server URL to the `target` address.

## Where to go next

- **[The client](./client.md):** the same transport in Rust.
- **[Android HTTP/3 client](../platforms/android/http3-client.md)** and **[iOS](../platforms/ios.md):**
  the SDK libraries that the mobile clients use.
- **[From a local SCION network to a real network](./real-network.md):** the credential, the
  address and the trust of a real deployment.
