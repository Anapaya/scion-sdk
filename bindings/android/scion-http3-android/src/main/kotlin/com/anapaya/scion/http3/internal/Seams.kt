// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.anapaya.scion.http3.internal

// Everything the library needs from the Android framework, as interfaces.
//
// There is one implementation of each, in `AndroidPlatform.kt`, and they are the only files that
// import `android.*`. That is what lets the logic above them run as an ordinary JVM unit test: the
// stubbed `android.jar` a unit test compiles against throws from every method, so code that reached
// the framework directly could not be tested at all without an emulator.
//
// These are not an abstraction over Android, and nothing here should grow to look like one. Each is
// the narrowest question the library actually asks.

/**
 * A clock that keeps running while the device sleeps.
 *
 * `SystemClock.elapsedRealtime()`, not `System.nanoTime()`: the latter stops during suspend, which
 * would make an hour in Doze look like seconds to the idle check that exists precisely because Doze
 * happened.
 */
internal fun interface MonotonicClock {
    fun elapsedRealtimeMillis(): Long
}

/** The platform's trust anchors, as a PEM bundle. */
internal fun interface SystemTrustStore {
    /**
     * Reads the anchors. Blocking: it touches the disk and parses a few hundred certificates, so it
     * belongs on a background dispatcher and must not be called while building a client.
     */
    fun anchorsPem(): ByteArray
}

/** Whether the application this library is linked into is debuggable. */
internal fun interface DebugGuard {
    fun isDebuggable(): Boolean
}

/** Where the library's own diagnostics go. */
internal interface LibraryLog {
    fun error(message: String)

    fun warn(message: String)

    fun debug(message: String)
}

/**
 * Watches which network the device sends over.
 *
 * Reports observations rather than decisions: what the callbacks saw, with no judgement about
 * whether it matters. [StalenessTracker] makes that judgement, which is what keeps it testable
 * without a device.
 */
internal interface NetworkMonitor {
    /**
     * Starts watching, delivering observations to [onObserved].
     *
     * Called on whatever thread the framework delivers callbacks on, so an implementation of
     * [onObserved] must be quick and must not throw: an exception escaping a framework callback
     * takes the process with it.
     */
    fun start(onObserved: (NetworkIdentity) -> Unit)

    /**
     * The network in use right now, or null if there is none or it cannot be determined.
     *
     * Cheap enough to ask on a request path: a couple of calls into the system service, no I/O.
     */
    fun currentIdentity(): NetworkIdentity?

    /** Stops watching. Idempotent, and safe to call from any thread. */
    fun stop()
}
