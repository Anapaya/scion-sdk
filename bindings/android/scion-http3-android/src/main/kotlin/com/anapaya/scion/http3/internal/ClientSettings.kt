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

import com.anapaya.scion.http3.PreferredUnderlay
import com.anapaya.scion.http3.SnapConfig
import com.anapaya.scion.http3.TrustAnchors
import com.anapaya.scion.http3.UdpConfig
import java.net.URI
import java.net.URISyntaxException

/**
 * Everything a client was configured with, validated, and holding no platform objects.
 *
 * Every setting except the endhost API and the trust anchors is nullable, and null means "whatever
 * the SCION stack does". That is the whole reason this type is separate from the FFI's own config:
 * a default restated here would be a second copy of a number the stack owns, and the two would
 * eventually disagree.
 *
 * Validation happens in [init], which is also what makes it testable: it needs no `Context`, so the
 * rejections can be exercised as ordinary unit tests rather than on a device.
 */
internal class ClientSettings(
    val endhostApiUrl: String,
    val trust: TrustAnchors,
    val authToken: String? = null,
    val preferredUnderlay: PreferredUnderlay? = null,
    val snap: SnapConfig? = null,
    val udp: UdpConfig? = null,
    val connectTimeoutMillis: Long? = null,
    val requestTimeoutMillis: Long? = null,
    val idleConnectionTimeoutMillis: Long? = null,
    val connectionAttemptDelayMillis: Long? = null,
    val maxOrigins: Int? = null,
    val maxResponseBodyBytes: Long? = null,
) {
    init {
        validateEndhostApiUrl(endhostApiUrl)
        authToken?.let { require(it.isNotEmpty()) { "an auth token cannot be empty" } }
        requirePositive("connectTimeout", connectTimeoutMillis)
        requirePositive("requestTimeout", requestTimeoutMillis)
        requirePositive("idleConnectionTimeout", idleConnectionTimeoutMillis)
        requirePositive("connectionAttemptDelay", connectionAttemptDelayMillis)
        maxOrigins?.let {
            require(it >= 1) { "maxOrigins has to be at least 1, got $it" }
        }
        maxResponseBodyBytes?.let {
            require(it > 0) { "maxResponseBody has to be positive, got $it bytes" }
        }
    }

    /**
     * How long a client may go unused before a request re-checks the network itself.
     *
     * Derived from the configured idle-connection timeout when there is one, since that is when the
     * connections a rebuild would discard have been swept anyway. With none configured this is a
     * heuristic of its own rather than a restatement of the stack's default: what matters is that
     * the gap is long enough not to fire between two ordinary requests, and short enough to catch a
     * change that happened while the application was in the background.
     */
    val idleThresholdMillis: Long
        get() =
            idleConnectionTimeoutMillis
                ?.let { StalenessTracker.idleThresholdFor(it) }
                ?: DEFAULT_IDLE_THRESHOLD_MILLIS

    private companion object {
        const val DEFAULT_IDLE_THRESHOLD_MILLIS: Long = 50_000

        fun requirePositive(
            name: String,
            millis: Long?,
        ) {
            millis?.let { require(it > 0) { "$name has to be positive, got $it ms" } }
        }

        fun validateEndhostApiUrl(url: String) {
            require(url.isNotEmpty()) {
                "endhostApi is required: it is the address the client discovers SCION " +
                    "connectivity through. A local PocketSCION topology reached from the " +
                    "emulator is http://10.0.2.2:8041."
            }
            val uri =
                try {
                    URI(url)
                } catch (e: URISyntaxException) {
                    throw IllegalArgumentException("endhostApi \"$url\" is not a valid URL", e)
                }
            require(uri.isAbsolute && !uri.host.isNullOrEmpty()) {
                "endhostApi \"$url\" needs a scheme and a host, for example " +
                    "https://endhost-api.example.org"
            }
            val scheme = uri.scheme.lowercase()
            require(scheme == "http" || scheme == "https") {
                "endhostApi \"$url\" has to be http or https, not $scheme"
            }
        }
    }
}

/**
 * Says, loudly, that certificate verification is off.
 *
 * Logged rather than refused, deliberately: a test against a throwaway server is a real need, and
 * the debuggable flag cannot tell an internal beta from a shipped app. So this makes noise instead
 * of decisions, and says plainly when the build it is running in is not a debug one.
 */
internal fun warnIfVerificationDisabled(
    trust: TrustAnchors,
    debug: DebugGuard,
    log: LibraryLog,
) {
    if (trust !is TrustAnchors.NoVerification) return
    log.error(
        "TLS certificate verification is DISABLED for this ScionHttp3Client. Every response " +
            "could come from anyone on the path. This is for local testing only.",
    )
    if (!debug.isDebuggable()) {
        log.error(
            "Worse: this application is not debuggable, so this is a release build. " +
                "TrustAnchors.insecureNoVerify() must not ship. Use TrustAnchors.pinned() with " +
                "the deployment's own certificate authority instead.",
        )
    }
}
