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

package com.anapaya.scion.http3

import java.io.IOException

/**
 * Everything a request can fail with.
 *
 * An [IOException], so an application that already handles network failure catches these without
 * changing its structure. The hierarchy is sealed, so a `when` over it is exhaustive and each arm
 * is something a caller can act on differently.
 *
 * @property isRetryable whether the same request may succeed if issued again. Reported by the
 *   stack rather than inferred from the arm: two failures of the same kind can differ here. A
 *   network change makes in-flight requests fail retryably, which is the case worth handling for
 *   idempotent requests.
 * @property detail the underlying failure and its causes, for logs and bug reports. Human-readable
 *   and not a stable format: never match on it.
 */
public sealed class ScionHttp3Exception(
    message: String,
    public val isRetryable: Boolean,
    public val detail: String,
    cause: Throwable?,
) : IOException(message, cause) {
    /** Which part of a request ran out of time. */
    public enum class TimeoutPhase {
        /** Establishing connectivity to the origin. */
        CONNECT,

        /** Waiting for the response head. */
        REQUEST,

        /** Collecting the response body. */
        BODY,

        /** A phase this version of the library does not distinguish. */
        OTHER,
    }

    /**
     * The client could not establish the connectivity a request needs, before sending anything.
     *
     * This is the layer below [Connect]: discovery through the endhost API, the SNAP handshake, or
     * reading the device's trust anchors, rather than reaching one origin. A wrong `endhostApi`, a
     * missing or rejected `authToken`, and no route to the endhost API all arrive here.
     */
    public class Connectivity internal constructor(
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(detail, isRetryable, detail, cause)

    /**
     * The request's host has no usable SCION address records.
     *
     * Either the name does not resolve, or it resolves to nothing this client can reach. Use
     * [ScionHttp3Request.Builder.target] to address a host that has no records at all.
     */
    public class Resolution internal constructor(
        public val host: String,
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception("$host: $detail", isRetryable, detail, cause)

    /** Reaching the origin failed: the socket, the QUIC handshake, or the peer refusing. */
    public class Connect internal constructor(
        public val host: String,
        public val port: Int,
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception("$host:$port: $detail", isRetryable, detail, cause)

    /**
     * The origin's certificate was rejected, or it does not speak HTTP/3.
     *
     * A private deployment whose certificate is signed by an internal CA needs
     * [TrustAnchors.pinned]; the platform anchors will not accept it.
     */
    public class Tls internal constructor(
        public val host: String,
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception("$host: $detail", isRetryable, detail, cause)

    /**
     * The origin reset the request's stream.
     *
     * @property code the HTTP/3 application error code, carrying the unsigned 64-bit value the
     *   peer sent. Compare it as bits rather than by magnitude.
     */
    public class StreamReset internal constructor(
        public val code: Long,
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception("stream reset, code $code: $detail", isRetryable, detail, cause)

    /** The origin broke HTTP/3 itself: a malformed frame, or a header section this client rejects. */
    public class Protocol internal constructor(
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(detail, isRetryable, detail, cause)

    /**
     * The origin allows no further concurrent requests on the connection.
     *
     * Retryable by nature: a request finishing frees a stream.
     */
    public class ConnectionLimit internal constructor(
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(detail, isRetryable, detail, cause)

    /**
     * The response body exceeded the permitted size and was not collected.
     *
     * @property limit the limit that was exceeded, in bytes. Raise it per request with
     *   [ScionHttp3Request.Builder.maxResponseBody], or for every request on the client with
     *   `maxResponseBody` on its builder.
     */
    public class BodyTooLarge internal constructor(
        public val limit: Long,
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception("response body exceeds $limit bytes", isRetryable, detail, cause)

    /**
     * A deadline expired.
     *
     * @property phase which part of the request ran out of time.
     * @property timeoutMillis the deadline that expired.
     */
    public class Timeout internal constructor(
        public val phase: TimeoutPhase,
        public val timeoutMillis: Long,
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(
            "timed out after ${timeoutMillis}ms in $phase: $detail",
            isRetryable,
            detail,
            cause,
        )

    /**
     * A body could not be decoded as requested.
     *
     * Raised by [ScionHttp3ResponseBody.string] when the bytes are not valid UTF-8. Read them with
     * [ScionHttp3ResponseBody.bytes] instead and decode them as whatever they are.
     */
    public class InvalidBody internal constructor(
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(detail, isRetryable, detail, cause)

    /**
     * The request or the client configuration was rejected before anything was sent.
     *
     * Most causes are refused earlier, by the builder that took them. What reaches here is what
     * only the stack can judge, such as an address the SCION topology cannot make sense of.
     */
    public class InvalidRequest internal constructor(
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(detail, isRetryable, detail, cause)

    /** The client is closed. A closed client is not reusable; build another one. */
    public class Closed internal constructor(
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(detail, isRetryable, detail, cause)

    /**
     * A failure this version of the library does not describe more precisely.
     *
     * Reaching this arm is worth reporting: it is either a bug or a failure mode that deserves its
     * own arm.
     */
    public class Internal internal constructor(
        isRetryable: Boolean,
        detail: String,
        cause: Throwable? = null,
    ) : ScionHttp3Exception(detail, isRetryable, detail, cause)
}
