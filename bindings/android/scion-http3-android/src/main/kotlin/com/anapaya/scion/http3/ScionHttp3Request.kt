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

import java.net.URI
import java.net.URISyntaxException
import kotlin.time.Duration

/**
 * One request: where to send it, what to send, and the per-request limits that apply to it.
 *
 * Immutable, and safe to issue more than once. Build one with [Builder].
 */
public class ScionHttp3Request internal constructor(
    /** The absolute `https` URL. */
    public val url: String,
    /** The method, upper-case by convention but sent exactly as given. */
    public val method: String,
    /** The header section, which does not include the `content-type` a body implies. */
    public val headers: ScionHttp3Headers,
    /** The body, or null when the request sends none. */
    public val body: ScionHttp3RequestBody?,
    /** Addresses to use instead of resolving [url]'s host. Empty means resolve it. */
    public val targets: List<ScionAddress>,
    /** Overrides the client's request timeout for this request; null keeps it. */
    public val requestTimeoutMillis: Long?,
    /** Overrides the client's response-body limit for this request; null keeps it. */
    public val maxResponseBodyBytes: Long?,
) {
    /** A builder holding everything in this request, for deriving a modified copy. */
    public fun newBuilder(): Builder = Builder(this)

    override fun toString(): String = "$method $url"

    /**
     * Accumulates a request. Not thread-safe; build one per request.
     *
     * Everything a builder can judge for itself is rejected here rather than at request time: a URL
     * that is not absolute `https`, a method that is not a token, a header a header section cannot
     * carry. That keeps a caller's mistake an [IllegalArgumentException] at the call that made it,
     * and leaves [ScionHttp3Exception] for what actually goes wrong on the network.
     */
    public class Builder {
        private var url: String? = null
        private var method: String = "GET"
        private var headers = ScionHttp3Headers.Builder()
        private var body: ScionHttp3RequestBody? = null
        private val targets = mutableListOf<ScionAddress>()
        private var requestTimeoutMillis: Long? = null
        private var maxResponseBodyBytes: Long? = null

        public constructor()

        internal constructor(request: ScionHttp3Request) {
            url = request.url
            method = request.method
            headers = request.headers.newBuilder()
            body = request.body
            targets += request.targets
            requestTimeoutMillis = request.requestTimeoutMillis
            maxResponseBodyBytes = request.maxResponseBodyBytes
        }

        /**
         * The absolute URL to request.
         *
         * Must be `https`. This is an HTTP/3-only client with nothing to fall back to, so a
         * plaintext URL is a mistake rather than a downgrade.
         */
        public fun url(url: String): Builder {
            this.url = url
            return this
        }

        /** `GET`, dropping any body already set. */
        public fun get(): Builder = method("GET", null)

        /** `POST` with a body. */
        public fun post(body: ScionHttp3RequestBody): Builder = method("POST", body)

        /** `PUT` with a body. */
        public fun put(body: ScionHttp3RequestBody): Builder = method("PUT", body)

        /** `PATCH` with a body. */
        public fun patch(body: ScionHttp3RequestBody): Builder = method("PATCH", body)

        /** `DELETE`, with a body only if one is given. */
        @JvmOverloads
        public fun delete(body: ScionHttp3RequestBody? = null): Builder = method("DELETE", body)

        /** `HEAD`, dropping any body already set. */
        public fun head(): Builder = method("HEAD", null)

        /** Any other method, with a body only if the method takes one. */
        @JvmOverloads
        public fun method(
            method: String,
            body: ScionHttp3RequestBody? = null,
        ): Builder {
            this.method = validateMethod(method)
            this.body = body
            return this
        }

        /** Sets a header, replacing every line that already has this name. */
        public fun header(
            name: String,
            value: String,
        ): Builder {
            headers.set(name, value)
            return this
        }

        /** Appends a header line, keeping any line that already has this name. */
        public fun addHeader(
            name: String,
            value: String,
        ): Builder {
            headers.add(name, value)
            return this
        }

        /** Replaces the whole header section. */
        public fun headers(headers: ScionHttp3Headers): Builder {
            this.headers = headers.newBuilder()
            return this
        }

        /** Removes every header line with this name. */
        public fun removeHeader(name: String): Builder {
            headers.removeAll(name)
            return this
        }

        /** Sets or clears the body without changing the method. */
        public fun body(body: ScionHttp3RequestBody?): Builder {
            this.body = body
            return this
        }

        /**
         * Sends this request to [target] instead of resolving the URL's host.
         *
         * The escape hatch, for a host that has no SCION address records: a server on a local
         * PocketSCION topology, or one reached before its records exist. Call it more than once to
         * offer several addresses, which are then raced as if resolution had returned them all.
         *
         * The URL keeps its host and port, and both still determine `:authority` and the
         * certificate that is accepted, so this changes only *where* the request is sent.
         */
        public fun target(target: ScionAddress): Builder {
            targets += target
            return this
        }

        /** Replaces the targets, emptying them when given an empty list. */
        public fun targets(targets: List<ScionAddress>): Builder {
            this.targets.clear()
            this.targets += targets
            return this
        }

        /** Overrides the client's request timeout for this request. Must be positive. */
        public fun requestTimeout(timeout: Duration): Builder =
            requestTimeoutMillis(timeout.inWholeMilliseconds)

        /**
         * Overrides the client's request timeout, in milliseconds.
         *
         * The `Duration` overload is the one to use from Kotlin; this one exists because
         * `kotlin.time.Duration` is awkward to construct from Java.
         */
        public fun requestTimeoutMillis(millis: Long): Builder {
            require(millis > 0) { "a request timeout must be positive, not $millis ms" }
            requestTimeoutMillis = millis
            return this
        }

        /**
         * Overrides the client's limit on the response body, in bytes. Must be positive.
         *
         * This is the limit that bounds memory: the body is collected before the response is
         * returned, so a limit applied afterwards cannot un-spend it.
         */
        public fun maxResponseBody(bytes: Long): Builder {
            require(bytes > 0) { "a response body limit must be positive, not $bytes bytes" }
            maxResponseBodyBytes = bytes
            return this
        }

        /**
         * @throws IllegalArgumentException if no URL was set, or it is not an absolute `https` URL.
         */
        public fun build(): ScionHttp3Request {
            val url = requireNotNull(url) { "a request needs a url" }
            validateUrl(url)
            val body = body
            // On the built section rather than on the builder: a builder is reusable, and mutating it
            // here would carry this body's content-type into the next request built from it, even one
            // with another body or none.
            var headers = headers.build()
            if (body?.contentType != null) {
                headers = headers.newBuilder().addIfAbsent("content-type", body.contentType).build()
            }
            return ScionHttp3Request(
                url = url,
                method = method,
                headers = headers,
                body = body,
                targets = targets.toList(),
                requestTimeoutMillis = requestTimeoutMillis,
                maxResponseBodyBytes = maxResponseBodyBytes,
            )
        }

        private companion object {
            private const val METHOD_SYMBOLS = "!#$%&'*+-.^_`|~"

            private fun validateMethod(method: String): String {
                require(method.isNotEmpty()) { "a method cannot be empty" }
                method.forEach { c ->
                    require((c.isLetterOrDigit() && c.code < 0x80) || c in METHOD_SYMBOLS) {
                        "\"$method\" is not a method: expected a token, for example GET or POST"
                    }
                }
                return method
            }

            private fun validateUrl(url: String) {
                val uri =
                    try {
                        URI(url)
                    } catch (e: URISyntaxException) {
                        throw IllegalArgumentException(
                            "\"$url\" is not a valid URL: ${e.reason}",
                            e,
                        )
                    }
                require(uri.isAbsolute) {
                    "\"$url\" is not absolute: a request URL needs a scheme and a host"
                }
                require(uri.scheme.equals("https", ignoreCase = true)) {
                    "\"$url\" is not https. This client speaks HTTP/3 over SCION only and has " +
                        "nothing to fall back to, so a plaintext URL cannot be served."
                }
                require(!uri.host.isNullOrEmpty()) { "\"$url\" has no host" }
            }
        }
    }
}
