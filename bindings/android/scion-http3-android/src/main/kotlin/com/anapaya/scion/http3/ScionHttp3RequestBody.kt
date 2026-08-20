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

/**
 * Bytes to send, and what they are.
 *
 * Bodies are held whole in memory in this version, which suits the REST and JSON traffic the
 * library is for. Streaming a body arrives later, without changing this type's callers.
 *
 * @property contentType the media type, sent as `content-type` unless the request already sets that
 *   header itself. Null sends no `content-type` at all.
 */
public class ScionHttp3RequestBody private constructor(
    public val contentType: String?,
    private val content: ByteArray,
) {
    /** How many bytes will be sent. */
    public val contentLength: Long get() = content.size.toLong()

    /**
     * A copy of the bytes.
     *
     * A copy so that a body, which is meant to be safe to send twice, cannot be changed underneath
     * a request that is already in flight.
     */
    public fun bytes(): ByteArray = content.copyOf()

    internal fun bytesNoCopy(): ByteArray = content

    public companion object {
        private const val JSON = "application/json"
        private const val TEXT = "text/plain; charset=utf-8"
        private const val OCTET_STREAM = "application/octet-stream"

        /** UTF-8 encoded JSON, sent as `application/json`. */
        @JvmStatic
        public fun json(json: String): ScionHttp3RequestBody = text(json, JSON)

        /** Already-encoded JSON, sent as `application/json`. */
        @JvmStatic
        public fun json(json: ByteArray): ScionHttp3RequestBody = bytes(json, JSON)

        /** UTF-8 encoded text, sent as `text/plain; charset=utf-8`. */
        @JvmStatic
        public fun text(text: String): ScionHttp3RequestBody = text(text, TEXT)

        /** UTF-8 encoded text with a media type of your own. */
        @JvmStatic
        public fun text(
            text: String,
            contentType: String?,
        ): ScionHttp3RequestBody =
            ScionHttp3RequestBody(contentType, text.toByteArray(Charsets.UTF_8))

        /** Arbitrary bytes, `application/octet-stream` unless another type is given. */
        @JvmStatic
        @JvmOverloads
        public fun bytes(
            bytes: ByteArray,
            contentType: String? = OCTET_STREAM,
        ): ScionHttp3RequestBody = ScionHttp3RequestBody(contentType, bytes.copyOf())

        /**
         * A body of zero bytes and no media type.
         *
         * Not the same as sending no body: a `POST` with this body sends `content-length: 0`, where
         * a request built without a body sends no body at all.
         */
        @JvmStatic
        public fun empty(): ScionHttp3RequestBody = ScionHttp3RequestBody(null, ByteArray(0))
    }
}
