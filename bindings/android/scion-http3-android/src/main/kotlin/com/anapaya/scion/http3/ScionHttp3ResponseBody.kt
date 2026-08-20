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

import java.io.Closeable
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * A response body.
 *
 * `Closeable` and `suspend` from the outset, although this version has the bytes in hand and needs
 * neither. Both become load-bearing when bodies stream: an unclosed body will then have to tell the
 * peer to stop sending, and reading will genuinely suspend. Writing `use { }` and `suspend` now is
 * what keeps that addition from breaking every call site.
 *
 * Closing a body of this version releases nothing, so forgetting to leaks nothing either.
 */
public class ScionHttp3ResponseBody internal constructor(
    private val content: ByteArray,
) : Closeable {
    // Volatile because a response can be handed to another coroutine, on another thread, and
    // "closed" has to be visible there rather than eventually.
    @Volatile
    private var closed = false

    /** How many bytes the body has. */
    public val contentLength: Long get() = content.size.toLong()

    /**
     * The bytes.
     *
     * A copy, so a caller cannot change what another reader of the same response sees.
     *
     * @param maxSize refuses a body larger than this many bytes. Note that in this version the
     *   whole body has already been received by the time it can be checked, so this guards a
     *   caller's own buffers rather than the memory the response cost. The limit that bounds *that*
     *   is [ScionHttp3Request.Builder.maxResponseBody], applied while the body is being collected.
     * @throws ScionHttp3Exception.BodyTooLarge if the body is larger than [maxSize].
     * @throws IllegalStateException if the body is closed.
     */
    @JvmOverloads
    public suspend fun bytes(maxSize: Long = Long.MAX_VALUE): ByteArray = read(maxSize).copyOf()

    /**
     * The bytes decoded as UTF-8.
     *
     * Strict: a body that is not valid UTF-8 is an error rather than a string full of replacement
     * characters, because a silently mangled payload is worse than a failed one. Read [bytes] and
     * decode them yourself when the encoding is something else.
     *
     * @throws ScionHttp3Exception.InvalidBody if the body is not valid UTF-8.
     * @throws ScionHttp3Exception.BodyTooLarge if the body is larger than [maxSize].
     * @throws IllegalStateException if the body is closed.
     */
    @JvmOverloads
    public suspend fun string(maxSize: Long = Long.MAX_VALUE): String {
        val bytes = read(maxSize)
        val decoder =
            Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        } catch (e: CharacterCodingException) {
            throw ScionHttp3Exception.InvalidBody(
                isRetryable = false,
                detail = "the response body is not valid UTF-8: ${e.message}",
                cause = e,
            )
        }
    }

    /**
     * Releases the body.
     *
     * Idempotent, and nothing may be read afterwards. Nothing to release in this version; see the
     * note on the class.
     */
    override fun close() {
        closed = true
    }

    private fun read(maxSize: Long): ByteArray {
        check(!closed) { "this response body is closed" }
        if (content.size > maxSize) {
            throw ScionHttp3Exception.BodyTooLarge(
                limit = maxSize,
                isRetryable = false,
                detail = "the response body is ${content.size} bytes, over the $maxSize requested",
            )
        }
        return content
    }
}
