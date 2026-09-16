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

import com.anapaya.scion.http3.internal.TunnelBackend
import com.anapaya.scion.http3.internal.toPublic
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception as FfiException

/**
 * A byte stream through a `CONNECT` tunnel opened with [ScionHttp3Client.openTunnel].
 *
 * The read and the write direction are independent: one coroutine may read while another writes.
 * [shutdownWrite] ends the write direction and leaves reads open. A read returns an empty
 * array at the end of the stream. One [read] returns at most one frame.
 *
 * Cancelling a pending read or write closes the tunnel. A call that is dropped mid-flight may
 * have lost the bytes it just read or have written part of its data, so the stream is not
 * usable after it.
 *
 * Close the tunnel when done with it. Closing resets the stream, which ends any call still in
 * flight with [ScionHttp3Exception.TunnelClosed]. Shutting the client down ends every tunnel on
 * it with [ScionHttp3Exception.Closed].
 */
public class ScionHttp3Tunnel internal constructor(
    private val backend: TunnelBackend,
) : Closeable {
    private val closed = AtomicBoolean(false)

    /** Whether [close] has been called. */
    public val isClosed: Boolean get() = closed.get()

    /**
     * Reads up to [max] bytes. Returns an empty array at the end of the stream.
     *
     * @throws ScionHttp3Exception if the tunnel failed or was closed.
     */
    public suspend fun read(max: Int): ByteArray {
        requireReadable(max)
        return guarded { backend.read(max) }
    }

    /**
     * Reads as [read] does or returns `null` once [timeoutMillis] elapsed with nothing to read.
     *
     * The tunnel stays usable after an elapsed deadline. A deadline of zero waits without limit.
     */
    internal suspend fun readWithin(
        max: Int,
        timeoutMillis: Long,
    ): ByteArray? {
        requireReadable(max)
        require(timeoutMillis >= 0) { "a deadline cannot be negative: $timeoutMillis" }
        if (timeoutMillis == 0L) return guarded { backend.read(max) }
        return guarded {
            backend.newCancel().use { cancel ->
                coroutineScope {
                    val timer =
                        launch {
                            delay(timeoutMillis)
                            cancel.cancel()
                        }
                    try {
                        backend.read(max, cancel)
                    } catch (e: FfiException.Cancelled) {
                        null
                    } finally {
                        timer.cancel()
                    }
                }
            }
        }
    }

    /**
     * Writes all of [data].
     *
     * @throws ScionHttp3Exception if the tunnel failed, was closed, or had its write direction
     *   shut down.
     */
    public suspend fun write(data: ByteArray) {
        if (data.isEmpty()) return
        guarded { backend.write(data) }
    }

    /**
     * Ends the write direction. The peer sees the end of the stream.
     *
     * Idempotent. A later [write] fails with [ScionHttp3Exception.TunnelClosed].
     */
    public suspend fun shutdownWrite(): Unit = guarded { backend.shutdownWrite() }

    /**
     * Resets the stream and releases the tunnel.
     *
     * Idempotent and safe to call from another thread while a read or a write is blocked: that
     * call ends with [ScionHttp3Exception.TunnelClosed].
     */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        backend.abort()
        backend.close()
    }

    private fun requireReadable(max: Int) {
        require(max > 0) {
            "max must be greater than zero: an empty result is the end of the stream"
        }
    }

    private suspend fun <T> guarded(block: suspend () -> T): T {
        if (closed.get()) throw closedException()
        try {
            return block()
        } catch (e: FfiException) {
            throw e.toPublic()
        } catch (e: CancellationException) {
            close()
            throw e
        } catch (e: IllegalStateException) {
            // The handle was destroyed by a close that raced this call.
            if (!closed.get()) throw e
            throw closedException(e)
        }
    }

    private fun closedException(cause: Throwable? = null): ScionHttp3Exception =
        ScionHttp3Exception.TunnelClosed(
            isRetryable = false,
            detail = "this tunnel is closed",
            cause = cause,
        )
}
