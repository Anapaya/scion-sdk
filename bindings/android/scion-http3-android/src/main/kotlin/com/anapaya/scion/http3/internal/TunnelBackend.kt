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

/** What the library needs from one generated tunnel object. */
internal interface TunnelBackend : AutoCloseable {
    /** Reads up to [max] bytes, at most one frame. An empty array is the end of the stream. */
    suspend fun read(max: Int): ByteArray

    /**
     * Reads as [read] does, and fails with the stack's `Cancelled` once [cancel] fires.
     *
     * [cancel] must come from this backend's [newCancel].
     */
    suspend fun read(
        max: Int,
        cancel: TunnelCancel,
    ): ByteArray

    /** A cancellation for one deadline read. */
    fun newCancel(): TunnelCancel

    /** Writes all of [data]. */
    suspend fun write(data: ByteArray)

    /** Ends the write direction. The peer sees the end of the stream; reads continue. */
    suspend fun shutdownWrite()

    /** Resets the stream and ends every call in flight. Idempotent, never fails. */
    fun abort()

    /** Releases the handle, which also resets the stream. */
    override fun close()
}

/** Fires once, from any thread, and then does nothing more. */
internal interface TunnelCancel : AutoCloseable {
    fun cancel()
}
