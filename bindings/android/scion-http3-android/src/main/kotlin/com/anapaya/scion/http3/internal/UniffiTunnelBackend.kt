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

import com.anapaya.scion.http3.uniffi.CancelHandle
import com.anapaya.scion.http3.uniffi.Tunnel

/** [TunnelBackend] over the generated bindings. */
internal class UniffiTunnelBackend(
    private val tunnel: Tunnel,
) : TunnelBackend {
    override suspend fun read(max: Int): ByteArray = tunnel.read(max.toUInt())

    override suspend fun read(
        max: Int,
        cancel: TunnelCancel,
    ): ByteArray = tunnel.readCancellable(max.toUInt(), (cancel as UniffiTunnelCancel).handle)

    override fun newCancel(): TunnelCancel = UniffiTunnelCancel(CancelHandle())

    override suspend fun write(data: ByteArray) {
        tunnel.write(data)
    }

    override suspend fun shutdownWrite() {
        tunnel.shutdownWrite()
    }

    override fun abort() {
        tunnel.abort()
    }

    override fun close() {
        tunnel.close()
    }
}

private class UniffiTunnelCancel(
    val handle: CancelHandle,
) : TunnelCancel {
    override fun cancel() {
        handle.cancel()
    }

    override fun close() {
        handle.close()
    }
}
