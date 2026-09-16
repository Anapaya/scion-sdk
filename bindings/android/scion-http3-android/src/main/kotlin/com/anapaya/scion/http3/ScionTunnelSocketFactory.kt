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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

/**
 * A `javax.net.SocketFactory` that creates [ScionTunnelSocket]s over one client.
 *
 * For OkHttp: `OkHttpClient.Builder().socketFactory(ScionTunnelSocketFactory(client))`. OkHttp
 * asks for an unconnected socket and connects it to an `InetSocketAddress` it built from the
 * address its `Dns` returned. The socket takes the host name from that address. A host that lives
 * on SCION alone has no address to look up, so give OkHttp a `Dns` that keeps the name on a
 * placeholder, and that fails for every other host:
 *
 * ```kotlin
 * val scionHosts = setOf("chat.example.org")
 * val okHttp = OkHttpClient.Builder()
 *     .socketFactory(ScionTunnelSocketFactory(client))
 *     .dns(object : Dns {
 *         override fun lookup(hostname: String): List<InetAddress> {
 *             if (hostname !in scionHosts) throw UnknownHostException(hostname)
 *             return listOf(InetAddress.getByAddress(hostname, byteArrayOf(0, 0, 0, 0)))
 *         }
 *     })
 *     .build()
 * ```
 *
 * The two settings belong together. The placeholder is never connected to by this factory, but a
 * client that has the `Dns` without the factory connects a platform socket to `0.0.0.0` on the
 * device itself. Set both on one client and let the `Dns` refuse the hosts that are not meant
 * for SCION rather than hand them the placeholder. A client derived with `newBuilder()` inherits
 * both.
 */
public class ScionTunnelSocketFactory(
    private val client: ScionHttp3Client,
) : SocketFactory() {
    override fun createSocket(): Socket = ScionTunnelSocket(client)

    override fun createSocket(
        host: String,
        port: Int,
    ): Socket = connected(InetSocketAddress.createUnresolved(host, port))

    override fun createSocket(
        host: String,
        port: Int,
        localHost: InetAddress?,
        localPort: Int,
    ): Socket = createSocket(host, port)

    override fun createSocket(
        host: InetAddress,
        port: Int,
    ): Socket = connected(InetSocketAddress(host, port))

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress?,
        localPort: Int,
    ): Socket = createSocket(address, port)

    private fun connected(endpoint: InetSocketAddress): Socket {
        val socket = ScionTunnelSocket(client)
        try {
            socket.connect(endpoint)
        } catch (e: IOException) {
            socket.close()
            throw e
        }
        return socket
    }
}
