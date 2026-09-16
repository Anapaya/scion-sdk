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

import java.net.InetSocketAddress

/**
 * The `host:port` a `CONNECT` tunnel is opened to.
 *
 * The host is a DNS name or an IP literal, and is kept in lowercase. An IPv6 literal is kept in
 * brackets, and a scope (`fe80::1%wlan0`) is dropped. The port is 1 to 65535.
 *
 * Only the shape is checked here. Whether the host resolves is the stack's question, asked when
 * the tunnel is opened.
 *
 * @throws IllegalArgumentException if [host] is empty, carries `user@`, or has a character a
 *   host cannot, or if [port] is out of range.
 */
public class ScionHttp3Authority(
    host: String,
    public val port: Int,
) {
    /** The host, in lowercase, an IPv6 literal in brackets. */
    public val host: String

    init {
        require(port in 1..65535) { "$port is not a port from 1 to 65535" }
        val trimmed = host.trim()
        require(trimmed.isNotEmpty()) { "an authority needs a host" }
        require(
            '@' !in trimmed,
        ) { "\"$trimmed\" carries user information, which an authority cannot" }
        require(trimmed.none { it.isWhitespace() || it in "/?#" }) {
            "\"$trimmed\" is not a host: it has a character a host cannot have"
        }
        this.host = normalizeHost(trimmed).lowercase()
    }

    /** `host:port`, which is what the stack receives. */
    override fun toString(): String = "$host:$port"

    override fun equals(other: Any?): Boolean =
        this === other || (other is ScionHttp3Authority && host == other.host && port == other.port)

    override fun hashCode(): Int = 31 * host.hashCode() + port

    public companion object {
        /**
         * Parses `host:port`, with an IPv6 host in brackets: `[::1]:443`.
         *
         * @throws IllegalArgumentException if [text] has no port, or either part is refused by
         *   the constructor.
         */
        @JvmStatic
        public fun parse(text: String): ScionHttp3Authority {
            val trimmed = text.trim()
            val colon = trimmed.lastIndexOf(':')
            require(colon > 0 && !trimmed.endsWith(']')) {
                "\"$trimmed\" has no port: expected host:port, with an IPv6 host in brackets"
            }
            val port =
                trimmed.substring(colon + 1).toIntOrNull()
                    ?: throw IllegalArgumentException(
                        "\"${trimmed.substring(colon + 1)}\" is not a port from 1 to 65535",
                    )
            return ScionHttp3Authority(trimmed.substring(0, colon), port)
        }

        /**
         * The authority a socket endpoint names.
         *
         * `hostString` and never `hostName`: the latter reverse-resolves an address literal, and
         * the former keeps the name an endpoint was created with, or the address it carries.
         */
        internal fun of(endpoint: InetSocketAddress): ScionHttp3Authority =
            ScionHttp3Authority(endpoint.hostString, endpoint.port)

        /** A host with a colon can only be an IPv6 literal. */
        private fun normalizeHost(host: String): String {
            if (':' !in host) return host
            val literal =
                if (host.startsWith('[')) {
                    require(host.endsWith(']') && host.indexOf(']') == host.length - 1) {
                        "\"$host\" opens a bracket it does not close"
                    }
                    host.substring(1, host.length - 1)
                } else {
                    require(']' !in host) { "\"$host\" closes a bracket it never opened" }
                    host.substringBefore('%')
                }
            require(isIpv6Literal(literal)) { "\"$host\" is not a DNS name or an IP literal" }
            return "[$literal]"
        }

        /**
         * Whether [text] is an IPv6 address: up to eight groups of one to four hex digits, one
         * `::` standing in for any number of zero groups, and optionally a dotted IPv4 address in
         * place of the last two groups.
         */
        private fun isIpv6Literal(text: String): Boolean {
            val halves = text.split("::")
            if (halves.size > 2) return false
            val compressed = halves.size == 2
            val groups = halves.flatMap { if (it.isEmpty()) emptyList() else it.split(':') }
            if (groups.isEmpty()) return compressed
            var count = 0
            groups.forEachIndexed { index, group ->
                if (index == groups.lastIndex && '.' in group) {
                    if (!isIpv4Literal(group)) return false
                    count += 2
                } else {
                    if (group.isEmpty() || group.length > 4) return false
                    if (!group.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return false
                    count += 1
                }
            }
            return if (compressed) count <= 7 else count == 8
        }

        private fun isIpv4Literal(text: String): Boolean {
            val parts = text.split('.')
            return parts.size == 4 &&
                parts.all { part ->
                    part.length in 1..3 &&
                        part.all { it.isDigit() } &&
                        part.toInt() <= 255
                }
        }
    }
}
