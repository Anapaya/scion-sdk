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
 * A SCION address, for addressing a host directly instead of resolving its name.
 *
 * This is an escape hatch, and the only type in the request path that names a SCION concept. Almost
 * every application should let the library resolve the URL's host instead; see
 * [ScionHttp3Request.Builder.target] for when this is the right tool.
 *
 * The text form is `<isd>-<as>,<host>`, for example `1-ff00:0:110,10.0.0.1`.
 *
 * Only the shape is checked here.
 */
public class ScionAddress private constructor(
    private val text: String,
) {
    override fun toString(): String = text

    override fun equals(other: Any?): Boolean =
        this === other || (other is ScionAddress && text == other.text)

    override fun hashCode(): Int = text.hashCode()

    public companion object {
        /**
         * Parses the `<isd>-<as>,<host>` form.
         *
         * @throws IllegalArgumentException if [text] is not that shape, or carries a port.
         */
        @JvmStatic
        public fun parse(text: String): ScionAddress {
            val trimmed = text.trim()
            require(trimmed.isNotEmpty()) { "a SCION address cannot be empty" }

            val comma = trimmed.indexOf(',')
            require(comma > 0 && comma < trimmed.length - 1) {
                "\"$trimmed\" is not a SCION address: expected <isd>-<as>,<host>, " +
                    "for example 1-ff00:0:110,10.0.0.1"
            }

            val isdAs = trimmed.substring(0, comma)
            require(
                isdAs.count { it == '-' } == 1 && !isdAs.startsWith('-') && !isdAs.endsWith('-'),
            ) {
                "\"$isdAs\" is not an ISD-AS: expected <isd>-<as>, for example 1-ff00:0:110"
            }

            requireNoPort(trimmed, trimmed.substring(comma + 1))
            return ScionAddress(trimmed)
        }

        private fun requireNoPort(
            whole: String,
            host: String,
        ) {
            val hasPort =
                if (host.startsWith('[')) {
                    // A bracketed IPv6 host: anything after the bracket can only be a port.
                    val end = host.indexOf(']')
                    require(end > 0) { "\"$host\" opens a bracket it never closes" }
                    end != host.length - 1
                } else {
                    // Counting colons, rather than looking for a dot as well: a bare IPv6 host needs
                    // at least two, so exactly one can only separate a host from a port. Judging by
                    // the dot instead would take "::ffff:10.0.0.1" for an address with a port, and
                    // let "localhost:8080" through as a host.
                    val colons = host.count { it == ':' }
                    val afterColon = host.substringAfterLast(':')
                    colons == 1 && afterColon.isNotEmpty() && afterColon.all(Char::isDigit)
                }
            require(!hasPort) {
                "\"$whole\" carries a port. A target addresses a host only; the port comes from " +
                    "the request URL."
            }
        }
    }
}
