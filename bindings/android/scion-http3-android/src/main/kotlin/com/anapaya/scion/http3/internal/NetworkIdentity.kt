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

/**
 * What makes one network different from another, for the purpose of deciding that connectivity has
 * to be rebuilt.
 *
 * Not just the network's handle. Android keeps the same handle across a DHCP renewal, a move between
 * access points on one network, and a cellular re-attach that holds on to its agent, and every one
 * of those changes the local address. A changed local address is exactly what invalidates the
 * sockets and the SNAP tunnel underneath, so the addresses are part of the identity.
 *
 * Capabilities are deliberately absent. Metered status, signal strength and validation state all
 * change constantly on a moving device without meaning anything has to be rebuilt, and leaving them
 * out is what makes that noise disappear structurally rather than through a list of callbacks to
 * ignore. DNS servers are left out for the same reason: they change on their own schedule, and a
 * resolution cache expiring is not worth a rebuild.
 *
 * @property handle the network's `Network.getNetworkHandle()`, which is stable for one network and
 *   never reused within a boot.
 * @property interfaceName the link's interface name, when the platform reports one.
 * @property addresses the local addresses, normalized. See [normalizeAddress].
 * @property validated whether the platform has confirmed the network actually reaches anything.
 *   Carried on the observation rather than in the identity, so a network that merely finishes
 *   validating is not mistaken for a different network.
 */
internal data class NetworkIdentity(
    val handle: Long,
    val interfaceName: String?,
    val addresses: Set<String>,
    val validated: Boolean,
) {
    /** Whether this observation says anything about a usable network. */
    val isUsable: Boolean get() = validated && addresses.isNotEmpty()

    /**
     * Whether this is the same network as [other], ignoring whether either was validated yet.
     *
     * This is the comparison the staleness decision uses, so that a network reporting itself
     * validated after being reported available does not read as a change.
     */
    fun isSameNetworkAs(other: NetworkIdentity): Boolean =
        handle == other.handle &&
            interfaceName == other.interfaceName &&
            addresses == other.addresses

    internal companion object {
        /**
         * Normalizes one local address to `address/prefix`, or null for an address that says
         * nothing about identity.
         *
         * Two rules earn their place here:
         *
         * IPv4 link-local (`169.254/16`) is dropped, because it is what the platform assigns when
         * it has no address at all, and it appears and disappears without the network changing.
         *
         * IPv6 addresses are reduced to their prefix. Android rotates privacy addresses within one
         * prefix on its own schedule, and a rotation invalidates nothing: the old address stays
         * usable while it is deprecated. Keeping the host bits would turn every rotation into a
         * rebuild of all connectivity.
         */
        fun normalizeAddress(
            address: ByteArray,
            prefixLength: Int,
        ): String? {
            if (address.size == 4) {
                if (address[0] == 169.toByte() && address[1] == 254.toByte()) return null
                return "${address.joinToString(
                    ".",
                ) { (it.toInt() and 0xFF).toString() }}/$prefixLength"
            }
            if (address.size == 16) {
                // fe80::/10, the link-local range, which every interface has and which never
                // distinguishes one network from another.
                if (address[0] == 0xFE.toByte() &&
                    (address[1].toInt() and 0xC0) == 0x80
                ) {
                    return null
                }
                return "${hexPrefix(address, prefixLength)}/$prefixLength"
            }
            return null
        }

        private fun hexPrefix(
            address: ByteArray,
            prefixLength: Int,
        ): String {
            val masked = address.copyOf()
            for (i in masked.indices) {
                val bitsBefore = i * 8
                val keep = (prefixLength - bitsBefore).coerceIn(0, 8)
                val mask = if (keep == 0) 0 else (0xFF shl (8 - keep)) and 0xFF
                masked[i] = (masked[i].toInt() and mask).toByte()
            }
            return masked.joinToString("") { "%02x".format(it) }
        }
    }
}
