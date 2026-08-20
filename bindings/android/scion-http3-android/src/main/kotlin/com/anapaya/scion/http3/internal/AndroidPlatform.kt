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

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.SystemClock
import android.util.Log
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The implementations of the seams in `Seams.kt`.
 *
 * These files, and only these, import `android.*`. Everything here is plumbing: it reads what the
 * framework says and hands it on. Nothing here decides anything, which matters because this is also
 * the code the unit tier cannot reach, and is covered by the instrumented tests instead.
 */

internal const val LOG_TAG: String = "ScionHttp3"

/** Elapsed real time, which keeps counting while the device sleeps. */
internal object AndroidClock : MonotonicClock {
    override fun elapsedRealtimeMillis(): Long = SystemClock.elapsedRealtime()
}

/** Diagnostics through logcat. */
internal object AndroidLog : LibraryLog {
    override fun error(message: String) {
        Log.e(LOG_TAG, message)
    }

    override fun warn(message: String) {
        Log.w(LOG_TAG, message)
    }

    override fun debug(message: String) {
        Log.d(LOG_TAG, message)
    }
}

/** Whether the host application is debuggable. */
internal class AndroidDebugGuard(
    private val context: Context,
) : DebugGuard {
    override fun isDebuggable(): Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
}

/**
 * The platform's trust anchors, read through the default trust manager.
 *
 * Through `TrustManagerFactory` rather than by walking the `AndroidCAStore` keystore. That keystore
 * also holds authorities the *user* installed, which an application targeting API 24 or later does
 * not trust by default; handing them to the TLS stack would quietly make this client accept
 * certificates every other client in the application rejects. The default trust manager already
 * applies the platform's rules, including the application's network security configuration, and
 * hands back certificates that are already parsed.
 *
 * It is also plain JDK API, which is why this class is the one piece of trust-anchor handling that
 * runs identically in a desktop unit test, where it yields the JDK's own authorities.
 */
internal class AndroidSystemTrustStore : SystemTrustStore {
    override fun anchorsPem(): ByteArray {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        val anchors =
            factory.trustManagers
                .filterIsInstance<X509TrustManager>()
                .flatMap { it.acceptedIssuers.asList() }
                .distinct()
        return PemEncoder.encode(anchors.filterIsInstance<X509Certificate>())
    }
}

/**
 * Watches the default network through [ConnectivityManager].
 *
 * The *default* network specifically, not every network matching a request: what matters here is the
 * network the application's own sockets go out over, and that is the default one by definition. A
 * broader registration would also report a Wi-Fi network appearing while cellular is still carrying
 * traffic, which changes nothing about the connectivity in use.
 *
 * Callbacks are registered without a `Handler`, because that overload needs API 26 and this library
 * supports 24. They therefore arrive on a thread the framework shares across the whole process, so
 * each one does as little as possible: read what changed, and hand an observation upwards.
 */
internal class ConnectivityNetworkMonitor(
    context: Context,
    private val log: LibraryLog,
) : NetworkMonitor {
    private val manager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val lock = Any()
    private var callback: ConnectivityManager.NetworkCallback? = null

    // The framework reports capabilities and link properties separately, so an observation can only
    // be assembled once both have arrived for the same network. Single-slot: a default-network
    // callback reporting a new network means the old one is no longer the default.
    private var handle: Long? = null
    private var validated = false
    private var linkProperties: LinkProperties? = null

    override fun start(onObserved: (NetworkIdentity) -> Unit) {
        val callback =
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    // Deliberately emits nothing. At this point the network is not validated and its
                    // link properties may still be empty, and rebuilding onto it would discard
                    // working connectivity for a handshake that cannot succeed yet.
                    synchronized(lock) {
                        if (handle != network.networkHandle) {
                            handle = network.networkHandle
                            validated = false
                            linkProperties = null
                        }
                    }
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) {
                    val observation =
                        synchronized(lock) {
                            adoptHandle(network)
                            validated = capabilities.isUsable()
                            observation()
                        }
                    observation?.let(onObserved)
                }

                override fun onLinkPropertiesChanged(
                    network: Network,
                    properties: LinkProperties,
                ) {
                    // The only callback that catches a network keeping its identity while its
                    // addresses change, which is what a DHCP renewal or a move between access points
                    // on one network looks like.
                    val observation =
                        synchronized(lock) {
                            adoptHandle(network)
                            linkProperties = properties
                            observation()
                        }
                    observation?.let(onObserved)
                }

                override fun onLost(network: Network) {
                    // Logged and nothing else. Keeping the last observation is what makes a brief
                    // loss that recovers onto the same network cost nothing, and acting here would
                    // rebuild while there is no network to rebuild onto.
                    log.debug("the default network was lost")
                }
            }

        synchronized(lock) {
            if (this.callback != null) return
            try {
                manager.registerDefaultNetworkCallback(callback)
                this.callback = callback
            } catch (e: RuntimeException) {
                // A SecurityException on a device that mishandles ACCESS_NETWORK_STATE, or the
                // framework's limit on callbacks per application. Neither is fatal: without
                // callbacks, a change is caught by the idle check on the next request instead.
                log.warn(
                    "could not watch for network changes ($e). Connectivity will still be " +
                        "rebuilt after an idle period, but not immediately on a change.",
                )
            }
        }
    }

    override fun currentIdentity(): NetworkIdentity? {
        val network = manager.activeNetwork ?: return null
        val properties = manager.getLinkProperties(network) ?: return null
        val capabilities = manager.getNetworkCapabilities(network)
        return identityOf(
            handle = network.networkHandle,
            properties = properties,
            // The same judgement the callback path makes, and deliberately not a looser one: a probe
            // that called a network usable where a callback would not would make the idle check
            // disagree with the callbacks about what the current network even is.
            validated = capabilities != null && capabilities.isUsable(),
        )
    }

    override fun stop() {
        val callback =
            synchronized(lock) {
                this.callback.also { this.callback = null }
            } ?: return
        try {
            manager.unregisterNetworkCallback(callback)
        } catch (e: IllegalArgumentException) {
            // Already gone. Not worth surfacing: the only thing that matters is that it is not
            // registered any more.
            log.debug("the network callback was already unregistered ($e)")
        }
    }

    /** Assumes the reported network is the default one, since that is what was registered for. */
    private fun adoptHandle(network: Network) {
        if (handle != network.networkHandle) {
            handle = network.networkHandle
            validated = false
            linkProperties = null
        }
    }

    private fun observation(): NetworkIdentity? {
        val handle = handle ?: return null
        val properties = linkProperties ?: return null
        val identity = identityOf(handle, properties, validated)
        // Held back until the network is usable, so the intermediate states of one handover do not
        // read as several changes.
        return identity.takeIf { it.isUsable }
    }

    /** Validated and able to reach the internet, which is what "usable" means for a request. */
    private fun NetworkCapabilities.isUsable(): Boolean =
        hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
            hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)

    private fun identityOf(
        handle: Long,
        properties: LinkProperties,
        validated: Boolean,
    ): NetworkIdentity =
        NetworkIdentity(
            handle = handle,
            interfaceName = properties.interfaceName,
            addresses =
                properties.linkAddresses
                    .mapNotNull {
                        NetworkIdentity.normalizeAddress(it.address.address, it.prefixLength)
                    }.toSortedSet(),
            validated = validated,
        )
}
