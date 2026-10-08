// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri

internal actual fun initPlatformTrust() {
    AndroidTrust.ensureInitialized()
}

/**
 * Hands the JVM and the application context to `rustls-platform-verifier` in
 * the Rust library.
 */
internal object AndroidTrust {
    @Volatile
    internal var context: Context? = null

    private val initialized by lazy {
        val context = checkNotNull(context) {
            "no application context: ScionTrustProvider did not run in this " +
                "process. Android runs it only in the main process, and only " +
                "if the merged manifest keeps it."
        }

        // The JVM binds `init` only in a library that System.loadLibrary
        // loaded. JNA loads the Rust library through its own dlopen. Both
        // loads get the same instance from the dynamic linker, so the UniFFI
        // calls see the state that `init` sets.
        System.loadLibrary("ktor_scion_core")
        init(context)
    }

    fun ensureInitialized() = initialized

    @JvmStatic
    private external fun init(context: Context)
}

/**
 * Stores the application context for [AndroidTrust].
 *
 * The library manifest declares this provider, so the manifest merger adds it
 * to every app that uses the engine. Android creates it in the main process,
 * before `Application.onCreate`. It does not load the Rust library, so an app
 * that starts no engine pays nothing at startup.
 */
internal class ScionTrustProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        AndroidTrust.context = context?.applicationContext
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
