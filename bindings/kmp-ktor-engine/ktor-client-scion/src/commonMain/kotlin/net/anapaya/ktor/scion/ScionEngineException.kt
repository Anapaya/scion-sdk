// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion

import kotlinx.io.IOException
import uniffi.ktor_scion_core.CoreException

/**
 * A request that the Rust library rejected or could not finish.
 *
 * Ktor treats an [IOException] as a transport failure, so the error of the
 * Rust library is wrapped rather than thrown as it comes. [cause] names the
 * failure kind.
 */
public class ScionEngineException internal constructor(
    message: String,
    public override val cause: CoreException,
) : IOException(message)
