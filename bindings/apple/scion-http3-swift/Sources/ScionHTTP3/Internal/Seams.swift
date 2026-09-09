// Copyright 2026 Anapaya Systems
import Foundation

// Everything the library needs from the platform as protocols.
//
// There is one implementation of each in `ApplePlatform.swift`.

/// A clock that keeps counting while the device sleeps in seconds from an arbitrary origin.
protocol MonotonicClock: Sendable {
    func now() -> TimeInterval
}

/// Where the library's own diagnostics go.
protocol LibraryLog: Sendable {
    func error(_ message: String)
    func warn(_ message: String)
    func debug(_ message: String)
}

/// Watches which network path the device sends over.
protocol NetworkMonitor: Sendable {
    /// Starts watching, delivering observations to `onObserved`.
    func start(onObserved: @escaping @Sendable (NetworkIdentity) -> Void)

    /// The path in use right now or nil if there is none or it cannot be determined.
    func currentIdentity() -> NetworkIdentity?

    /// Stops watching. Idempotent, and safe to call from any thread.
    func stop()
}
