// Copyright 2026 Anapaya Systems
import Foundation
import Network
import os

// The implementations of the seams in `Seams.swift`.

/// The system's monotonic clock, which keeps counting while the device sleeps.
struct SystemClock: MonotonicClock {
    func now() -> TimeInterval {
        TimeInterval(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000_000
    }
}

/// Diagnostics through the unified logging system.
struct OSLibraryLog: LibraryLog {
    private static let subsystem = "net.anapaya.scion.http3"
    private static let category = "ScionHttp3"

    func error(_ message: String) {
        Logger(subsystem: Self.subsystem, category: Self.category)
            .error("\(message, privacy: .public)")
    }

    func warn(_ message: String) {
        Logger(subsystem: Self.subsystem, category: Self.category)
            .warning("\(message, privacy: .public)")
    }

    func debug(_ message: String) {
        Logger(subsystem: Self.subsystem, category: Self.category)
            .debug("\(message, privacy: .public)")
    }
}

/// Watches the path the device sends over through `NWPathMonitor`.
final class PathNetworkMonitor: NetworkMonitor {
    private let queue = DispatchQueue(label: "net.anapaya.scion.http3.path-monitor")
    private let monitor = Locked<NWPathMonitor?>(nil)

    func start(onObserved: @escaping @Sendable (NetworkIdentity) -> Void) {
        monitor.withLock { current in
            guard current == nil else { return }
            let started = NWPathMonitor()
            started.pathUpdateHandler = { path in
                onObserved(NetworkIdentity(path))
            }
            started.start(queue: queue)
            current = started
        }
    }

    func currentIdentity() -> NetworkIdentity? {
        monitor.withLock { $0.map { NetworkIdentity($0.currentPath) } }
    }

    func stop() {
        let stopped = monitor.withLock { current -> NWPathMonitor? in
            defer { current = nil }
            return current
        }
        stopped?.cancel()
    }
}

extension NetworkIdentity {
    init(_ path: NWPath) {
        let interface = path.availableInterfaces.first
        self.init(
            interfaceName: interface?.name,
            interfaceType: interface.map { Self.describe($0.type) },
            gateways: path.gateways.map { String(describing: $0) },
            satisfied: path.status == .satisfied)
    }

    private static func describe(_ type: NWInterface.InterfaceType) -> String {
        switch type {
        case .wifi: return "wifi"
        case .cellular: return "cellular"
        case .wiredEthernet: return "wiredEthernet"
        case .loopback: return "loopback"
        case .other: return "other"
        @unknown default: return "unknown"
        }
    }
}
