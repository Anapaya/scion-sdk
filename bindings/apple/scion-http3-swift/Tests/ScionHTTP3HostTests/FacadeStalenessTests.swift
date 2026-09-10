// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// A network change the platform reports marks the client stale and the next request rebuilds.
final class FacadeStalenessTests: XCTestCase {
    private var server: TestServer!
    private var monitor: ScriptedNetworkMonitor!
    private var client: ScionHttp3Client!

    override func setUpWithError() throws {
        server = try TestServer.start()
        monitor = ScriptedNetworkMonitor(current: wifi)
        var configuration = ScionHttp3Client.Configuration(
            endhostApi: server.endpoints.endhostApiUrl, authToken: server.endpoints.authToken)
        configuration.trust = try .pinned(Data(server.endpoints.caPem.utf8))
        configuration.connectTimeout = 15
        // Short, so that a client which did not rebuild fails while someone is still watching.
        configuration.requestTimeout = 5
        client = ScionHttp3Client(
            settings: try ClientSettings(configuration), backends: uniffiBackendFactory,
            monitor: monitor, clock: SystemClock(), log: OSLibraryLog())
    }

    override func tearDown() async throws {
        await client.shutdown()
        server.stop()
    }

    func testAChangedPathRebuildsConnectivityOnTheNextRequest() async throws {
        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
        XCTAssertTrue(monitor.isStarted, "the client did not start watching the network")

        try await server.restartServer()

        // Past the debounce window since the first observation, so that the change is marked
        // rather than remembered.
        try await Task.sleep(nanoseconds: 600_000_000)
        monitor.deliver(cellular)

        let recovered = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(recovered.code, 200)
    }
}

private let wifi = NetworkIdentity(
    interfaceName: "en0", interfaceType: "wifi", gateways: ["192.168.1.1"], satisfied: true)
private let cellular = NetworkIdentity(
    interfaceName: "pdp_ip0", interfaceType: "cellular", gateways: ["10.0.0.1"], satisfied: true)

/// A monitor whose observations the test delivers.
private final class ScriptedNetworkMonitor: NetworkMonitor {
    private struct State {
        var current: NetworkIdentity
        var observer: (@Sendable (NetworkIdentity) -> Void)?
    }

    private let state: Locked<State>

    init(current: NetworkIdentity) {
        state = Locked(State(current: current))
    }

    var isStarted: Bool {
        state.withLock { $0.observer != nil }
    }

    func start(onObserved: @escaping @Sendable (NetworkIdentity) -> Void) {
        let current = state.withLock { s in
            s.observer = onObserved
            return s.current
        }
        // The platform reports the current path as soon as it is asked to watch.
        onObserved(current)
    }

    func currentIdentity() -> NetworkIdentity? {
        state.withLock { $0.current }
    }

    func stop() {
        state.withLock { $0.observer = nil }
    }

    /// Delivers an observation the way the platform would.
    func deliver(_ identity: NetworkIdentity) {
        let observer = state.withLock { s in
            s.current = identity
            return s.observer
        }
        guard let observer else {
            return XCTFail("the monitor was never started")
        }
        observer(identity)
    }
}
