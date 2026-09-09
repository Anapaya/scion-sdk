// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// What building a client does, and what it refuses.
final class ClientConstructionTests: XCTestCase {
    func testBuildingAClientBuildsNoBackendAndStartsNoMonitor() throws {
        let factory = FakeBackendFactory()
        let monitor = FakeNetworkMonitor()
        _ = try client(factory: factory, monitor: monitor)

        XCTAssertEqual(factory.creations.withLock { $0 }, 0)
        XCTAssertEqual(monitor.starts, 0)
    }

    func testThePublicInitializerPerformsNoIO() throws {
        let client = try ScionHttp3Client(endhostApi: "http://127.0.0.1:8041")
        XCTAssertFalse(client.isShutDown)

        var configuration = ScionHttp3Client.Configuration(
            endhostApi: "https://endhost-api.example.org", authToken: "token")
        configuration.connectTimeout = 10
        configuration.requestTimeout = 30
        configuration.idleConnectionTimeout = 60
        configuration.maxOrigins = 8
        configuration.connectionAttemptDelay = 0.25
        XCTAssertNoThrow(try ScionHttp3Client(configuration: configuration))
    }

    func testTheFirstRequestBuildsExactlyOneBackendAndStartsTheMonitorWithIt() async throws {
        let factory = FakeBackendFactory()
        let monitor = FakeNetworkMonitor()
        let client = try client(factory: factory, monitor: monitor)

        _ = try await client.execute(request())
        _ = try await client.execute(request())

        XCTAssertEqual(factory.creations.withLock { $0 }, 1)
        XCTAssertEqual(monitor.starts, 1)
        let settings = factory.settings.withLock { $0 }
        XCTAssertEqual(settings.first?.endhostApiUrl, "https://endhost-api.example.org")
    }

    func testTheEndhostApiIsRequired() {
        let error = thrown { try settings(endhostApi: "") } as? ScionHttp3Error
        guard case .invalidConfiguration(let detail)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertTrue(detail.contains("endhostApi is required"), detail)
    }

    func testAPlaintextEndhostApiIsAllowed() {
        // PocketSCION serves its endhost API in plaintext.
        XCTAssertNoThrow(try settings(endhostApi: "http://127.0.0.1:8041"))
    }

    func testAnEndhostApiThatIsNotAnHttpUrlIsRefused() {
        let urls = [
            "endhost-api.example.org", "ftp://endhost-api.example.org", "https://", "::not a url",
        ]
        for url in urls {
            let error = thrown { try settings(endhostApi: url) }
            XCTAssertTrue(error is ScionHttp3Error, "\(url) was accepted")
        }
    }

    func testEachRejectedSettingNamesItself() {
        func rejected(_ name: String, _ change: (inout ScionHttp3Client.Configuration) -> Void) {
            var configuration = configuration()
            change(&configuration)
            let error = thrown { try ClientSettings(configuration) } as? ScionHttp3Error
            guard case .invalidConfiguration(let detail)? = error else {
                return XCTFail("\(name) was accepted")
            }
            XCTAssertTrue(detail.contains(name), "\(name): \(detail)")
        }
        rejected("connectTimeout") { $0.connectTimeout = 0 }
        rejected("requestTimeout") { $0.requestTimeout = -1 }
        rejected("idleConnectionTimeout") { $0.idleConnectionTimeout = 0 }
        rejected("connectionAttemptDelay") { $0.connectionAttemptDelay = .nan }
        rejected("maxOrigins") { $0.maxOrigins = 0 }
        rejected("maxResponseBodyBytes") { $0.maxResponseBodyBytes = 0 }
        rejected("auth token") { $0.authToken = "" }
        rejected("data plane index") { $0.snap.dataPlaneIndex = -1 }
        rejected("32-byte") { $0.snap.staticIdentity = Data(repeating: 1, count: 31) }
        rejected("outbound IP") { $0.udp.outboundIps = ["10.0.0.5", " "] }
        rejected("nextHopResolverFetchInterval") { $0.udp.nextHopResolverFetchInterval = 0 }
    }

    func testTheIdleThresholdFollowsTheConfiguration() throws {
        XCTAssertEqual(try settings().idleThreshold, 50, "a heuristic of its own without a timeout")
        XCTAssertEqual(try settings(idleConnectionTimeout: 90).idleThreshold, 180)
        XCTAssertEqual(try settings(idleConnectionTimeout: 10).idleThreshold, 30)
    }

    func testTheConvenienceInitializerAndTheConfigurationAgree() throws {
        let fromValues = try ClientSettings(
            ScionHttp3Client.Configuration(endhostApi: "https://e.example", authToken: "t"))
        var configuration = ScionHttp3Client.Configuration(endhostApi: "https://e.example")
        configuration.authToken = "t"
        XCTAssertEqual(fromValues, try ClientSettings(configuration))
    }
}
