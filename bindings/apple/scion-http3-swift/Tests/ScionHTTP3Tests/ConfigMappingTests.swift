// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

final class ConfigMappingTests: XCTestCase {
    private let base = FfiConfig(
        endhostApiUrl: "",
        authToken: nil,
        preferredUnderlay: nil,
        discovery: FfiDiscoveryConfig(maxGroups: 3, apisPerGroup: 2, perGroupDelayMs: 7),
        snap: FfiSnapConfig(dpIndex: nil, staticIdentity: nil),
        udp: FfiUdpConfig(outboundIps: [], nextHopResolverFetchIntervalMs: 11),
        trust: .systemDefault,
        dnsOverrides: [],
        connectTimeoutMs: 10_001,
        requestTimeoutMs: 30_001,
        idleConnectionTimeoutMs: 25_001,
        maxOrigins: 8,
        connectionAttemptDelayMs: 251,
        maxResponseBodyBytes: 16_000_001)

    func testEverySettingReachesItsField() throws {
        var configuration = ScionHttp3Client.Configuration(
            endhostApi: "https://endhost-api.example.org", authToken: "token")
        configuration.preferredUnderlay = .snap
        configuration.snap.dataPlaneIndex = 2
        configuration.snap.staticIdentity = Data(repeating: 7, count: 32)
        configuration.udp.outboundIps = ["10.0.0.5"]
        configuration.udp.nextHopResolverFetchInterval = 3
        configuration.trust = .insecureNoVerify
        configuration.connectTimeout = 1
        configuration.requestTimeout = 2
        configuration.idleConnectionTimeout = 4
        configuration.connectionAttemptDelay = 0.25
        configuration.maxOrigins = 5
        configuration.maxResponseBodyBytes = 6

        let expected = FfiConfig(
            endhostApiUrl: "https://endhost-api.example.org",
            authToken: "token",
            preferredUnderlay: .snap,
            discovery: base.discovery,
            snap: FfiSnapConfig(dpIndex: 2, staticIdentity: Data(repeating: 7, count: 32)),
            udp: FfiUdpConfig(outboundIps: ["10.0.0.5"], nextHopResolverFetchIntervalMs: 3_000),
            trust: .insecureNoVerify,
            dnsOverrides: [],
            connectTimeoutMs: 1_000,
            requestTimeoutMs: 2_000,
            idleConnectionTimeoutMs: 4_000,
            maxOrigins: 5,
            connectionAttemptDelayMs: 250,
            maxResponseBodyBytes: 6)
        XCTAssertEqual(try ClientSettings(configuration).applyTo(base), expected)
    }

    func testAnUnsetSettingKeepsTheStacksDefault() throws {
        var expected = base
        expected.endhostApiUrl = "https://endhost-api.example.org"
        XCTAssertEqual(try settings().applyTo(base), expected)
    }

    func testDurationsCrossAsWholeMilliseconds() throws {
        var configuration = configuration()
        configuration.connectTimeout = 0.0015
        XCTAssertEqual(try ClientSettings(configuration).applyTo(base).connectTimeoutMs, 2)
        XCTAssertEqual(milliseconds(1.25), 1_250)
    }

    func testDnsOverridesCrossAsTextSortedByHost() throws {
        let one = try ScionAddress("1-ff00:0:110,10.0.0.1")
        let two = try ScionAddress("1-ff00:0:110,10.0.0.2")
        let three = try ScionAddress("1-ff00:0:111,10.0.0.3")
        var configuration = configuration()
        configuration.dnsOverrides = ["b.example": [one], "a.example": [two, three]]
        let overrides = try ClientSettings(configuration).applyTo(base).dnsOverrides
        XCTAssertEqual(
            overrides,
            [
                FfiDnsOverride(host: "a.example", addresses: [two.description, three.description]),
                FfiDnsOverride(host: "b.example", addresses: [one.description]),
            ])
        XCTAssertTrue(try settings().applyTo(base).dnsOverrides.isEmpty)
    }

    func testPinnedAnchorsCrossAsTheirBytes() throws {
        let settings = try settings(trust: .pinned(validPem))
        XCTAssertEqual(settings.applyTo(base).trust, .pem(pem: validPem))
    }

    func testTheDefaultsAreNotRestatedHere() throws {
        let settings = try settings()
        XCTAssertNil(settings.connectTimeout)
        XCTAssertNil(settings.maxOrigins)
        XCTAssertNil(settings.preferredUnderlay)
    }
}
