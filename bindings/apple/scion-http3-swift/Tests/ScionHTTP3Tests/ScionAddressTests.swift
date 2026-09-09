// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

final class ScionAddressTests: XCTestCase {
    func testTheTextIsKept() throws {
        let plain = try ScionAddress("1-ff00:0:110,10.0.0.1")
        XCTAssertEqual(plain.description, "1-ff00:0:110,10.0.0.1")
        let padded = try ScionAddress("  1-ff00:0:110,10.0.0.1 ")
        XCTAssertEqual(padded.description, "1-ff00:0:110,10.0.0.1")
    }

    func testIPv6HostsAreAccepted() throws {
        XCTAssertNoThrow(try ScionAddress("1-ff00:0:110,[fd00::1]"))
        XCTAssertNoThrow(try ScionAddress("1-ff00:0:110,fd00::1"))
        XCTAssertNoThrow(try ScionAddress("1-ff00:0:110,::ffff:10.0.0.1"))
    }

    func testAPortIsRefused() {
        let withPorts = [
            "1-ff00:0:110,10.0.0.1:443", "1-ff00:0:110,[fd00::1]:443", "1-ff00:0:110,host:8080",
        ]
        for text in withPorts {
            let error = thrown { try ScionAddress(text) } as? ScionHttp3Error
            guard case .invalidRequest(let detail)? = error else {
                return XCTFail("\(text) was not refused: \(String(describing: error))")
            }
            XCTAssertTrue(detail.contains("carries a port"), detail)
        }
    }

    func testNonsenseIsRefused() {
        let nonsense = [
            "", "1-ff00:0:110", ",10.0.0.1", "1-ff00:0:110,", "ff00:0:110,10.0.0.1",
            "1-2-3,10.0.0.1",
        ]
        for text in nonsense {
            let error = thrown { try ScionAddress(text) }
            XCTAssertTrue(error is ScionHttp3Error, "\(text) was accepted")
        }
    }

    func testAnUnclosedBracketIsRefused() {
        let error = thrown { try ScionAddress("1-ff00:0:110,[fd00::1") } as? ScionHttp3Error
        XCTAssertTrue(error?.detail.contains("never closes") ?? false)
    }

    func testValueEquality() throws {
        let one = try ScionAddress("1-ff00:0:110,10.0.0.1")
        XCTAssertEqual(one, try ScionAddress("1-ff00:0:110,10.0.0.1"))
        XCTAssertNotEqual(one, try ScionAddress("1-ff00:0:110,10.0.0.2"))
    }
}
