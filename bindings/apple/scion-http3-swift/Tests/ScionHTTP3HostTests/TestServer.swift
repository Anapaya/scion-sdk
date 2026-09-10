// Copyright 2026 Anapaya Systems
import Foundation
import XCTest

/// A handle on a running `scion-h3-test-server`: a PocketSCION topology with an HTTP/3 server in
/// it, written in Rust.
///
/// Nothing here serves anything. On macOS it starts that process, reads the endpoints it prints,
/// and stops it again. A separate process because a SCION topology cannot be started from Swift.
/// On iOS a test cannot start a process either, so it attaches to a server that was started
/// outside the test and reads the same endpoints from the server's control API.
final class TestServer {
    /// Everything a client needs to reach this server.
    struct Endpoints: Decodable {
        let endhostApiUrl: String
        let authToken: String
        let baseUrl: String
        /// The server's SCION address, without a port: the port comes from the URL.
        let target: String
        let caPem: String
        /// An authority that signed nothing here, for a client that has to fail to verify.
        let wrongCaPem: String
        var controlUrl: String
        /// What carries the traffic, `udp` or `snap`.
        let underlay: String

        enum CodingKeys: String, CodingKey {
            case endhostApiUrl = "endhost_api_url"
            case authToken = "auth_token"
            case baseUrl = "base_url"
            case target
            case caPem = "ca_pem"
            case wrongCaPem = "wrong_ca_pem"
            case controlUrl = "control_url"
            case underlay
        }
    }

    /// A condition the caller has to fix.
    struct Failure: Error, CustomStringConvertible {
        let description: String

        init(_ description: String) {
            self.description = description
        }
    }

    /// The variable that names the server binary. Unset, the harness builds the server with cargo.
    static let binaryVariable = "SCION_H3_TEST_SERVER"

    /// The variable that names the control API of a server started outside the tests. Set, the
    /// harness attaches to that server instead of starting one.
    static let controlUrlVariable = "SCION_H3_TEST_SERVER_CONTROL_URL"

    static let defaultControlUrl = "http://127.0.0.1:7443"

    /// How long to wait for the topology to come up before giving up on it.
    private static let startTimeout: TimeInterval = 120
    private static let shutdownTimeout: TimeInterval = 10

    /// How long an attach keeps asking the control API before it reports the server missing.
    private static let attachWindow: TimeInterval = 10

    let endpoints: Endpoints

    /// Stops the server this harness started. Does nothing for a server it attached to.
    private let stopper: () -> Void

    private init(endpoints: Endpoints, stopper: @escaping () -> Void) {
        self.endpoints = endpoints
        self.stopper = stopper
    }

    /// The counters the server keeps read over its control API.
    struct Stats: Decodable {
        let endlessChunks: [String: Int]
        let endlessReleased: [String: Int]
        let uploadedBytes: [String: Int]
        let uploadsTruncated: [String: Int]
        let requests: [String: Int]
        let started: [String: Int]
        let restarts: Int

        enum CodingKeys: String, CodingKey {
            case endlessChunks = "endless_chunks"
            case endlessReleased = "endless_released"
            case uploadedBytes = "uploaded_bytes"
            case uploadsTruncated = "uploads_truncated"
            case requests
            case started
            case restarts
        }
    }

    /// How long `waitUntil` polls before it gives up.
    static let waitDeadline: TimeInterval = 30

    /// A URL on this server.
    func url(_ path: String) -> String {
        endpoints.baseUrl + path
    }

    /// Reads the counters. Plain HTTP over TCP to the control API, never SCION.
    func stats() async throws -> Stats {
        let (data, _) = try await URLSession.shared.data(
            from: URL(string: endpoints.controlUrl + "/stats")!)
        return try JSONDecoder().decode(Stats.self, from: data)
    }

    /// Stops the HTTP/3 server and starts it again at the same address, which a client sees as a
    /// reconnect.
    func restartServer() async throws {
        var request = URLRequest(url: URL(string: endpoints.controlUrl + "/restart-server")!)
        request.httpMethod = "POST"
        let (_, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Failure("restarting the server failed: \(response)")
        }
    }

    /// Polls the counters until `condition` holds, or fails naming `what` did not happen.
    func waitUntil(
        _ what: String, deadline: TimeInterval = waitDeadline,
        _ condition: (Stats) -> Bool
    ) async throws {
        let end = Date().addingTimeInterval(deadline)
        while true {
            if condition(try await stats()) {
                return
            }
            if Date() > end {
                throw Failure("\(what) did not happen within \(Int(deadline)) s")
            }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    /// A server started with the given extra arguments or the server the tests were told to
    /// attach to.
    static func start(arguments: [String] = []) throws -> TestServer {
        if let controlUrl = attachedControlUrl() {
            guard arguments.isEmpty else {
                throw XCTSkip(
                    "needs a server started with \(arguments.joined(separator: " ")) and the "
                        + "server at \(controlUrl) cannot be reconfigured")
            }
            return try attach(controlUrl: controlUrl)
        }
        return try spawn(arguments: arguments)
    }

    /// Stops the server.
    func stop() {
        stopper()
    }

    /// The control API to attach to, or nil to start a server here.
    private static func attachedControlUrl() -> String? {
        let environment = ProcessInfo.processInfo.environment
        #if os(macOS)
            return environment[controlUrlVariable]
        #else
            return environment[controlUrlVariable] ?? defaultControlUrl
        #endif
    }

    private static func attach(controlUrl: String) throws -> TestServer {
        guard let url = URL(string: controlUrl + "/info") else {
            throw Failure("\(controlUrlVariable) is not a URL: \(controlUrl)")
        }
        // Retried, because the harness that started the server may still be waiting for it.
        let deadline = Date().addingTimeInterval(attachWindow)
        var data: Data
        while true {
            do {
                data = try get(url)
                break
            } catch {
                if Date() > deadline {
                    throw Failure(
                        "\(url) could not be reached, and stayed unreachable for "
                            + "\(Int(attachWindow)) s: \(error). Start scion-h3-test-server with "
                            + "--control-port, or run tools/e2e.sh, which does. "
                            + "\(controlUrlVariable) names another control API.")
                }
                Thread.sleep(forTimeInterval: 0.5)
            }
        }
        var endpoints = try JSONDecoder().decode(Endpoints.self, from: data)
        // The address this side reached, which the server's own idea of it need not be.
        endpoints.controlUrl = controlUrl
        return TestServer(endpoints: endpoints, stopper: {})
    }

    /// A GET that blocks the caller so `start` can stay synchronous for `setUpWithError`.
    private static func get(_ url: URL) throws -> Data {
        let result = Box<Result<Data, any Error>>(.failure(Failure("no answer")))
        let done = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: url) { data, response, error in
            if let error {
                result.value = .failure(error)
            } else if let code = (response as? HTTPURLResponse)?.statusCode, code != 200 {
                result.value = .failure(Failure("GET \(url) answered \(code)"))
            } else {
                result.value = .success(data ?? Data())
            }
            done.signal()
        }.resume()
        done.wait()
        return try result.value.get()
    }

    #if os(macOS)
        private static func spawn(arguments: [String]) throws -> TestServer {
            let binary = try binaryPath()
            let process = Process()
            process.executableURL = URL(fileURLWithPath: binary)
            process.arguments = arguments
            let stdin = Pipe()
            let stdout = Pipe()
            process.standardInput = stdin
            process.standardOutput = stdout
            process.standardError = FileHandle.standardError
            try process.run()

            guard let description = firstLine(of: stdout.fileHandleForReading, within: startTimeout)
            else {
                process.terminate()
                throw Failure(
                    "\(binary) did not report its endpoints within \(Int(startTimeout)) s")
            }
            let endpoints = try JSONDecoder().decode(Endpoints.self, from: Data(description.utf8))
            return TestServer(endpoints: endpoints) {
                // Closing its input is how the server is asked to stop.
                try? stdin.fileHandleForWriting.close()
                let deadline = Date().addingTimeInterval(shutdownTimeout)
                while process.isRunning && Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.1)
                }
                if process.isRunning {
                    process.terminate()
                    process.waitUntilExit()
                }
            }
        }

        /// The first line the server prints, or nil if none arrived in time.
        private static func firstLine(of handle: FileHandle, within timeout: TimeInterval)
            -> String?
        {
            let result = Box<String?>(nil)
            let done = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                // Whole chunks, because the line can be longer than one pipe read.
                var buffer = Data()
                while true {
                    let chunk = handle.availableData
                    if chunk.isEmpty {
                        break
                    }
                    buffer.append(chunk)
                    if let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                        result.value = String(decoding: buffer[..<newline], as: UTF8.self)
                        break
                    }
                }
                done.signal()
            }
            guard done.wait(timeout: .now() + timeout) == .success else {
                return nil
            }
            return result.value
        }

        private static func binaryPath() throws -> String {
            if let path = ProcessInfo.processInfo.environment[binaryVariable] {
                return path
            }
            return try buildWithCargo()
        }

        private static func buildWithCargo() throws -> String {
            let workspace = try workspaceRoot()
            try cargo(["build", "--locked", "--release", "-p", "scion-h3-test-server"], in: workspace)
            let metadata = try cargo(
                ["metadata", "--format-version", "1", "--no-deps"], in: workspace, capture: true)
            guard let object = try JSONSerialization.jsonObject(with: metadata) as? [String: Any],
                let targetDirectory = object["target_directory"] as? String
            else {
                throw Failure("cargo metadata did not report a target directory")
            }
            return targetDirectory + "/release/scion-h3-test-server"
        }

        private static func workspaceRoot() throws -> URL {
            var url = URL(fileURLWithPath: #filePath)
            for _ in 0..<6 {
                url.deleteLastPathComponent()
            }
            guard
                FileManager.default.fileExists(atPath: url.appendingPathComponent("Cargo.toml").path)
            else {
                throw Failure(
                    "\(url.path) holds no Cargo.toml, so the test server cannot be built from here. "
                        + "Set \(binaryVariable) to the path of a scion-h3-test-server binary.")
            }
            return url
        }

        /// Runs cargo through the PATH and returns its standard output if asked to capture it.
        @discardableResult
        private static func cargo(_ arguments: [String], in directory: URL, capture: Bool = false)
            throws -> Data
        {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = ["cargo"] + arguments
            process.currentDirectoryURL = directory
            process.standardError = FileHandle.standardError
            let stdout = Pipe()
            if capture {
                process.standardOutput = stdout
            } else {
                process.standardOutput = FileHandle.standardError
            }
            try process.run()
            let output = capture ? stdout.fileHandleForReading.readDataToEndOfFile() : Data()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                throw Failure(
                    "cargo \(arguments.joined(separator: " ")) exited \(process.terminationStatus). "
                        + "Its output is above. Or set \(binaryVariable) to a built server.")
            }
            return output
        }
    #else
        private static func spawn(arguments: [String]) throws -> TestServer {
            // Unreachable: `attachedControlUrl` never returns nil here.
            throw Failure("this platform cannot start the test server")
        }
    #endif
}

/// A value one queue writes and another reads.
private final class Box<Value>: @unchecked Sendable {
    var value: Value

    init(_ value: Value) {
        self.value = value
    }
}
