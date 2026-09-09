// Copyright 2026 Anapaya Systems
import Foundation
import XCTest

@testable import ScionHTTP3

// These fakes replace the two things a unit test does not have: the native library the generated
// bindings call and a device whose network changes. Everything above them is the real code.
//
// The fakes are kept deliberately dumb. `FakeBackend` answers with what it was told to answer
// with and keeps no connection state of its own.

/// A cancel handle that tells whoever asked when it fires.
final class FakeCancelHandle: Http3CancelHandle {
    private struct State {
        var fired = false
        var onCancel: [@Sendable () -> Void] = []
    }

    private let state = Locked(State())

    var isFired: Bool { state.withLock { $0.fired } }

    func cancel() {
        let callbacks = state.withLock { s -> [@Sendable () -> Void] in
            s.fired = true
            defer { s.onCancel = [] }
            return s.onCancel
        }
        callbacks.forEach { $0() }
    }

    /// Runs `body` when the handle fires, or at once if it already has.
    func whenCancelled(_ body: @escaping @Sendable () -> Void) {
        let firedAlready = state.withLock { s -> Bool in
            if s.fired { return true }
            s.onCancel.append(body)
            return false
        }
        if firedAlready {
            body()
        }
    }
}

/// Holds a call open until the test opens the gate, or the call's handle fires.
final class Gate: Sendable {
    private struct State {
        var open = false
        var waiters: [Locked<CheckedContinuation<Bool, Never>?>] = []
    }

    private let state = Locked(State())

    /// True when the gate was opened, false when `handle` fired first.
    func wait(cancelledBy handle: FakeCancelHandle) async -> Bool {
        await withCheckedContinuation { continuation in
            let slot = Locked<CheckedContinuation<Bool, Never>?>(continuation)
            let openAlready = state.withLock { s -> Bool in
                if s.open { return true }
                s.waiters.append(slot)
                return false
            }
            if openAlready {
                Self.resume(slot, with: true)
                return
            }
            handle.whenCancelled { Self.resume(slot, with: false) }
        }
    }

    func open() {
        let waiters = state.withLock { s -> [Locked<CheckedContinuation<Bool, Never>?>] in
            s.open = true
            defer { s.waiters = [] }
            return s.waiters
        }
        waiters.forEach { Self.resume($0, with: true) }
    }

    private static func resume(
        _ slot: Locked<CheckedContinuation<Bool, Never>?>, with value: Bool
    ) {
        let continuation = slot.withLock { s -> CheckedContinuation<Bool, Never>? in
            defer { s = nil }
            return s
        }
        continuation?.resume(returning: value)
    }
}

/// Records what reached the FFI, and answers with whatever the test set up.
final class FakeBackend: Http3Backend {
    struct Recorded {
        var requests: [FfiRequest] = []
        var warmedUp: [String] = []
        var tokens: [String] = []
        var handles: [FakeCancelHandle] = []
        var resets = 0
        var shutdowns = 0
        /// Set while a held-open `execute` was cancelled, which is what proves cancellation
        /// arrived.
        var executeWasCancelled = false
    }

    let recorded = Locked(Recorded())

    /// What `execute` answers with.
    let response = Locked(fakeResponse())

    /// Thrown from `execute` and `warmUp` instead of answering, when set.
    let failure = Locked<(any Error)?>(nil)

    /// Thrown from `setAuthToken` instead of recording it, as the stack does without a token.
    let setAuthTokenFailure = Locked<(any Error)?>(nil)

    /// When set, `execute` waits on it until the test opens it or the handle fires.
    let gate = Locked<Gate?>(nil)

    var requests: [FfiRequest] { recorded.withLock { $0.requests } }
    var warmedUp: [String] { recorded.withLock { $0.warmedUp } }
    var tokens: [String] { recorded.withLock { $0.tokens } }
    var handles: [FakeCancelHandle] { recorded.withLock { $0.handles } }
    var resets: Int { recorded.withLock { $0.resets } }
    var shutdowns: Int { recorded.withLock { $0.shutdowns } }
    var executeWasCancelled: Bool { recorded.withLock { $0.executeWasCancelled } }

    func newCancelHandle() -> any Http3CancelHandle {
        let handle = FakeCancelHandle()
        recorded.withLock { $0.handles.append(handle) }
        return handle
    }

    func execute(_ request: FfiRequest, cancel: any Http3CancelHandle) async throws -> FfiResponse {
        recorded.withLock { $0.requests.append(request) }
        guard let handle = cancel as? FakeCancelHandle else {
            preconditionFailure("the handle did not come from this backend")
        }
        if handle.isFired {
            throw cancelled()
        }
        if let gate = gate.withLock({ $0 }) {
            let opened = await gate.wait(cancelledBy: handle)
            if !opened {
                recorded.withLock { $0.executeWasCancelled = true }
                throw cancelled()
            }
        }
        if let failure = failure.withLock({ $0 }) {
            throw failure
        }
        return response.withLock { $0 }
    }

    func warmUp(_ url: String) async throws {
        recorded.withLock { $0.warmedUp.append(url) }
        if let failure = failure.withLock({ $0 }) {
            throw failure
        }
    }

    func reset() {
        recorded.withLock { $0.resets += 1 }
    }

    func setAuthToken(_ token: String) throws {
        if let failure = setAuthTokenFailure.withLock({ $0 }) {
            throw failure
        }
        recorded.withLock { $0.tokens.append(token) }
    }

    func shutdown() async {
        recorded.withLock { $0.shutdowns += 1 }
    }

    private func cancelled() -> FfiError {
        FfiError.Cancelled(retryable: false, detail: "the request was cancelled")
    }
}

/// Hands out a backend, and counts how often it was asked for one.
final class FakeBackendFactory: Sendable {
    let backend: FakeBackend
    let creations = Locked(0)
    let settings = Locked<[ClientSettings]>([])

    /// Thrown instead of building one, as the Rust constructor can.
    let failure = Locked<(any Error)?>(nil)

    /// Runs while a backend is being built, for testing what happens meanwhile.
    let whileCreating = Locked<(@Sendable () -> Void)?>(nil)

    init(backend: FakeBackend = FakeBackend()) {
        self.backend = backend
    }

    var factory: Http3BackendFactory {
        { [self] settings in
            self.settings.withLock { $0.append(settings) }
            self.creations.withLock { $0 += 1 }
            self.whileCreating.withLock { $0 }?()
            if let failure = self.failure.withLock({ $0 }) {
                throw failure
            }
            return self.backend
        }
    }
}

/// Holds a backend construction until the test lets it go.
final class Hold: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)

    func wait() {
        semaphore.wait()
    }

    func release() {
        semaphore.signal()
    }
}

/// A clock the test moves by hand.
final class FakeClock: MonotonicClock {
    private let time: Locked<TimeInterval>

    init(now: TimeInterval = 1_000) {
        time = Locked(now)
    }

    func now() -> TimeInterval {
        time.withLock { $0 }
    }

    func advance(_ seconds: TimeInterval) {
        time.withLock { $0 += seconds }
    }
}

/// A monitor whose observations and probe answers the test controls.
final class FakeNetworkMonitor: NetworkMonitor {
    private struct State {
        var current: NetworkIdentity?
        var observer: (@Sendable (NetworkIdentity) -> Void)?
        var starts = 0
        var stops = 0
    }

    private let state: Locked<State>

    init(current: NetworkIdentity? = nil) {
        state = Locked(State(current: current))
    }

    var starts: Int { state.withLock { $0.starts } }
    var stops: Int { state.withLock { $0.stops } }

    var current: NetworkIdentity? {
        get { state.withLock { $0.current } }
        set { state.withLock { $0.current = newValue } }
    }

    func start(onObserved: @escaping @Sendable (NetworkIdentity) -> Void) {
        state.withLock { s in
            s.starts += 1
            s.observer = onObserved
        }
    }

    func currentIdentity() -> NetworkIdentity? {
        state.withLock { $0.current }
    }

    func stop() {
        state.withLock { $0.stops += 1 }
    }

    /// Delivers an observation the way the platform would.
    func observe(_ identity: NetworkIdentity) {
        guard let observer = state.withLock({ $0.observer }) else {
            XCTFail("the monitor was never started")
            return
        }
        observer(identity)
    }
}

/// Keeps what was logged, so a test can assert that something was said and how loudly.
final class RecordingLog: LibraryLog {
    private struct Lines {
        var errors: [String] = []
        var warnings: [String] = []
        var debugs: [String] = []
    }

    private let lines = Locked(Lines())

    var errors: [String] { lines.withLock { $0.errors } }
    var warnings: [String] { lines.withLock { $0.warnings } }
    var debugs: [String] { lines.withLock { $0.debugs } }

    func error(_ message: String) {
        lines.withLock { $0.errors.append(message) }
    }

    func warn(_ message: String) {
        lines.withLock { $0.warnings.append(message) }
    }

    func debug(_ message: String) {
        lines.withLock { $0.debugs.append(message) }
    }
}

// Builders for the fixtures every test needs, so that a test says only what it is actually about.

func configuration(
    endhostApi: String = "https://endhost-api.example.org",
    authToken: String? = nil,
    trust: TrustAnchors = .systemDefault,
    idleConnectionTimeout: TimeInterval? = nil
) -> ScionHttp3Client.Configuration {
    var configuration = ScionHttp3Client.Configuration(endhostApi: endhostApi, authToken: authToken)
    configuration.trust = trust
    configuration.idleConnectionTimeout = idleConnectionTimeout
    return configuration
}

func settings(
    endhostApi: String = "https://endhost-api.example.org",
    authToken: String? = nil,
    trust: TrustAnchors = .systemDefault,
    idleConnectionTimeout: TimeInterval? = nil
) throws -> ClientSettings {
    try ClientSettings(
        configuration(
            endhostApi: endhostApi, authToken: authToken, trust: trust,
            idleConnectionTimeout: idleConnectionTimeout))
}

func fakeResponse(
    status: UInt16 = 200,
    headers: [FfiHeader] = [],
    body: Data = Data(),
    trailers: [FfiHeader] = []
) -> FfiResponse {
    FfiResponse(status: status, headers: headers, body: body, trailers: trailers)
}

func identity(
    interfaceName: String? = "en0",
    interfaceType: String? = "wifi",
    gateways: [String] = ["192.168.1.1"],
    satisfied: Bool = true
) -> NetworkIdentity {
    NetworkIdentity(
        interfaceName: interfaceName, interfaceType: interfaceType, gateways: gateways,
        satisfied: satisfied)
}

/// A client wired to fakes, which is how every lifecycle and staleness test builds one.
func client(
    factory: FakeBackendFactory = FakeBackendFactory(),
    monitor: FakeNetworkMonitor = FakeNetworkMonitor(),
    clock: FakeClock = FakeClock(),
    log: RecordingLog = RecordingLog(),
    settings: ClientSettings? = nil
) throws -> ScionHttp3Client {
    ScionHttp3Client(
        settings: try settings ?? ScionHTTP3Tests.settings(),
        backends: factory.factory,
        monitor: monitor,
        clock: clock,
        log: log)
}

func request(_ url: String = "https://example.org/hello") -> ScionHttp3Request {
    ScionHttp3Request(url: url)
}

/// Runs `body` and returns what it threw, or fails the test if it threw nothing.
func thrown<T>(
    _ body: () async throws -> T, file: StaticString = #filePath, line: UInt = #line
) async -> (any Error)? {
    do {
        _ = try await body()
        XCTFail("expected an error, got a result", file: file, line: line)
        return nil
    } catch {
        return error
    }
}

/// Runs `body` and returns what it threw, or fails the test if it threw nothing.
func thrown<T>(
    _ body: () throws -> T, file: StaticString = #filePath, line: UInt = #line
) -> (any Error)? {
    do {
        _ = try body()
        XCTFail("expected an error, got a result", file: file, line: line)
        return nil
    } catch {
        return error
    }
}

/// Polls `condition` until it holds or `timeout` passes.
func eventually(
    timeout: TimeInterval = 5, _ condition: @escaping @Sendable () -> Bool
) async -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() {
            return true
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return condition()
}

let validPem = Data(
    """
    -----BEGIN CERTIFICATE-----
    MIIBpzCCAU2gAwIBAgIUGAW/ntquyyLRkob0XwT5KQ1JNykwCgYIKoZIzj0EAwIw
    KDEmMCQGA1UEAwwdc2Npb24taHR0cDMtc3dpZnQgdGVzdCBhbmNob3IwIBcNMjYw
    OTA4MTEyNzA2WhgPMjEyNjA4MTUxMTI3MDZaMCgxJjAkBgNVBAMMHXNjaW9uLWh0
    dHAzLXN3aWZ0IHRlc3QgYW5jaG9yMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
    VihOfy20D1qnazHpfH8gsjeXCouZ8QRTCHtDTJI+xQkrQzULCpCzQsasMlwNkAgd
    jIjDxVYwaxTj6VlI6s7RDKNTMFEwHQYDVR0OBBYEFGZftkgddYAeqJbrv5es+elm
    dLgbMB8GA1UdIwQYMBaAFGZftkgddYAeqJbrv5es+elmdLgbMA8GA1UdEwEB/wQF
    MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhANj/tm7yVVCx6ZnwMbqVWDKhdsWLv/07
    CGrsVYOUHXhWAiAl0/z9d/QIyIym+TJ+6G+vSb2LD4nGyLVeaLp/NIPS9Q==
    -----END CERTIFICATE-----

    """.utf8)
