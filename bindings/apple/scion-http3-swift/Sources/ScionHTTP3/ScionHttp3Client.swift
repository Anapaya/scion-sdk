// Copyright 2026 Anapaya Systems
import Foundation

/// An HTTP client that sends its requests over SCION.
///
/// Build one, keep it for the life of the application, and shut it down when the application is
/// done with it. It is thread-safe, it is safe to call from any task or actor, and it holds the
/// connections every request reuses.
///
/// ```swift
/// let client = try ScionHttp3Client(
///     endhostApi: "https://endhost-api.example.org",
///     authToken: token)
///
/// let rooms = try await client.get("https://chat.example.org/rooms").body.string()
/// ```
///
/// Building a client does no work. The first request establishes connectivity, which is also when a
/// mistake in the configuration first shows up.
///
/// Requests are ordinary `async` functions and cancel the way any other does. Cancelling the `Task`
/// that awaits one resets its HTTP/3 stream, leaves the connection usable, and throws
/// `CancellationError`.
///
/// The client watches for network changes on its own. After the device moves between Wi-Fi and
/// cellular, connectivity is rebuilt on the next request; nothing has to be called for that to
/// happen. Requests that were in flight when the network went away do fail and they are marked
/// `ScionHttp3Error.isRetryable` so an idempotent request can be sent again.
///
/// `deinit` is best-effort: a client that is dropped without `shutdown()` closes its connections in
/// the background, whenever ARC releases it. An application that wants the peers told promptly
/// awaits `shutdown()`.
public final class ScionHttp3Client: Sendable {
    /// Everything a client can be configured with.
    ///
    /// Two settings cover the common case: where the endhost API is, and the token for it.
    /// Everything else has a default that comes from the SCION stack itself rather than from this
    /// library, so an unset setting is not a value restated here that could drift from the real
    /// one.
    ///
    /// Keep the whole value out of logs: it holds the token.
    public struct Configuration: Sendable, Equatable {
        /// Where the client discovers SCION connectivity. Required.
        ///
        /// This, and not a choice of transport, is what points the client at a network: the endhost
        /// API reports what is available and the client uses it. `http` is accepted, because a
        /// local PocketSCION topology serves its endhost API in plaintext.
        public var endhostApi: String

        /// The token for the endhost API and the SNAP control plane.
        ///
        /// A client built without one cannot be given one later; see `setAuthToken(_:)`.
        public var authToken: String?

        /// Which transport to favor among those the endhost API offers.
        ///
        /// A preference applied to what is available, not a selection. Leave it unset unless there
        /// is a reason to prefer one.
        public var preferredUnderlay: PreferredUnderlay?

        /// Settings for the SNAP transport, when its defaults do not fit.
        public var snap = SnapConfig()

        /// Settings for the UDP transport, when its defaults do not fit.
        public var udp = UdpConfig()

        /// Which authorities a server certificate is checked against. The system's, unless set.
        public var trust: TrustAnchors = .systemDefault

        /// How long establishing connectivity to an origin may take, in seconds.
        public var connectTimeout: TimeInterval?

        /// How long a whole request may take, from sending it to holding its body, in seconds.
        ///
        /// Override it for one request with `ScionHttp3Request.requestTimeout`.
        public var requestTimeout: TimeInterval?

        /// How long an unused connection is kept before it is closed, in seconds.
        public var idleConnectionTimeout: TimeInterval?

        /// How long to wait before trying the next of an origin's addresses, in seconds.
        ///
        /// An origin can have several addresses, which are tried in a staggered race rather than
        /// one after another. This is the stagger.
        public var connectionAttemptDelay: TimeInterval?

        /// How many origins the client keeps connections for.
        ///
        /// Origins, not connections: an application talking to two hosts needs two, however many
        /// requests it makes.
        public var maxOrigins: Int?

        /// The largest response body to collect, in bytes.
        ///
        /// This is what bounds the memory a response can cost, since the body is collected before
        /// the response is handed over. Override it for one request with
        /// `ScionHttp3Request.maxResponseBodyBytes`.
        public var maxResponseBodyBytes: Int?

        public init(endhostApi: String, authToken: String? = nil) {
            self.endhostApi = endhostApi
            self.authToken = authToken
        }
    }

    private struct State {
        var isShutDown = false
        var backend: (any Http3Backend)?
        var creation: Task<any Http3Backend, any Error>?
        // The token in force, which is not always the one the client was built with. Held here as
        // well as in the stack because a renewal can arrive before there is a stack to tell, and a
        // token dropped on the floor would be found missing much later, as a rejected request.
        var authToken: String?
    }

    private enum BackendLookup {
        case ready(any Http3Backend)
        case creating(Task<any Http3Backend, any Error>)
    }

    private enum TokenTarget {
        case shutDown
        case notConnected
        case backend(any Http3Backend)
    }

    private let settings: ClientSettings
    private let backends: Http3BackendFactory
    private let monitor: any NetworkMonitor
    private let staleness: StalenessTracker
    private let log: any LibraryLog
    private let state: Locked<State>

    /// A client for the common case: where the endhost API is, and the token for it.
    ///
    /// Throws `ScionHttp3Error.invalidConfiguration` if a setting cannot be right. Whatever only
    /// the SCION stack can judge is reported by the first request instead.
    public convenience init(endhostApi: String, authToken: String? = nil) throws {
        try self.init(configuration: Configuration(endhostApi: endhostApi, authToken: authToken))
    }

    /// A client with every setting spelled out. Performs no I/O.
    ///
    /// Throws `ScionHttp3Error.invalidConfiguration` if a setting cannot be right: no endhost API,
    /// a URL that is not one, a timeout that is not positive. Whatever only the SCION stack can
    /// judge is reported by the first request instead.
    public convenience init(configuration: Configuration) throws {
        self.init(
            settings: try ClientSettings(configuration),
            backends: uniffiBackendFactory,
            monitor: PathNetworkMonitor(),
            clock: SystemClock(),
            log: OSLibraryLog())
    }

    init(
        settings: ClientSettings, backends: @escaping Http3BackendFactory,
        monitor: any NetworkMonitor, clock: any MonotonicClock, log: any LibraryLog
    ) {
        self.settings = settings
        self.backends = backends
        self.monitor = monitor
        self.staleness = StalenessTracker(
            clock: clock, idleThreshold: settings.idleThreshold, log: log)
        self.log = log
        self.state = Locked(State(authToken: settings.authToken))
        warnIfVerificationDisabled(settings.trust, log: log)
    }

    deinit {
        monitor.stop()
    }

    /// Whether `shutdown()` has been called.
    public var isShutDown: Bool {
        state.withLock { $0.isShutDown }
    }

    /// Sends `request` and returns its response, with the body received.
    ///
    /// Cancelling the task that awaits this cancels the request on the wire: the stream is reset
    /// and the connection stays usable. The call then throws `CancellationError`.
    ///
    /// Throws `ScionHttp3Error` if the request does not produce a response.
    public func execute(_ request: ScionHttp3Request) async throws -> ScionHttp3Response {
        let ffiRequest = try ffiRequest(from: request)
        return try await withBackend { backend in
            let handle = backend.newCancelHandle()
            // The exported call cannot see a cancelled task, so the handle carries the cancellation
            // over. A task that is already cancelled fires the handle at once, and the stack then
            // sends nothing.
            let response = try await withTaskCancellationHandler {
                try await backend.execute(ffiRequest, cancel: handle)
            } onCancel: {
                handle.cancel()
            }
            return publicResponse(from: response, to: request, keepAlive: backend)
        }
    }

    /// `GET url`, with the client's own timeouts.
    public func get(_ url: String) async throws -> ScionHttp3Response {
        try await execute(ScionHttp3Request(url: url))
    }

    /// `POST url` with `body`.
    public func post(
        _ url: String, body: ScionHttp3RequestBody
    ) async throws -> ScionHttp3Response {
        try await execute(ScionHttp3Request(url: url, method: .post, body: body))
    }

    /// Establishes connectivity to `url`'s origin before a request needs it.
    ///
    /// Optional, and only worth it when the first request's latency matters and its URL is known
    /// early: a splash screen can warm up the origin the first screen will call.
    public func warmUp(_ url: String) async throws {
        try await withBackend { try await $0.warmUp(url) }
    }

    /// Marks connectivity stale, so the next request rebuilds it.
    ///
    /// Returns immediately and does no work of its own; nothing is rebuilt until there is a request
    /// to rebuild for, and a client that has not connected yet does nothing at all.
    ///
    /// Calling this is not usually necessary, since network changes are noticed without it. It is
    /// here for what the library cannot see: a VPN going up, a captive portal being signed into, or
    /// an application that knows more about its own connectivity than the platform reports.
    public func reset() {
        let (isShutDown, backend) = state.withLock { ($0.isShutDown, $0.backend) }
        if isShutDown {
            return
        }
        staleness.onManualReset()
        backend?.reset()
    }

    /// Replaces the token requests authenticate with.
    ///
    /// Takes effect on the next request, and keeps the connections already established. Ignored by
    /// a shut-down client, as `reset()` is.
    ///
    /// Throws `ScionHttp3Error.invalidConfiguration` if the client was built without `authToken`.
    /// There is then nothing reading a token, so there is nothing to replace: build a client with
    /// one instead.
    public func setAuthToken(_ token: String) throws {
        if token.isEmpty {
            throw ScionHttp3Error.invalidConfiguration(detail: "an auth token cannot be empty")
        }
        guard settings.authToken != nil else {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "this client was built without an authToken, so there is no token to "
                    + "replace. Set ScionHttp3Client.Configuration.authToken instead.")
        }
        let target: TokenTarget = state.withLock { s in
            if s.isShutDown {
                return .shutDown
            }
            s.authToken = token
            guard let backend = s.backend else { return .notConnected }
            return .backend(backend)
        }
        switch target {
        case .shutDown:
            log.debug("ignoring a token renewal on a client that is already shut down")
        case .notConnected:
            // A client that has not connected yet has nothing to tell; the token it is holding now
            // is what the stack will be built with.
            break
        case .backend(let backend):
            do {
                try backend.setAuthToken(token)
            } catch {
                throw publicError(error)
            }
        }
    }

    /// Closes the connection pool gracefully, then the client.
    ///
    /// Waits for each connection to tell its peer it is going away, which is the polite thing to do
    /// and lets a server release its own state promptly. Requests still in flight are faulted while
    /// this runs rather than awaited. Anything issued afterwards fails with
    /// `ScionHttp3Error.closed`, and a shut-down client cannot be reopened.
    ///
    /// Idempotent.
    public func shutdown() async {
        let (alreadyShutDown, backend) = state.withLock { s in
            let already = s.isShutDown
            s.isShutDown = true
            defer { s.backend = nil }
            return (already, s.backend)
        }
        if alreadyShutDown {
            return
        }
        monitor.stop()
        // A backend still being built finds the flag set when it is done, and shuts itself down.
        await backend?.shutdown()
    }

    /// Runs `body` against the backend, with everything every caller of it owes the stack.
    ///
    /// Building the backend is inside the mapped region deliberately. The Rust constructor is
    /// fallible too, over what only it can judge, such as an outbound address that parses as text
    /// here and not as an address there. Building it outside would let that reach the caller as the
    /// generated error, which is not this library's type, and every case of the public error
    /// promises otherwise.
    private func withBackend<T: Sendable>(
        _ body: (any Http3Backend) async throws -> T
    ) async throws -> T {
        defer { staleness.onUseComplete() }
        do {
            let backend = try await backend()
            if staleness.onUseAttempt(probe: { monitor.currentIdentity() }) {
                backend.reset()
            }
            return try await body(backend)
        } catch {
            throw publicError(error)
        }
    }

    /// The backend, built on first use.
    ///
    /// Not built in the initializer on purpose: constructing it starts the runtime that carries
    /// every request, which does not belong on the thread that builds the client, usually the main
    /// thread during application start. Concurrent first requests share one construction.
    private func backend() async throws -> any Http3Backend {
        let lookup: BackendLookup = try state.withLock { s in
            if s.isShutDown {
                throw ScionHttp3Error.closed
            }
            if let backend = s.backend {
                return .ready(backend)
            }
            if let creation = s.creation {
                return .creating(creation)
            }
            // Detached, so that the caller who happens to be first cannot take the construction
            // down with it by being cancelled while every other caller waits on the same task.
            let creation = Task.detached { [self] in try await self.createBackend() }
            s.creation = creation
            return .creating(creation)
        }
        switch lookup {
        case .ready(let backend):
            return backend
        case .creating(let creation):
            return try await creation.value
        }
    }

    private func createBackend() async throws -> any Http3Backend {
        let created: any Http3Backend
        do {
            created = try backends(settings)
        } catch {
            state.withLock { $0.creation = nil }
            throw error
        }
        do {
            // A token renewed before the first request went into the state rather than into a stack
            // that did not exist. This is where it catches up.
            let pending = state.withLock { $0.authToken }
            if let pending, pending != settings.authToken {
                try created.setAuthToken(pending)
            }
        } catch {
            state.withLock { $0.creation = nil }
            await created.shutdown()
            throw error
        }
        monitor.start { [weak self] identity in
            self?.staleness.observe(identity)
        }
        // Published and checked under one lock with shutdown(), so the backend is released exactly
        // once: by shutdown() if it found it published, by this task if the flag was already set.
        let published = state.withLock { s -> Bool in
            s.creation = nil
            if s.isShutDown {
                return false
            }
            s.backend = created
            return true
        }
        if !published {
            monitor.stop()
            await created.shutdown()
            throw ScionHttp3Error.closed
        }
        return created
    }
}
