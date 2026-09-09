// Copyright 2026 Anapaya Systems
internal import ScionHTTP3Uniffi

/// What the library needs from the generated bindings.
protocol Http3Backend: AnyObject, Sendable {
    /// A handle for one call to `execute`.
    func newCancelHandle() -> any Http3CancelHandle

    /// Issues a request and stops it when `cancel` fires.
    func execute(_ request: HttpRequest, cancel: any Http3CancelHandle) async throws -> HttpResponse

    /// Establishes connectivity to an origin before it is needed.
    func warmUp(_ url: String) async throws

    /// Marks connectivity stale.
    func reset()

    /// Replaces the bearer token. Fails if the client was built without one.
    func setAuthToken(_ token: String) throws

    /// Closes the connection pool gracefully, faulting anything in flight.
    func shutdown() async
}

/// A one-shot cancellation for one request.
protocol Http3CancelHandle: AnyObject, Sendable {
    /// Cancels the request the handle was passed to. Idempotent, and a noop once the request ended.
    func cancel()
}

/// Builds a backend from validated settings.
typealias Http3BackendFactory = @Sendable (ClientSettings) throws -> any Http3Backend
