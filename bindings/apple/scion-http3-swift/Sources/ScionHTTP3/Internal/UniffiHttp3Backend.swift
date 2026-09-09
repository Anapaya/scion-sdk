// Copyright 2026 Anapaya Systems
internal import ScionHTTP3Uniffi

/// `Http3Backend` over the generated bindings.
final class UniffiHttp3Backend: Http3Backend {
    private let client: FfiClient

    init(client: FfiClient) {
        self.client = client
    }

    func newCancelHandle() -> any Http3CancelHandle {
        CancelHandle()
    }

    func execute(
        _ request: HttpRequest, cancel: any Http3CancelHandle
    ) async throws -> HttpResponse {
        guard let handle = cancel as? CancelHandle else {
            preconditionFailure("a cancel handle from another backend was passed to this one")
        }
        return try await client.executeCancellable(request: request, cancel: handle)
    }

    func warmUp(_ url: String) async throws {
        try await client.warmUp(url: url)
    }

    func reset() {
        client.reset()
    }

    func setAuthToken(_ token: String) throws {
        try client.setAuthToken(token: token)
    }

    func shutdown() async {
        await client.shutdown()
    }
}

extension CancelHandle: Http3CancelHandle {}

/// Builds a real backend. This is the first call into the native library a client makes: it starts
/// the runtime that carries every request.
let uniffiBackendFactory: Http3BackendFactory = { settings in
    let config = settings.applyTo(defaultClientConfig(endhostApiUrl: settings.endhostApiUrl))
    return UniffiHttp3Backend(client: try FfiClient(config: config))
}
