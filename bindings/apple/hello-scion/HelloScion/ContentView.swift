// Copyright 2026 Anapaya Systems

import ScionHTTP3
import SwiftUI

struct ContentView: View {
    @State private var output = "Start the test server, then press Send request."
    @State private var sending = false

    @State private var helloScion: HelloScion?

    var body: some View {
        VStack(spacing: 16) {
            Button("Send request") {
                sending = true
                output = "Sending…"
                Task {
                    output = await sendRequest()
                    sending = false
                }
            }
            .disabled(sending)
            .frame(maxWidth: .infinity)

            ScrollView {
                Text(output)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding()
    }

    private func sendRequest() async -> String {
        do {
            let reply = try await client().hello()
            return "\(reply.code)\n\n\(reply.body)"
        } catch let error as ScionHttp3Error {
            return describe(error)
        } catch {
            // Reading the test network's configuration happens before any SCION call, so it fails
            // on its own terms. The screen is the only place a reader can see that.
            return error.localizedDescription
        }
    }

    /// The client, built on first use and kept for the view's life.
    private func client() async throws -> HelloScion {
        if let helloScion {
            return helloScion
        }
        let network = try await LocalNetwork.discover()
        let built = try HelloScion(network: network)
        helloScion = built
        return built
    }

    // ANCHOR: errors
    /// Every failure the client reports is a `ScionHttp3Error`. A non-2xx status arrives as a
    /// response instead, carrying a code and a body.
    private func describe(_ error: ScionHttp3Error) -> String {
        let cause: String
        switch error {
        case .connectivity:
            cause = "No usable network."
        case .connect(let host, let port, _, _):
            cause = "Could not reach \(host):\(port). Is the test server still running?"
        case .tls(let host, _, _):
            cause = "The certificate \(host) presented was rejected."
        case .timeout(let phase, let after, _, _):
            cause = "Gave up in the \(phase) phase after \(after) s."
        default:
            cause = error.localizedDescription
        }
        let advice = "Sending it again can succeed. The client does not retry on its own."
        return error.isRetryable ? "\(cause)\n\n\(advice)" : cause
    }
    // ANCHOR_END: errors
}
