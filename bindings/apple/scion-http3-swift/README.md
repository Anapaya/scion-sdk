# scion-http3-swift

The Swift package for the SCION HTTP/3 client on iOS and macOS. It is not released yet. What is here
is the skeleton the facade is written into:

| | |
| --- | --- |
| `Sources/ScionHTTP3` | The hand-written facade and the only module an adopter imports. |
| `Sources/ScionHTTP3Uniffi` | The Swift that `uniffi-bindgen` generates from `scion-http3-ffi`. Not checked in; `apple.py xcframework` writes it. |
| `ScionHTTP3UniffiFFI.xcframework` | The static library with its C header, one slice per platform. Not checked in; `apple.py xcframework` writes it. |
| `Tests/ScionHTTP3UniffiTests` | The path from Swift to Rust, proven against a `scion-h3-test-server` the tests start themselves. |

`ScionHTTP3Uniffi` is not a product of this package, and the facade imports it with
`internal import`, so no generated type can appear in the facade's API.

To build the XCFramework, run the tests, or regenerate the bindings, see [the build
README](../README.md).
