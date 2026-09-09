// swift-tools-version: 6.0
// Copyright 2026 Anapaya Systems
import PackageDescription

let package = Package(
    name: "scion-http3-swift",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "ScionHTTP3", targets: ["ScionHTTP3"]),
    ],
    targets: [
        .target(name: "ScionHTTP3", dependencies: ["ScionHTTP3Uniffi"]),
        .target(
            name: "ScionHTTP3Uniffi",
            dependencies: ["ScionHTTP3UniffiFFI"],
            swiftSettings: [.swiftLanguageMode(.v6)],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
                .linkedLibrary("c++"),
                .linkedLibrary("iconv"),
            ]
        ),
        // The static library, one slice per platform, with the C header and the module map. The
        // name is the module the generated Swift imports. Written here by `apple.py xcframework`.
        // A tagged release replaces the path with the URL of the zip attached to the release and
        // its checksum.
        .binaryTarget(name: "ScionHTTP3UniffiFFI", path: "ScionHTTP3UniffiFFI.xcframework"),
        .testTarget(name: "ScionHTTP3Tests", dependencies: ["ScionHTTP3", "ScionHTTP3Uniffi"]),
        .testTarget(name: "ScionHTTP3HostTests", dependencies: ["ScionHTTP3", "ScionHTTP3Uniffi"]),
    ]
)
