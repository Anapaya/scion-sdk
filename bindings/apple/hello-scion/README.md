# Hello SCION

An iOS app with one button. Pressing it sends `GET /hello` over HTTP/3 on a SCION network and
shows what came back.

## Run it

Start the test network on the Mac. The simulator shares the Mac's network, so the app reaches the
server's loopback address directly, and it expects the control API on port 7443:

```bash
cd endhost/public
cargo run -p scion-h3-test-server -- --control-port 7443
```

The app depends on the Swift package next to it, and the package needs the XCFramework and the
generated bindings, which `apple.py xcframework` writes. Building all five slices takes a while;
the simulator needs only its own:

```bash
cd endhost/public
./bindings/apple/tools/apple.py build --target aarch64-apple-ios-sim
./bindings/apple/tools/apple.py xcframework
```

The Xcode project is generated. Generate it, then open it:

```bash
cd bindings/apple/hello-scion
brew install xcodegen
xcodegen generate
open HelloScion.xcodeproj
```

Run the `HelloScion` scheme on an iPhone simulator and press **Send request**. The output is the
status and `world`.

Without Xcode's window, the build CI runs is:

```bash
xcodebuild build -project HelloScion.xcodeproj -scheme HelloScion \
    -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO
```

## Against a released package

By default, the app depends on `scion-http3-swift` in this repository. To build it against a
published release, download `scion-http3-swift-<version>.zip` from the
[release](https://github.com/Anapaya/scion-sdk/releases) and unpack it. Then point `project.yml`
at the unpacked package and generate the project again:

```yaml
packages:
  scion-http3-swift:
    path: <path to the unpacked package>
```
