# Hello SCION

An Android app with one button. Pressing it sends `GET /hello` over HTTP/3 on a SCION network and
shows what came back.

| File | What it is |
| --- | --- |
| `HelloScion.kt` | Builds the client and sends the request. The only file that mentions SCION. |
| `LocalNetwork.kt` | Asks the local test server where it is. A real app knows this already. |
| `MainActivity.kt` | The screen implementation. |

## Run it

Start the test network on the host. The emulator reaches the host's loopback as `10.0.2.2`, and the
app expects the control API on port 7443:

```bash
cd endhost/public
cargo run -p scion-h3-test-server -- \
    --underlay snap --advertise-ip 10.0.2.2 --control-port 7443
```

Both options matter. Over the UDP underlay the network addresses the app at `10.0.2.15`, which
nothing outside the emulator's NAT can reach. `--advertise-ip` is what makes the network tell the
app to use `10.0.2.2` instead.

Then install the app on a running x86_64 emulator. The native libraries come from cargo rather than
from Gradle, so build them first:

```bash
cd endhost/public
./bindings/android/tools/android.py build --abi x86_64
cd bindings/android
./gradlew :hello-scion:installDebug
```

Press **Send request**. The output is the status and `world`.

## Against a released AAR

By default this module depends on `scion-http3-android` in this repository, so CI builds the sample
against the library it ships. To build it the way a consumer does, against a published artifact,
publish one locally and name its version:

```bash
./gradlew :scion-http3-android:publishToMavenLocal
./gradlew :hello-scion:assembleDebug -PscionSdkVersion=<version>
```
