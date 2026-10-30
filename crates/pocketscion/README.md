# PocketSCION

PocketSCION is a lightweight SCION network simulator. It allows you to create and manage local SCION
topologies, making it an invaluable tool for testing your applications without needing a
full-fledged SCION network.

PocketSCION supports both the UDP and SNAP underlays, allowing you to test your applications in a
variety of network scenarios.

The `util::topologies` module has ready-made topologies. `minimal_topology` starts two ASes with one
link between them:

```rust
use pocketscion::util::topologies::{IA132, UnderlayType, minimal::minimal_topology};

let ps = minimal_topology(UnderlayType::Snap).await;
let endhost_api = ps.endhost_api(IA132).expect("the topology has an endhost API for IA132");
```

To build your own topology, configure a `PocketScionState` and start it with
`PocketScionRuntimeBuilder`.

## PocketSCION AA

On a real SCION network, your application authenticates with an AA that is specific to the type of
subscription that you own. The PocketSCION AA fulfills the role of the AA for testing purposes.

The PocketSCION AA gives a SNAP token to each caller. It does not ask for an API key, so it gives no
security. Use it only with a local PocketSCION network.

### Start the PocketSCION AA

The topologies in `util::topologies` start the PocketSCION AA. `PsSetup::aa_url` gives its URL. For
your own topology, add the AA to the state before you start the runtime:

```rust
use pocketscion::comp::aa::AaConfig;

pstate.set_aa(AaConfig::default())?;
```

With the default configuration, the AA signs the tokens with the key that the PocketSCION SNAPs
accept. The tokens stay valid for one hour.

### Get a SNAP token

Give a `PocketScionAaTokenSource` to the stack. The token source gets a SNAP token from the AA and
renews the token before it expires.

```rust
use pocketscion::comp::aa::PocketScionAaTokenSource;
use scion_stack::stack::ScionStackBuilder;

let aa_url = ps.aa_url().expect("the topology has a PocketSCION AA");
let stack = ScionStackBuilder::new()
    .with_endhost_api(endhost_api)
    .with_auth_token_source(PocketScionAaTokenSource::new(&aa_url)?)
    .build()
    .await?;
```
