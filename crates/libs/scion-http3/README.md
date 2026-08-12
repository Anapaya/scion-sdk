# scion-http3

A high-level HTTP/3-over-SCION client: give it a URL, get a response.

```rust
use scion_http3::{Client, Config};

/// Cap on a collected response body; a larger one fails rather than buffering
/// unboundedly.
const MAX_BODY_SIZE: usize = 1 << 20;

async fn get_rooms() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(
        Config::new("https://endhost-api.example.org".parse()?).with_auth_token("token"),
    );
    let response = client.get("https://chat.example.org/rooms").await?;
    let (body, _trailers) = response.text(Some(MAX_BODY_SIZE)).await?;
    println!("{body}");
    Ok(())
}
```

See the crate documentation for the full API, and
`examples/http3_get_post.rs` for a runnable end-to-end example against a
local network:

```sh
cargo run -p scion-http3 --example http3_get_post
```
