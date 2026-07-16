# docusaurus-code-import

The **single source of truth** for the code-include remark plugin used across the
SCION SDK docs. It lets guide pages pull code samples *by reference* from real,
tested source files (named anchors, line ranges, or whole file), with an `@sdk`
path alias so one reference string resolves in every build layout.

## Why

Guide snippets that are copy-pasted rot silently the moment the API changes. This
plugin instead references the SDK's own example sources — which are compiled and
tested in CI (`cargo build --examples`, doctests) — so a breaking change fails CI
before it can ship a stale snippet.

## Authoring syntax

Write an empty fenced code block whose meta carries a `reference` attribute:

````md
```rust reference="@sdk/scion-stack/examples/udp_echo.rs#server" title="udp_echo.rs"
```
````

`reference="<path>[#selector]"`:

- `<path>` — if it starts with a configured alias (e.g. `@sdk`), the prefix is
  replaced by the alias target; otherwise it is resolved relative to the page.
- `#selector` — a named anchor (`#server`), a line range (`#L10-L20`), or omitted
  (whole file, with `ANCHOR` bookkeeping lines stripped).

Named anchors are mdBook-style comment markers in the source:

```rust
// ANCHOR: server
let server_socket = server_stack.bind(None).await?;
// ANCHOR_END: server
```

The `reference` attribute is stripped after resolution, so the block gets normal
syntax highlighting; other meta (e.g. `title=`) is preserved.
