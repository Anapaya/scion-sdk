# `scion-stack` API conventions

Rules for public items in this crate, aligned with the
[Rust API guidelines](https://rust-lang.github.io/api-guidelines/). Follow them when adding or
changing anything `pub`. Deviations are listed at the end.

## Naming

- Constructors: `new`; fallible constructors return `Result`. Name alternate constructors
  descriptively (`ScionStack::static_udp_underlay`, `StaticEndhostApiDiscovery::global`).
- Prefer named, discoverable constructors over `From`/`TryFrom` for tuples or ambiguous inputs
  (`Segments::new(core, non_core)`, not `From<(Vec<_>, Vec<_>)>`). Keep `From`/`TryFrom` for
  unambiguous, lossless conversions.
- Getters: no `get_` prefix (`local_addr`, `snap_data_plane`).
- `try_*` means "returns `Result`". A cache lookup returning `Option` is named plainly
  (`MultiPathManager::cached_path`).
- Name methods by intent, not by the underlying representation. Reserve smart-pointer verbs like
  `downgrade`/`upgrade` for types that *present* as handles (e.g. a `*Ref`). On a component, prefer
  a descriptive name (`MultiPathManager::weak_ref` → `MultiPathManagerRef`, which then
  `upgrade`s back to a strong handle) rather than exposing that it's an `Arc` internally.

## Errors

- One `thiserror` enum per operation (`ScionSocketBindError`, `BuildScionStackError`, ...). Don't
  merge them into per-module god-enums.
- All public error enums are `#[non_exhaustive]` (so variants can be added without a major bump).
- No `anyhow` in public signatures. No foreign error types in public variants — wrap the cause in
  `#[source] Box<dyn std::error::Error + Send + Sync>` (keeps `Error::source()` working while
  hiding the dependency's type).
- Give callers a classifier method instead of the raw cause when they need to branch
  (`ApiAttemptError::is_transient`).
- Keep the `source()` chain; don't flatten a cause into a `String`.

## `#[non_exhaustive]`

- On every public error enum, and on public enums/structs expected to grow
  (`PreferredUnderlay`, `UnderlayInfo`, `Segments`, ...). Not on closed value types (`Score`).
- A `#[non_exhaustive]` struct that downstream constructs gets a constructor (`Segments::new`).

## Builders

- Config types are self-builders: `default()`/`new()` + consuming `with_*` setters (`#[must_use]`),
  passed by value. No separate `*Builder` types (`SocketConfig`, `SnapUnderlayConfig`,
  `UdpUnderlayConfig`, `MultiPathManagerConfig`). Accumulators may use `&mut self` `add_*`
  (`PathStrategy::add_policy`).
- `ScionStackBuilder` is the one standalone builder — it has a real terminal step (`async`, fallible
  `build()`).

## Common traits

Derive `Debug`/`Clone`/`Copy`/`PartialEq`/`Eq` on public value types where they apply.

## Dependency exposure

Which foreign types appear in the public API is a deliberate choice:

- Every crate whose types appear in a public signature is re-exported from the crate root
  (`scion_stack::<crate>::...`), so clients need no direct dependency to name/construct those types.
  See the "Re-exported dependencies" block in `src/lib.rs`.
- Re-export the whole crate, not just the leaked type. Callers usually need sibling/helper types
  to construct the value.
- A foreign type that is *not* re-exported is a leak to hide (prefer a `std` equivalent) or wrap.
- Re-exporting is a semver commitment: a breaking release of a re-exported crate breaks
  `scion-stack`.

`std`/`core`/`alloc` are exempt. Blanket trait impls that `rustdoc` attributes to our types from
transitive deps (e.g., `zerocopy` pointer invariants, `tonic::IntoRequest::into_request`,
`tower_http`/`tower_layer` redirect-policy combinators, `crossbeam-epoch`) are unavoidable artifacts
of depending on those crates, not types we place in our own signatures. They are not re-exported.

### Enforcement

Unfortunately, there is no fully automated way to check for foreign types in public signatures.
We use a combination of compile-time and code-review checks:

- `tests/public_api_reexports.rs` pins the intentional re-exports: dropping or renaming one is a
  compile error. This catches the common regression but not a brand-new leak.
- New leaks must be caught in **code review**. When a `pub` signature gains a foreign type, decide
  keep-and-re-export or hide/wrap per the rules above. To diff the API surface, reviewers can run
  [`cargo public-api`](https://crates.io/crates/cargo-public-api) ad hoc. Anything it reports from a
  crate not in the re-export list (and not a blanket-impl artifact) is a leak to classify.

## Linting

`#![warn(clippy::pedantic)]` with a documented allow-list in `src/lib.rs`; enforced in CI
(`clippy ... -- -D warnings`). Add lints to the allow-list only with a one-line rationale.
