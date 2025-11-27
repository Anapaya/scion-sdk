// Copyright 2025 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Deterministic hierarchical secret derivation (DHSD)
//!
//! The method presented herein enables deterministic hierarchical secret
//! derivation: a master secret and a path deterministically generate a new secret,
//! giving rise to a tree structure. Compromising a secret only compromises the
//! respective subtree, not any other secrets.
//!
//! While the use case similar to and the design is heavily inspired by
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), DHSD
//! is simpler, more general and adapted to our needs. In particular, we focus on
//! general secret derivation; derivation of private and public keys for specific
//! private/public key algorithms is out of scope. (Note that the latter can be
//! achieved indirectly.)
//!
//! ## Out of scope
//!
//! (Direct) Derivation of private and public keys.
//!
//! ## Business impact and use cases
//!
//! Deterministic hierarchical secret derivation allows an operator to scale the
//! infrascture and adopt new features while only maintain a _single_ secret.
//!
//! ## Solution
//!
//! The DHSD-function `DHSD: S ⨯ P → S` maps a value of the cross product `S ⨯ P` to
//! `S`, where `S = {0,1}^256` is the set of all 256-bit wide bit strings and `P` is
//! the set of hierarchical paths. In this context, a path is a finite sequence of
//! elements of `S` which are called _node labels_:
//! `P = { [n_0, n_1, ..., n_{i-1}] | i ∈ ℕ ∧ n_i ∈ S }`.
//!
//! The function definition for DHSD is inductive:
//!
//! ```text
//! DHSD(s, [n]) = HMAC-SHA256(s, n)
//!
//! DHSD(s, [n_0, n_1, ... n_{i-1}]) = DHSD(DHSD(s, n_0), [n_1, ..., n_{i-1}])
//! ```
//!
//! The HMAC-SHA256 key derivation function is defined in
//! [rfc2104](https://datatracker.ietf.org/doc/html/rfc2104) and instantiated with
//! SHA256 as the hash function.
//!
//! ### Path coercion
//!
//! `DHSD` can be applied to any tree structure where the child nodes are uniquely
//! named by simply applying `SHA256` to the node name to form a node label.
//!
//! ## Example
//!
//! Here is a short example of how to use this module to derive a secret state from a path.
//!
//! ```
//! use dhsd::{DhsdSecret, NodeLabel};
//! // In a real application, this root secret should be a securely
//! // generated random key. For this example, we'll use a fixed array.
//! let root_secret = [42u8; 32];
//! let root_secret = DhsdSecret::from_root_secret(root_secret);
//!
//! // Define the labels that form the derivation path.
//! // NodeLabel can be created from a string.
//! let path_labels = vec![
//!     NodeLabel::from("applications"),
//!     NodeLabel::from("networking"),
//!     NodeLabel::from("scion"),
//! ];
//!
//! // Derive the final secret by providing the full path.
//! let derived_secret = root_secret.derive_from_iter(path_labels);
//!
//! // For comparison, we can also derive the secret step-by-step.
//! let intermediate_secret1 = root_secret.derive(NodeLabel::from("applications"));
//! let intermediate_secret2 = intermediate_secret1.derive(NodeLabel::from("networking"));
//! let manual_derived_secret = intermediate_secret2.derive(NodeLabel::from("scion"));
//!
//! // The result of derive_from_path is identical to the step-by-step derivation.
//! assert_eq!(derived_secret, manual_derived_secret);
//!
//! println!("Successfully derived and verified the secret.");
//! ```

mod dhsd_state;
pub use dhsd_state::{DhsdSecret, NodeLabel};
