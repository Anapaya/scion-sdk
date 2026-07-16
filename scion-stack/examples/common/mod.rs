// Copyright 2026 Anapaya Systems
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

//! Shared setup helpers for the scion-stack examples.

// Not every example uses every helper; each example compiles its own copy of this module.
#![allow(dead_code)]

use anyhow::Context;
use pocketscion::util::{dev_auth_token, topologies::PsSetup};
use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
use sciparse::identifier::isd_asn::IsdAsn;

/// Builds a [`ScionStack`] attached to the given AS of a running PocketSCION topology.
///
/// This is the one-liner every example uses to go from "a simulation is running"
/// to "I have a SCION stack I can open sockets on":
///
/// ```ignore
/// let stack = common::build_stack(&ps, IA132).await?;
/// let socket = stack.bind(None).await?;
/// ```
// ANCHOR: build-stack
pub async fn build_stack(ps: &PsSetup, isd_as: IsdAsn) -> anyhow::Result<ScionStack> {
    let endhost_api = ps
        .endhost_api(isd_as)
        .with_context(|| format!("PocketSCION has no endhost API for {isd_as}"))?;

    ScionStackBuilder::new()
        .with_endhost_api(endhost_api)
        .with_auth_token(dev_auth_token())
        .build()
        .await
        .with_context(|| format!("building SCION stack for {isd_as}"))
}
// ANCHOR_END: build-stack
