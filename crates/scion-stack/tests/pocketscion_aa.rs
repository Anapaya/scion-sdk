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

//! Integration test for stacks that get their SNAP tokens from the PocketSCION AA.

use pocketscion::{
    comp::aa::PocketScionAaTokenSource,
    util::topologies::{IA132, IA212, PsSetup, UnderlayType, minimal::minimal_topology},
};
use scion_stack::stack::{ScionStack, ScionStackBuilder};
use sciparse::identifier::isd_asn::IsdAsn;
use test_log::test;

async fn build_stack(ps: &PsSetup, isd_as: IsdAsn) -> ScionStack {
    let aa_url = ps.aa_url().expect("the topology has a PocketSCION AA");
    ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(isd_as).unwrap())
        .with_auth_token_source(PocketScionAaTokenSource::new(&aa_url).unwrap())
        .build()
        .await
        .expect("build SCION stack")
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn snap_accepts_tokens_from_the_pocketscion_aa() {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let ps = minimal_topology(UnderlayType::Snap).await;

    let sender_stack = build_stack(&ps, IA132).await;
    let receiver_stack = build_stack(&ps, IA212).await;
    let sender_socket = sender_stack.bind(None).await.unwrap();
    let receiver_socket = receiver_stack.bind(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    let data = b"token from the PocketSCION AA";
    let mut buffer = [0u8; 64];
    let (received, _) = tokio::join!(
        async { receiver_socket.recv_from(&mut buffer).await.unwrap() },
        async { sender_socket.send_to(data, receiver_addr).await.unwrap() },
    );

    let (len, source) = received;
    assert_eq!(&buffer[..len], data);
    assert_eq!(source, sender_socket.local_addr());
}
