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

//! Simple end-to-end test for PocketScion using an EndhostAPI

use std::{str::FromStr, time::SystemTime};

use anyhow::Context;
use endhost_api_client::client::{CrpcEndhostApiClient, EndhostApiClient};
use ntest::timeout;
use pocketscion::{
    self,
    network::scion::topology::{ScionAs, ScionTopology},
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use scion_proto::address::IsdAsn;
use url::Url;

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn should_have_working_eh_api() -> anyhow::Result<()> {
    let mut state = SharedPocketScionState::new(SystemTime::now());

    let ia1 = IsdAsn::from_str("1-1")?;
    let ia2 = IsdAsn::from_str("2-3")?;

    // Setup minimal topology
    let mut topo = ScionTopology::new();
    topo.add_as(ScionAs::new_core("1-1".parse()?))?
        .add_as(ScionAs::new_core("1-2".parse()?))?
        .add_as(ScionAs::new("1-3".parse()?))?
        .add_as(ScionAs::new_core("2-1".parse()?))?
        .add_as(ScionAs::new("2-2".parse()?))?
        .add_as(ScionAs::new("2-3".parse()?))?
        .add_link("1-1#1 core 1-2#2".parse()?)?
        .add_link("1-2#1 down_to 1-3#1".parse()?)?
        .add_link("1-1#2 down_to 1-3#2".parse()?)?
        .add_link("1-1#3 core 2-1#1".parse()?)?
        .add_link("2-1#2 down_to 2-2#1".parse()?)?
        .add_link("2-2#2 down_to 2-3#1".parse()?)?;

    state.set_topology(topo);

    // Setup snap
    state.add_snap(ia1)?;

    // Setup Eh API
    let eh_api_id = state.add_endhost_api(vec![ia1]);

    // Start PocketScion
    let ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state.into_state())
        .start()
        .await
        .context("error starting runtime")?;

    tracing::info!("Runtime started");

    let ps_api = ps_rt.api_client().get_io_config().await?;
    let eh_addr = ps_api
        .endhost_apis
        .get(&eh_api_id)
        .expect("missing addr for endhost api");

    tracing::info!(%eh_addr, "Got endhost api addr");

    let eh_client = CrpcEndhostApiClient::new(&Url::parse(&format!("http://{eh_addr}"))?)?;

    let underlays = eh_client
        .list_underlays(ia1)
        .await
        .context("endhost api client failed")?;
    println!("{underlays:?}");

    assert_eq!(underlays.snap_underlay.len(), 1);

    let page = eh_client
        .list_segments(ia1, ia2, 256, "".to_string())
        .await
        .context("error listing segments")?;

    assert_eq!(page.segments.down_segments.len(), 1);
    assert_eq!(page.segments.core_segments.len(), 1);

    Ok(())
}
