// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! Fetches F3 finality certificates from the Filecoin mainnet RPC and writes
//! them to `tests/fixtures/filecoin_certs.json` as a JSON array in the raw RPC
//! format.
//!
//! Run once to regenerate fixtures:
//! ```bash
//! cargo run --bin fetch_fixtures -- [num_certs]
//! ```
//! Defaults to fetching 10 certificates (instances 0..9).

use anyhow::Result;
use filecoin_f3_lightclient::NETWORK_CONFIGS;
use filecoin_f3_rpc::RPCClient;
use std::env;
use std::path::PathBuf;

const FILECOIN_NETWORK_NAME: &str = "filecoin";
const DEFAULT_NUM_CERTS: u64 = 10;

#[tokio::main]
async fn main() -> Result<()> {
    let num_certs: u64 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NUM_CERTS);

    let config = NETWORK_CONFIGS
        .iter()
        .find(|c| c.network_name == FILECOIN_NETWORK_NAME).unwrap();

    println!("Fetching {} certificates from {}", num_certs, config.endpoint);

    let client = RPCClient::new(config.endpoint)?;
    let mut certs = Vec::with_capacity(num_certs as usize);

    for i in 0..num_certs {
        println!("  fetching instance {}...", i);
        let cert = client.get_certificate(i).await?;
        println!(" ok (signers: {}, deltas: {})", cert.signers.len(), cert.power_table_delta.len());
        certs.push(cert);
    }

    let out_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/filecoin_certs.json");

    let json = serde_json::to_string_pretty(&certs)?;
    std::fs::write(&out_path, &json)?;
    println!("Written {} certificates to {}", certs.len(), out_path.display());

    Ok(())
}
