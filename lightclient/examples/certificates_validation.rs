//! # Example: F3 certificates validation
//!
//! Demonstrates how to validate Filecoin F3 finality certificates
//!
//! ## Usage:
//! ```bash
//! cargo run --example certificates_validation -- calibrationnet
//! cargo run --example certificates_validation -- filecoin
//! ```
//!
//! Note: this example uses a simple sequential approach for demonstration purposes.
//! For production use, certificates could be fetched concurrently.
//!
use anyhow::Result;
use filecoin_f3_gpbft::PowerEntries;
use filecoin_f3_gpbft::powertable::{is_strong_quorum, signer_scaled_total};
use filecoin_f3_lightclient::LightClient;
use std::env;

struct NetworkConfig {
    network_name: &'static str,
    endpoint: &'static str,
}

const NETWORK_CONFIGS: [NetworkConfig; 2] = [
    NetworkConfig {
        network_name: "calibrationnet",
        endpoint: "https://filecoin-calibration.ipc.space/rpc/v1",
    },
    NetworkConfig {
        network_name: "filecoin",
        endpoint: "https://filecoin.ipc.space/rpc/v1",
    },
];

#[tokio::main]
async fn main() -> Result<()> {
    println!("F3 certificates validation example");

    let config = get_network_config()?;
    println!(
        "connecting to network `{}` F3 RPC endpoint: {:?}",
        config.network_name, config.endpoint
    );

    let mut client = LightClient::new(config.endpoint, config.network_name)?;

    println!("initializing with instance 0");
    let mut state = client.initialize(0).await?;
    println!("instance 0 power table size: {}", state.power_table.len());

    println!("starting to loop");
    println!("------------------------");
    for i in 0..20 {
        println!("instance {}: fetching certificate...", i);
        let cert = client.get_certificate(i).await?;
        let instance = cert.gpbft_instance;

        // Calculate signer information
        let signer_count = cert.signers.iter().count();
        let power_entries = PowerEntries(state.power_table.to_vec());
        let signer_indices: Vec<u64> = cert.signers.iter().collect();
        let (scaled_power, total_scaled) = power_entries.scaled()?;
        let signer_scaled_total = signer_scaled_total(&scaled_power, &signer_indices)?;
        let power_percentage = (signer_scaled_total * 100) / total_scaled;
        let is_quorum = is_strong_quorum(signer_scaled_total, total_scaled);

        println!("instance {}: got certificate", cert.gpbft_instance);
        let suffix = cert.ec_chain.suffix();
        let last_epoch = suffix.last().map(|ts| ts.epoch);
        println!(
            "instance {}: chain suffix size: {}, last epoch: {}",
            instance,
            suffix.len(),
            last_epoch.map_or("none".to_string(), |epoch| epoch.to_string()),
        );
        println!(
            "instance {}: {}/{} signers, {}/{} power ({}%, strong quorum: {})",
            instance,
            signer_count,
            state.power_table.len(),
            signer_scaled_total,
            total_scaled,
            power_percentage,
            is_quorum,
        );
        println!(
            "instance {}: power table diffs: {}",
            instance,
            cert.power_table_delta.len(),
        );
        println!(
            "instance {}: power table cid: {}",
            instance, cert.supplemental_data.power_table,
        );

        println!("instance {}: validating certificate...", instance);
        match client.validate_certificates(&state, &[cert]) {
            Ok(new_state) => {
                println!("instance {}: certificate validated successfully", instance);
                println!("new instance: {}", new_state.instance);
                println!("new power table size: {}", new_state.power_table.len());
                let chain_last = new_state.chain.as_ref().unwrap().last().unwrap();
                println!("new chain last tipset epoch: {}", chain_last.epoch);
                println!("new chain last tipset key: {}", to_hex(&chain_last.key));
                println!(
                    "new chain last tipset commitments hash: {}",
                    chain_last.commitments
                );
                println!("------------------------");

                state = new_state;
            }
            Err(e) => {
                println!("instance {}: validation error: {}", instance, e);
                return Err(e.into());
            }
        }
    }
    Ok(())
}

fn get_network_config() -> Result<&'static NetworkConfig> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <network_name>", args[0]);
        eprintln!("Available networks: calibrationnet, filecoin");
        std::process::exit(1);
    }

    let network_name = &args[1];
    NETWORK_CONFIGS
        .iter()
        .find(|c| c.network_name == network_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown network '{}'. Available networks: {}",
                network_name,
                NETWORK_CONFIGS
                    .iter()
                    .map(|c| c.network_name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
