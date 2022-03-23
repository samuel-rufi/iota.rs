// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! cargo run --example stronghold --features=stronghold --release

use iota_client::{
    signing::{stronghold::StrongholdSigner, Signer},
    Client, Result,
};
extern crate dotenv;
use dotenv::dotenv;
use std::{env, path::PathBuf};

/// In this example we will create addresses with a stronghold signer

#[tokio::main]
async fn main() -> Result<()> {
    // Create a client instance
    let iota = Client::builder()
        .with_node("http://localhost:14265")? // Insert your node URL here
        .with_node_sync_disabled()
        .finish()
        .await?;

    let mut stronghold_signer = StrongholdSigner::builder()
        .password("some_hopefully_secure_password")
        .snapshot_path(PathBuf::from("test.stronghold"))
        .build()
        .unwrap();

    // This example uses dotenv, which is not safe for use in production
    dotenv().ok();
    let mnemonic = env::var("NONSECURE_USE_OF_DEVELOPMENT_MNEMONIC1").unwrap();
    // The mnemonic only needs to be stored the first time
    stronghold_signer.store_mnemonic(mnemonic).await.unwrap();

    // Generate addresses with custom account index and range
    let addresses = iota
        .get_addresses(&stronghold_signer.into())
        .with_account_index(0)
        .with_range(0..2)
        .finish()
        .await?;

    println!("List of generated public addresses:\n{:?}\n", addresses);

    Ok(())
}
