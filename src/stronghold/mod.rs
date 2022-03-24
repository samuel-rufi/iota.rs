// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! [Stronghold] integration for iota.rs.
//!
//! [Stronghold] can be used as a multi-purpose secret service providing:
//!
//! - Smart-card-like secret _vault_
//! - Generic key-value database _store_
//!
//! This module contains the implementation of [StrongholdClient], a multi-purpose wrapper on a [Stronghold] connection
//! for [Signer] and [DatabaseProvider].
//!
//! [Stronghold]: iota_stronghold

mod common;
mod db;
mod signer;

use crate::signing::{SignerHandle, SignerType};
use derive_builder::Builder;
use iota_stronghold::Stronghold;
use log::debug;
use riker::actors::ActorSystem;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(feature = "async"))]
use std::sync::Mutex;
#[cfg(feature = "async")]
use tokio::sync::Mutex;

use self::common::PRIVATE_DATA_CLIENT_PATH;

/// A wrapper on [Stronghold].
#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct StrongholdClient {
    /// A stronghold instance.
    #[builder(default = "Self::default_stronghold()?")]
    stronghold: Stronghold,

    /// A key to open the Stronghold vault.
    ///
    /// Note that in [StrongholdClientBuilder] there isn't a `key()` setter, because we don't want a user to directly
    /// set this field. Instead, [StrongholdClientBuilder::password()] is provided to hash a user-input password string
    /// and derive a key from it.
    #[builder(default = "Arc::new(Mutex::new(None))", setter(custom))]
    key: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,

    /// An interval of time, after which `key` will be cleared from the memory.
    ///
    /// This is an extra security measure to further prevent attacks. If a timeout is set, then upon a `key` is set, a
    /// timer will be spawned in the background to clear ([zeroize]) the key after `timeout`.
    ///
    /// If [StrongholdClient] is destroyed (dropped), then the timer will stop too.
    #[builder(default, setter(strip_option))]
    timeout: Option<Duration>,

    /// A handle to the timeout task.
    #[builder(default = "Arc::new(Mutex::new(None))", setter(skip))]
    timeout_task: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// The path to a snapshot (persistent Stronghold).
    snapshot_path: PathBuf,

    /// Whether the snapshot has been loaded from the disk to the memory.
    #[builder(setter(skip))]
    snapshot_loaded: bool,
}

/// [SignerHandle]s wrapping [Signer]s are still required at some places.
impl From<StrongholdClient> for SignerHandle {
    fn from(signer: StrongholdClient) -> Self {
        SignerHandle {
            signer: Arc::new(Mutex::new(Box::new(signer))),
            signer_type: SignerType::Stronghold,
        }
    }
}

/// Extra / custom builder method implementations.
impl StrongholdClientBuilder {
    /// Use an user-input password string to derive a key to use [Stronghold].
    pub fn password(mut self, password: &str) -> Self {
        // Note that derive_builder always adds another layer of Option<T>.
        self.key = Some(Arc::new(Mutex::new(Some(self::common::derive_key_from_password(
            password,
        )))));
        self
    }

    /// We create a default Stronghold instance if none is supplied by the user.
    fn default_stronghold() -> Result<Stronghold, String> {
        let system = ActorSystem::new().map_err(|err| err.to_string())?;
        let client_path = PRIVATE_DATA_CLIENT_PATH.to_vec();
        let options = Vec::new();

        Ok(Stronghold::init_stronghold_system(system, client_path, options))
    }
}

impl StrongholdClient {
    /// Create a builder to construct a [StrongholdClient].
    pub fn builder() -> StrongholdClientBuilder {
        StrongholdClientBuilder::default()
    }

    /// Use an user-input password string to derive a key to use [Stronghold].
    pub async fn set_password(&mut self, password: &str) -> &mut Self {
        *self.key.lock().await = Some(self::common::derive_key_from_password(password));

        // If a timeout is set, spawn a task to clear the key after the timeout.
        if let Some(timeout) = self.timeout {
            // If there has been a spawned task, stop it and re-spawn one.
            if let Some(timeout_task) = self.timeout_task.lock().await.take() {
                timeout_task.abort();
            }

            // The key clearing task, with the data it owns.
            let key = self.key.clone();
            let task_self = self.timeout_task.clone();

            *self.timeout_task.lock().await = Some(tokio::spawn(async move {
                tokio::time::sleep(timeout).await;

                debug!("StrongholdClient is purging the key");
                if let Some(mut key) = key.lock().await.take() {
                    key.zeroize();
                }

                // Take self, but do nothing (we're exiting anyways).
                task_self.lock().await.take();
            }));
        }

        self
    }

    /// Immediately clear ([zeroize]) the stored key.
    ///
    /// If a key clearing thread has been spawned, then it'll be stopped too.
    pub async fn clear_key(&mut self) {
        // Stop a spawned task and setting it to None first.
        if let Some(timeout_task) = self.timeout_task.lock().await.take() {
            timeout_task.abort();
        }

        // Purge the key, setting it to None then.
        if let Some(mut key) = self.key.lock().await.take() {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clear_key() {
        let mut client = StrongholdClient::builder()
            .snapshot_path(PathBuf::from("test.stronghold"))
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();

        // Passwords can be set later; no clearing task was spawned; any action requiring the key (derived from the
        // password) would fail.
        assert!(matches!(*client.key.lock().await, None));
        assert!(matches!(client.timeout, Some(_)));
        assert!(matches!(*client.timeout_task.lock().await, None));

        // Setting a password would spawn a task to automatically clear the key.
        client.set_password("password").await;
        assert!(matches!(*client.key.lock().await, Some(_)));
        assert!(matches!(client.timeout, Some(_)));
        assert!(matches!(*client.timeout_task.lock().await, Some(_)));

        // After the timeout, the key should be purged.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(matches!(*client.key.lock().await, None));
        assert!(matches!(client.timeout, Some(_)));
        assert!(matches!(*client.timeout_task.lock().await, None));

        // Set the key again, but this time we manually purge the key.
        client.set_password("password").await;
        assert!(matches!(*client.key.lock().await, Some(_)));
        assert!(matches!(client.timeout, Some(_)));
        assert!(matches!(*client.timeout_task.lock().await, Some(_)));

        client.clear_key().await;
        assert!(matches!(*client.key.lock().await, None));
        assert!(matches!(client.timeout, Some(_)));
        assert!(matches!(*client.timeout_task.lock().await, None));
    }
}
