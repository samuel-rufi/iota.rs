// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! [Stronghold] integration for iota.rs.
//!
//! [Stronghold] can be used as a multi-purpose secret service providing:
//!
//! - Smart-card-like secret _vault_
//! - Generic key-value encrypted database _store_
//!
//! [StrongholdClient] respectively implements [DatabaseProvider] and [Signer] for the above purposes. Type aliases
//! [StrongholdDatabaseProvider] and [StrongholdSigner] are also provided if one wants to have a more consistent naming
//! when using any of the feature sets.
//!
//! Use `builder()` to construct a [StrongholdClient] with customized parameters; see documentation
//! of methods of [StrongholdClientBuilder] for details. Alternatively, invoking `new()` (or using [Default::default()])
//! creates a [StrongholdClient] with default parameters.
//!
//! The default [StrongholdClient]:
//!
//! - is not initialized with a password
//! - is without a password clearing timeout
//! - is not associated with a snapshot file on the disk (i.e. working purely in memory)
//!
//! The default setting limits what [StrongholdClient] can do:
//!
//! - Without a password, all cryptographic operations (including database operations, as they encrypt / decrypt data)
//!   would fail.
//! - Without a password clearing timeout, the derived key would be stored in the memory for as long as possible, and
//!   could be used as an attack vector.
//! - Without a snapshot path configured, all operations would be _transient_ (i.e. all data would be lost when
//!   [StrongholdClient] is dropped).
//!
//! These configurations can also be done later using methods e.g. [set_password()], [set_snapshot_path()].
//!
//! To load / store the Stronghold state from / to a snapshot, manually invoke [read_stronghold_snapshot()] /
//! [write_stronghold_snapshot()] before / after any other operation.
//!
//! [Stronghold]: iota_stronghold
//! [DatabaseProvider]: crate::db::DatabaseProvider
//! [Signer]: crate::signing::Signer
//! [StrongholdDatabaseProvider]: crate::db::StrongholdDatabaseProvider
//! [StrongholdSigner]: crate::signing::StrongholdSigner

mod common;
mod db;
mod encryption;
mod signer;

use self::common::{PRIVATE_DATA_CLIENT_PATH, STRONGHOLD_FILENAME};
use crate::{
    signing::{SignerHandle, SignerType},
    Error, Result,
};
use derive_builder::Builder;
use iota_stronghold::{ResultMessage, Stronghold};
use log::debug;
use riker::actors::ActorSystem;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::Mutex, task::JoinHandle};
use zeroize::{Zeroize, Zeroizing};

/// A wrapper on [Stronghold].
#[derive(Builder)]
#[builder(default, pattern = "owned")]
pub struct StrongholdClient {
    /// A stronghold instance.
    stronghold: Stronghold,

    /// A key to open the Stronghold vault.
    ///
    /// Note that in [StrongholdClientBuilder] there isn't a `key()` setter, because we don't want a user to directly
    /// set this field. Instead, [StrongholdClientBuilder::password()] is provided to hash a user-input password string
    /// and derive a key from it.
    #[builder(setter(custom))]
    key: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,

    /// An interval of time, after which `key` will be cleared from the memory.
    ///
    /// This is an extra security measure to further prevent attacks. If a timeout is set, then upon a `key` is set, a
    /// timer will be spawned in the background to clear ([zeroize]) the key after `timeout`.
    ///
    /// If [StrongholdClient] is destroyed (dropped), then the timer will stop too.
    #[builder(setter(strip_option))]
    timeout: Option<Duration>,

    /// A handle to the timeout task.
    #[builder(setter(skip))]
    timeout_task: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// The path to a snapshot (persistent Stronghold).
    #[builder(setter(strip_option))]
    snapshot_path: Option<PathBuf>,

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

impl Default for StrongholdClient {
    fn default() -> Self {
        // XXX: we unwrap here.
        let system = ActorSystem::new().map_err(|err| err.to_string()).unwrap();
        let client_path = PRIVATE_DATA_CLIENT_PATH.to_vec();
        let options = Vec::new();

        Self {
            stronghold: Stronghold::init_stronghold_system(system, client_path, options),
            key: Arc::new(Mutex::new(None)),
            timeout: None,
            timeout_task: Arc::new(Mutex::new(None)),
            snapshot_path: None,
            snapshot_loaded: false,
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
}

impl StrongholdClient {
    /// Create a [StrongholdClient] with default parameters.
    pub fn new() -> StrongholdClient {
        StrongholdClient::default()
    }

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

    /// Set the path to a Stronghold snapshot file.
    pub async fn set_snapshot_path(&mut self, path: PathBuf) -> &mut Self {
        self.snapshot_path = Some(path);
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

    /// Load Stronghold from a snapshot at [Self::snapshot_path], if it hasn't been loaded yet.
    pub async fn read_stronghold_snapshot(&mut self) -> Result<()> {
        if self.snapshot_loaded {
            return Ok(());
        }

        // The key and the snapshot path need to be supplied first.
        let locked_key = self.key.lock().await;
        let key = if let Some(key) = &*locked_key {
            key
        } else {
            return Err(Error::StrongholdKeyCleared);
        };

        let snapshot_path = if let Some(path) = &self.snapshot_path {
            path
        } else {
            return Err(Error::StrongholdSnapshotPathMissing);
        };

        match self
            .stronghold
            .read_snapshot(
                PRIVATE_DATA_CLIENT_PATH.to_vec(),
                None,
                &**key,
                Some(STRONGHOLD_FILENAME.to_string()),
                Some(snapshot_path.clone()),
            )
            .await
        {
            ResultMessage::Ok(_) => Ok(()),
            ResultMessage::Error(err) => Err(crate::Error::StrongholdProcedureError(err)),
        }?;

        self.snapshot_loaded = true;

        Ok(())
    }

    /// Persist Stronghold to a snapshot at [Self::snapshot_path].
    ///
    /// It doesn't "unload" the snapshot -- Stronghold is RAM-based.
    pub async fn write_stronghold_snapshot(&mut self) -> Result<()> {
        // The key and the snapshot path need to be supplied first.
        let locked_key = self.key.lock().await;
        let key = if let Some(key) = &*locked_key {
            key
        } else {
            return Err(Error::StrongholdKeyCleared);
        };

        let snapshot_path = if let Some(path) = &self.snapshot_path {
            path
        } else {
            return Err(Error::StrongholdSnapshotPathMissing);
        };

        match self
            .stronghold
            .write_all_to_snapshot(
                &**key,
                Some(STRONGHOLD_FILENAME.to_string()),
                Some(snapshot_path.clone()),
            )
            .await
        {
            ResultMessage::Ok(_) => Ok(()),
            ResultMessage::Error(err) => Err(crate::Error::StrongholdProcedureError(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clear_key() {
        let mut client = StrongholdClient::builder()
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
