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
use riker::actors::ActorSystem;
use std::{path::PathBuf, sync::Arc, time::Duration};
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
    #[builder(setter(custom))]
    key: Zeroizing<Option<Vec<u8>>>,

    /// An interval of time, after which `key` will be cleared from the memory.
    ///
    /// This is an extra security measure to further prevent attacks. If a timeout is set, then upon a `key` is set, a
    /// timer will be spawned in the background to clear ([zeroize]) the key after `timeout`.
    ///
    /// If [StrongholdClient] is destroyed (dropped), then the timer will stop too.
    #[builder(default)]
    _timeout: Option<Duration>,

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

impl StrongholdClientBuilder {
    /// Use an user-input password string to derive a key to use [Stronghold].
    pub fn password(mut self, password: &str) -> Self {
        // Note that derive_builder always adds another layer of Option<T>.
        self.key = Some(self::common::derive_key_from_password(password));
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
    pub fn set_password(&mut self, password: &str) -> &Self {
        self.key = self::common::derive_key_from_password(password);

        // TODO: Spawn the password clearing thread

        self
    }

    /// Immediately clear ([zeroize]) the stored key.
    ///
    /// If a key clearing threas has been spawned, then it'll be stopped too.
    pub fn clear_key(&mut self) -> &Self {
        self.key.zeroize();

        // TODO: Stop the password clearing thread

        self
    }
}
