// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Database provider interfaces and implementations.

mod stronghold;

pub use self::stronghold::StrongholdDatabaseProvider;

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

/// The interface for database providers.
#[async_trait]
pub trait DatabaseProvider {
    /// Get a value out of the database.
    async fn get<V>(&mut self, k: &str) -> Option<V>
    where
        V: DeserializeOwned;

    /// Insert a value into the database.
    ///
    /// If there exists a record under the same key as `k`, it will be replaced by the new value (`v`) and returned.
    async fn insert<V, U>(&mut self, k: &str, v: &V) -> Option<U>
    where
        V: Send + Sync + Serialize,
        U: Send + Sync + DeserializeOwned;

    /// Delete a value from the database.
    ///
    /// The deleted value is returned.
    async fn delete<V>(&mut self, k: &str) -> Option<V>
    where
        V: Send + Sync + DeserializeOwned;
}
