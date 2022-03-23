// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Database provider interfaces and implementations.

mod stronghold;

pub use self::stronghold::StrongholdDatabaseProvider;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// The interface for database providers.
#[async_trait]
pub trait DatabaseProvider {
    /// Get a value out of the database.
    async fn get<'de, K, V>(&self, k: &K) -> Option<V>
    where
        K: Send + Sync + Serialize,
        V: Deserialize<'de>;

    /// Insert a value into the database.
    ///
    /// If there exists a record under the same key as `k`, it will be replaced by the new value (`v`) and returned.
    async fn insert<'de, K, V, U>(&mut self, k: &K, v: &V) -> Option<U>
    where
        K: Send + Sync + Serialize,
        V: Send + Sync + Serialize,
        U: Deserialize<'de>;

    /// Delete a value from the database.
    ///
    /// The deleted value is returned.
    async fn delete<'de, K, V>(&mut self, k: &K) -> Option<V>
    where
        K: Send + Sync + Serialize,
        V: Send + Sync + Deserialize<'de>;
}
