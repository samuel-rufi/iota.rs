// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The [DatabaseProvider] implementation for [StrongholdClient].

use super::{
    encryption::{decrypt, encrypt},
    StrongholdClient,
};
use crate::db::DatabaseProvider;
use async_trait::async_trait;
use iota_stronghold::{Location, ResultMessage};
use log::{debug, error, warn};
use serde::{de::DeserializeOwned, Serialize};

/// Convert from a string to a Stronghold location that we'll use.
fn location_from_key(key: &str) -> Location {
    // This has been the case in wallet.rs; we preserve it here.
    Location::Generic {
        vault_path: key.as_bytes().to_vec(),
        record_path: key.as_bytes().to_vec(),
    }
}

#[async_trait]
impl DatabaseProvider for StrongholdClient {
    async fn get<V>(&mut self, k: &str) -> Option<V>
    where
        V: DeserializeOwned,
    {
        let location = location_from_key(k);
        let (data, status) = self.stronghold.read_from_store(location).await;

        if let ResultMessage::Error(err) = status {
            debug!("Stronghold reported an error: {}", err);
            return None;
        }

        let decrypted = {
            let locked_key = self.key.lock().await;
            let key = if let Some(key) = &*locked_key {
                key
            } else {
                warn!("Failed to decrypt data from store: The key has been cleared!");
                return None;
            };

            match decrypt(&data, key) {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to decrypt data from store: {}", e);
                    return None;
                }
            }
        };

        match serde_json::from_slice(&decrypted) {
            Ok(v) => Some(v),
            Err(e) => {
                error!("Failed to deserialize data from Stronghold store: {}", e);
                None
            }
        }
    }

    async fn insert<V, U>(&mut self, k: &str, v: &V) -> Option<U>
    where
        V: Send + Sync + Serialize,
        U: Send + Sync + DeserializeOwned,
    {
        // XXX: Any of the error happens below would cause a loss of data. Should we alter the design of the
        // DatabaseProvider trait?

        let old_value = self.get(k).await;
        let new_value = match serde_json::to_vec(v) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to serialize data: {}", e);
                return old_value;
            }
        };

        let encrypted = {
            let locked_key = self.key.lock().await;
            let key = if let Some(key) = &*locked_key {
                key
            } else {
                warn!("Failed to encrypt data: The key has been cleared!");
                return None;
            };

            match encrypt(&new_value, key) {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to encrypt data: {}", e);
                    return None;
                }
            }
        };

        let location = location_from_key(k);
        let status = self.stronghold.write_to_store(location, encrypted, None).await;

        if let ResultMessage::Error(err) = status {
            error!("Stronghold has failed to write data to a store: {}", err);
        }

        old_value
    }

    async fn delete<V>(&mut self, k: &str) -> Option<V>
    where
        V: Send + Sync + DeserializeOwned,
    {
        let old_value = self.get(k).await;

        let location = location_from_key(k);
        let status = self.stronghold.delete_from_store(location).await;

        if let ResultMessage::Error(err) = status {
            error!("Stronghold has failed to delete data from a store: {}", err);
        }

        old_value
    }
}

mod tests {
    #[tokio::test]
    async fn test_stronghold_db() {
        use super::StrongholdClient;
        use crate::db::DatabaseProvider;

        let mut stronghold = StrongholdClient::builder()
            .snapshot_path("test.stronghold".into())
            .password("testtset")
            .build()
            .unwrap();

        // Store something.
        let _: Option<()> = stronghold.insert("test-0", &"0-tset").await;
        let _: Option<()> = stronghold.insert("test-1", &("1", "tset")).await;
        let _: Option<()> = stronghold.insert("test-2", &["2", "tset"]).await;

        // Read them out.
        assert_eq!(stronghold.get("test-0").await, Some(String::from("0-tset")));
        assert_eq!(
            stronghold.get("test-1").await,
            Some((String::from("1"), String::from("tset")))
        );
        assert_eq!(
            stronghold.get("test-2").await,
            Some(vec![String::from("2"), String::from("tset")])
        );

        // Getting on non-existent keys returns None.
        let thiskeydoesnotexist: Option<()> = stronghold.get("thiskeydoesnotexist").await;
        assert!(matches!(thiskeydoesnotexist, None));

        // Overwriting gets the old data.
        assert_eq!(
            stronghold.insert("test-0", &["foo"]).await,
            Some(String::from("0-tset"))
        );
        assert_eq!(stronghold.get("test-0").await, Some(vec![String::from("foo")]));

        // Deleting gets the old data.
        assert_eq!(stronghold.delete("test-0").await, Some(vec![String::from("foo")]));
        assert_eq!(
            stronghold.delete("test-1").await,
            Some((String::from("1"), String::from("tset")))
        );
        assert_eq!(
            stronghold.delete("test-2").await,
            Some(vec![String::from("2"), String::from("tset")])
        );
    }
}
