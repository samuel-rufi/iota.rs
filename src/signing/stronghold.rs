// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Stronghold-as-a-Signer implementation.

use crate::stronghold::StrongholdClient;

/// Stronghold as a signer.
///
/// This is just an alias to the all-in-one [StrongholdClient].
pub type StrongholdSigner = StrongholdClient;
