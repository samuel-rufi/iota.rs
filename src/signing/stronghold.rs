// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Stronghold-as-a-Signer implementation.

use crate::stronghold::StrongholdAdapter;

/// Stronghold as a signer.
///
/// This is just an alias to the all-in-one [StrongholdAdapter].
pub type StrongholdSigner = StrongholdAdapter;
