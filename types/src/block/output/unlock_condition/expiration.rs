// Copyright 2021-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use derive_more::From;

use crate::block::{address::Address, Error};

/// Defines a unix time until which only Address, defined in Address Unlock Condition, is allowed to unlock the output.
/// After or at the unix time, only Return Address can unlock it.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, From, packable::Packable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExpirationUnlockCondition {
    // The address that can unlock the expired output.
    return_address: Address,
    // Before this unix time, seconds since unix epoch,
    // [`AddressUnlockCondition`](crate::unlock_condition::AddressUnlockCondition) is allowed to unlock the output.
    // After that, only the return [`Address`](crate::address::Address) can.
    #[packable(verify_with = verify_timestamp)]
    timestamp: u32,
}

impl ExpirationUnlockCondition {
    /// The [`UnlockCondition`](crate::block::output::UnlockCondition) kind of an [`ExpirationUnlockCondition`].
    pub const KIND: u8 = 3;

    /// Creates a new [`ExpirationUnlockCondition`].
    #[inline(always)]
    pub fn new(return_address: Address, timestamp: u32) -> Result<Self, Error> {
        verify_timestamp::<true>(&timestamp, &())?;

        Ok(Self {
            return_address,
            timestamp,
        })
    }

    /// Returns the return address of a [`ExpirationUnlockCondition`].
    #[inline(always)]
    pub fn return_address(&self) -> &Address {
        &self.return_address
    }

    /// Returns the timestamp of a [`ExpirationUnlockCondition`].
    #[inline(always)]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns the return address if the condition has expired.
    pub fn return_address_expired(&self, timestamp: u32) -> Option<&Address> {
        if timestamp >= self.timestamp() {
            Some(&self.return_address)
        } else {
            None
        }
    }
}

#[inline]
fn verify_timestamp<const VERIFY: bool>(timestamp: &u32, _: &()) -> Result<(), Error> {
    if VERIFY && *timestamp == 0 {
        Err(Error::ExpirationUnlockConditionZero)
    } else {
        Ok(())
    }
}

#[cfg(feature = "dto")]
#[allow(missing_docs)]
pub mod dto {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::block::{address::dto::AddressDto, error::dto::DtoError};

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ExpirationUnlockConditionDto {
        #[serde(rename = "type")]
        pub kind: u8,
        #[serde(rename = "returnAddress")]
        pub return_address: AddressDto,
        #[serde(rename = "unixTime")]
        pub timestamp: u32,
    }

    impl From<&ExpirationUnlockCondition> for ExpirationUnlockConditionDto {
        fn from(value: &ExpirationUnlockCondition) -> Self {
            ExpirationUnlockConditionDto {
                kind: ExpirationUnlockCondition::KIND,
                return_address: value.return_address().into(),
                timestamp: value.timestamp(),
            }
        }
    }

    impl TryFrom<&ExpirationUnlockConditionDto> for ExpirationUnlockCondition {
        type Error = DtoError;

        fn try_from(value: &ExpirationUnlockConditionDto) -> Result<ExpirationUnlockCondition, DtoError> {
            ExpirationUnlockCondition::new(
                (&value.return_address)
                    .try_into()
                    .map_err(|_e| DtoError::InvalidField("expirationUnlockCondition"))?,
                value.timestamp,
            )
            .map_err(|_| DtoError::InvalidField("expirationUnlockCondition"))
        }
    }
}
