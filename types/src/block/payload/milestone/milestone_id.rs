// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

impl_id!(
    pub MilestoneId,
    32,
    "A milestone identifier, the BLAKE2b-256 hash of the milestone bytes. See <https://www.blake2.net/> for more information."
);

#[cfg(feature = "serde")]
string_serde_impl!(MilestoneId);

#[cfg(feature = "inx")]
mod inx {
    use super::*;

    impl From<MilestoneId> for ::inx::proto::MilestoneId {
        fn from(value: MilestoneId) -> Self {
            Self { id: value.0.to_vec() }
        }
    }

    impl TryFrom<::inx::proto::MilestoneId> for MilestoneId {
        type Error = crate::block::error::inx::InxError;

        fn try_from(value: ::inx::proto::MilestoneId) -> Result<Self, Self::Error> {
            let bytes: [u8; MilestoneId::LENGTH] = value
                .id
                .try_into()
                .map_err(|e| Self::Error::InvalidId("MilestoneId", e))?;
            Ok(MilestoneId::from(bytes))
        }
    }
}
