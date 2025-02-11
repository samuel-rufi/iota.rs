// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use alloc::string::{FromUtf8Error, String};
use core::{convert::Infallible, fmt};

use crypto::Error as CryptoError;
use iota_pow::Error as PowError;
use prefix_hex::Error as HexError;
use primitive_types::U256;

use crate::block::{
    input::UtxoInput,
    output::{
        feature::FeatureCount, unlock_condition::UnlockConditionCount, AliasId, MetadataFeatureLength,
        NativeTokenCount, NftId, OutputIndex, StateMetadataLength, TagFeatureLength,
    },
    parent::ParentCount,
    payload::{
        milestone::BinaryParametersLength, InputCount, MilestoneMetadataLength, MilestoneOptionCount, OutputCount,
        ReceiptFundsCount, SignatureCount, TagLength, TaggedDataLength,
    },
    unlock::{UnlockCount, UnlockIndex},
};

/// Error occurring when creating/parsing/validating blocks.
#[derive(Debug, PartialEq)]
#[allow(missing_docs)]
pub enum Error {
    CannotReplaceMissingField,
    ConsumedAmountOverflow,
    ConsumedNativeTokensAmountOverflow,
    CreatedAmountOverflow,
    CreatedNativeTokensAmountOverflow,
    Crypto(CryptoError),
    DuplicateSignatureUnlock(u16),
    DuplicateUtxo(UtxoInput),
    ExpirationUnlockConditionZero,
    FeaturesNotUniqueSorted,
    InputUnlockCountMismatch { input_count: usize, unlock_count: usize },
    InvalidAddress,
    InvalidAddressKind(u8),
    InvalidAliasIndex(<UnlockIndex as TryFrom<u16>>::Error),
    InvalidControllerKind(u8),
    InvalidStorageDepositAmount(u64),
    // The above is used by `Packable` to denote out-of-range values. The following denotes the actual amount.
    InsufficientStorageDepositAmount { amount: u64, required: u64 },
    StorageDepositReturnExceedsOutputAmount { deposit: u64, amount: u64 },
    InsufficientStorageDepositReturnAmount { deposit: u64, required: u64 },
    InvalidBinaryParametersLength(<BinaryParametersLength as TryFrom<usize>>::Error),
    InvalidEssenceKind(u8),
    InvalidFeatureCount(<FeatureCount as TryFrom<usize>>::Error),
    InvalidFeatureKind(u8),
    InvalidFoundryOutputSupply { minted: U256, melted: U256, max: U256 },
    Hex(HexError),
    InvalidInputKind(u8),
    InvalidInputCount(<InputCount as TryFrom<usize>>::Error),
    InvalidInputOutputIndex(<OutputIndex as TryFrom<u16>>::Error),
    InvalidBech32Hrp(FromUtf8Error),
    InvalidBlockLength(usize),
    InvalidStateMetadataLength(<StateMetadataLength as TryFrom<usize>>::Error),
    InvalidMetadataFeatureLength(<MetadataFeatureLength as TryFrom<usize>>::Error),
    InvalidMilestoneMetadataLength(<MilestoneMetadataLength as TryFrom<usize>>::Error),
    InvalidMilestoneOptionCount(<MilestoneOptionCount as TryFrom<usize>>::Error),
    InvalidMilestoneOptionKind(u8),
    InvalidMigratedFundsEntryAmount(u64),
    InvalidNativeTokenCount(<NativeTokenCount as TryFrom<usize>>::Error),
    InvalidNetworkName(FromUtf8Error),
    InvalidNftIndex(<UnlockIndex as TryFrom<u16>>::Error),
    InvalidOutputAmount(u64),
    InvalidOutputCount(<OutputCount as TryFrom<usize>>::Error),
    InvalidOutputKind(u8),
    InvalidParentCount(<ParentCount as TryFrom<usize>>::Error),
    InvalidPayloadKind(u32),
    InvalidPayloadLength { expected: usize, actual: usize },
    InvalidReceiptFundsCount(<ReceiptFundsCount as TryFrom<usize>>::Error),
    InvalidReceiptFundsSum(u128),
    InvalidReferenceIndex(<UnlockIndex as TryFrom<u16>>::Error),
    InvalidSignature,
    InvalidSignatureKind(u8),
    InvalidStringPrefix(<u8 as TryFrom<usize>>::Error),
    InvalidTaggedDataLength(<TaggedDataLength as TryFrom<usize>>::Error),
    InvalidTagFeatureLength(<TagFeatureLength as TryFrom<usize>>::Error),
    InvalidTagLength(<TagLength as TryFrom<usize>>::Error),
    InvalidTailTransactionHash,
    InvalidTokenSchemeKind(u8),
    InvalidTransactionAmountSum(u128),
    InvalidTransactionNativeTokensCount(u16),
    InvalidTreasuryOutputAmount(u64),
    InvalidUnlockCount(<UnlockCount as TryFrom<usize>>::Error),
    InvalidUnlockKind(u8),
    InvalidUnlockReference(u16),
    InvalidUnlockAlias(u16),
    InvalidUnlockNft(u16),
    InvalidUnlockConditionCount(<UnlockConditionCount as TryFrom<usize>>::Error),
    InvalidUnlockConditionKind(u8),
    MigratedFundsNotSorted,
    MilestoneInvalidSignatureCount(<SignatureCount as TryFrom<usize>>::Error),
    MilestonePublicKeysSignaturesCountMismatch { key_count: usize, sig_count: usize },
    MilestoneOptionsNotUniqueSorted,
    MilestoneSignaturesNotUniqueSorted,
    MissingAddressUnlockCondition,
    MissingGovernorUnlockCondition,
    MissingPayload,
    MissingRequiredSenderBlock,
    MissingStateControllerUnlockCondition,
    NativeTokensNotUniqueSorted,
    NativeTokensNullAmount,
    NativeTokensOverflow,
    NetworkIdMismatch { expected: u64, actual: u64 },
    NonZeroStateIndexOrFoundryCounter,
    ParentsNotUniqueSorted,
    ProtocolVersionMismatch { expected: u8, actual: u8 },
    Pow(PowError),
    ReceiptFundsNotUniqueSorted,
    RemainingBytesAfterBlock,
    SelfControlledAliasOutput(AliasId),
    SelfDepositNft(NftId),
    SignaturePublicKeyMismatch { expected: String, actual: String },
    StorageDepositReturnOverflow,
    TailTransactionHashNotUnique { previous: usize, current: usize },
    TimelockUnlockConditionZero,
    UnallowedFeature { index: usize, kind: u8 },
    UnallowedUnlockCondition { index: usize, kind: u8 },
    UnlockConditionsNotUniqueSorted,
    UnsupportedOutputKind(u8),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CannotReplaceMissingField => write!(f, "cannot replace missing field"),
            Error::ConsumedAmountOverflow => write!(f, "consumed amount overflow"),
            Error::ConsumedNativeTokensAmountOverflow => write!(f, "consumed native tokens amount overflow"),
            Error::CreatedAmountOverflow => write!(f, "created amount overflow"),
            Error::CreatedNativeTokensAmountOverflow => write!(f, "created native tokens amount overflow"),
            Error::Crypto(e) => write!(f, "cryptographic error: {e}"),
            Error::DuplicateSignatureUnlock(index) => {
                write!(f, "duplicate signature unlock at index: {index}")
            }
            Error::DuplicateUtxo(utxo) => write!(f, "duplicate UTXO {utxo:?} in inputs"),
            Error::ExpirationUnlockConditionZero => {
                write!(
                    f,
                    "expiration unlock condition with milestone index and timestamp set to 0",
                )
            }
            Error::FeaturesNotUniqueSorted => write!(f, "features are not unique and/or sorted"),
            Error::InputUnlockCountMismatch {
                input_count,
                unlock_count,
            } => {
                write!(
                    f,
                    "input count and unlock count mismatch: {input_count} != {unlock_count}",
                )
            }
            Error::InvalidAddress => write!(f, "invalid address provided"),
            Error::InvalidAddressKind(k) => write!(f, "invalid address kind: {k}"),
            Error::InvalidAliasIndex(index) => write!(f, "invalid alias index: {index}"),
            Error::InvalidBech32Hrp(err) => write!(f, "invalid bech32 hrp: {err}"),
            Error::InvalidBinaryParametersLength(length) => {
                write!(f, "invalid binary parameters length: {length}")
            }
            Error::InvalidControllerKind(k) => write!(f, "invalid controller kind: {k}"),
            Error::InvalidStorageDepositAmount(amount) => {
                write!(f, "invalid storage deposit amount: {amount}")
            }
            Error::InsufficientStorageDepositAmount { amount, required } => {
                write!(
                    f,
                    "insufficient output amount for storage deposit: {amount} (should be at least {required})"
                )
            }
            Error::InsufficientStorageDepositReturnAmount { deposit, required } => {
                write!(
                    f,
                    "the return deposit ({deposit}) must be greater than the minimum storage deposit ({required})"
                )
            }
            Error::StorageDepositReturnExceedsOutputAmount { deposit, amount } => write!(
                f,
                "storage deposit return of {deposit} exceeds the original output amount of {amount}"
            ),
            Error::InvalidEssenceKind(k) => write!(f, "invalid essence kind: {k}"),
            Error::InvalidFeatureCount(count) => write!(f, "invalid feature count: {count}"),
            Error::InvalidFeatureKind(k) => write!(f, "invalid feature kind: {k}"),
            Error::InvalidFoundryOutputSupply { minted, melted, max } => write!(
                f,
                "invalid foundry output supply: minted {minted}, melted {melted} max {max}",
            ),
            Error::Hex(error) => write!(f, "hex error: {error}"),
            Error::InvalidInputKind(k) => write!(f, "invalid input kind: {k}"),
            Error::InvalidInputCount(count) => write!(f, "invalid input count: {count}"),
            Error::InvalidInputOutputIndex(index) => write!(f, "invalid input or output index: {index}"),
            Error::InvalidBlockLength(length) => write!(f, "invalid block length {length}"),
            Error::InvalidStateMetadataLength(length) => write!(f, "invalid state metadata length {length}"),
            Error::InvalidMetadataFeatureLength(length) => {
                write!(f, "invalid metadata feature length {length}")
            }
            Error::InvalidMilestoneMetadataLength(length) => {
                write!(f, "invalid milestone metadata length {length}")
            }
            Error::InvalidMilestoneOptionCount(count) => write!(f, "invalid milestone option count: {count}"),
            Error::InvalidMilestoneOptionKind(k) => write!(f, "invalid milestone option kind: {k}"),
            Error::InvalidMigratedFundsEntryAmount(amount) => {
                write!(f, "invalid migrated funds entry amount: {amount}")
            }
            Error::InvalidNativeTokenCount(count) => write!(f, "invalid native token count: {count}"),
            Error::InvalidNetworkName(err) => write!(f, "invalid network name: {err}"),
            Error::InvalidNftIndex(index) => write!(f, "invalid nft index: {index}"),
            Error::InvalidOutputAmount(amount) => write!(f, "invalid output amount: {amount}"),
            Error::InvalidOutputCount(count) => write!(f, "invalid output count: {count}"),
            Error::InvalidOutputKind(k) => write!(f, "invalid output kind: {k}"),
            Error::InvalidParentCount(count) => {
                write!(f, "invalid parents count: {count}")
            }
            Error::InvalidPayloadKind(k) => write!(f, "invalid payload kind: {k}"),
            Error::InvalidPayloadLength { expected, actual } => {
                write!(f, "invalid payload length: expected {expected} but got {actual}")
            }
            Error::InvalidReceiptFundsCount(count) => write!(f, "invalid receipt funds count: {count}"),
            Error::InvalidReceiptFundsSum(sum) => write!(f, "invalid receipt amount sum: {sum}"),
            Error::InvalidReferenceIndex(index) => write!(f, "invalid reference index: {index}"),
            Error::InvalidSignature => write!(f, "invalid signature provided"),
            Error::InvalidSignatureKind(k) => write!(f, "invalid signature kind: {k}"),
            Error::InvalidStringPrefix(p) => write!(f, "invalid string prefix: {p}"),
            Error::InvalidTaggedDataLength(length) => {
                write!(f, "invalid tagged data length {length}")
            }
            Error::InvalidTagFeatureLength(length) => {
                write!(f, "invalid tag feature length {length}")
            }
            Error::InvalidTagLength(length) => {
                write!(f, "invalid tag length {length}")
            }
            Error::InvalidTailTransactionHash => write!(f, "invalid tail transaction hash"),
            Error::InvalidTokenSchemeKind(k) => write!(f, "invalid token scheme kind {k}"),
            Error::InvalidTransactionAmountSum(value) => write!(f, "invalid transaction amount sum: {value}"),
            Error::InvalidTransactionNativeTokensCount(count) => {
                write!(f, "invalid transaction native tokens count: {count}")
            }
            Error::InvalidTreasuryOutputAmount(amount) => write!(f, "invalid treasury amount: {amount}"),
            Error::InvalidUnlockCount(count) => write!(f, "invalid unlock count: {count}"),
            Error::InvalidUnlockKind(k) => write!(f, "invalid unlock kind: {k}"),
            Error::InvalidUnlockReference(index) => {
                write!(f, "invalid unlock reference: {index}")
            }
            Error::InvalidUnlockAlias(index) => {
                write!(f, "invalid unlock alias: {index}")
            }
            Error::InvalidUnlockNft(index) => {
                write!(f, "invalid unlock nft: {index}")
            }
            Error::InvalidUnlockConditionCount(count) => write!(f, "invalid unlock condition count: {count}"),
            Error::InvalidUnlockConditionKind(k) => write!(f, "invalid unlock condition kind: {k}"),
            Error::MigratedFundsNotSorted => {
                write!(f, "migrated funds are not sorted")
            }
            Error::MilestoneInvalidSignatureCount(count) => {
                write!(f, "invalid milestone signature count: {count}")
            }
            Error::MilestonePublicKeysSignaturesCountMismatch { key_count, sig_count } => {
                write!(
                    f,
                    "milestone public keys and signatures count mismatch: {key_count} != {sig_count}",
                )
            }
            Error::MilestoneOptionsNotUniqueSorted => {
                write!(f, "milestone options are not unique and/or sorted")
            }
            Error::MilestoneSignaturesNotUniqueSorted => {
                write!(f, "milestone signatures are not unique and/or sorted")
            }
            Error::MissingAddressUnlockCondition => write!(f, "missing address unlock condition"),
            Error::MissingGovernorUnlockCondition => write!(f, "missing governor unlock condition"),
            Error::MissingPayload => write!(f, "missing payload"),
            Error::MissingRequiredSenderBlock => write!(f, "missing required sender block"),
            Error::MissingStateControllerUnlockCondition => write!(f, "missing state controller unlock condition"),
            Error::NativeTokensNotUniqueSorted => write!(f, "native tokens are not unique and/or sorted"),
            Error::NativeTokensNullAmount => write!(f, "native tokens null amount"),
            Error::NativeTokensOverflow => write!(f, "native tokens overflow"),
            Error::NetworkIdMismatch { expected, actual } => {
                write!(f, "network ID mismatch: expected {expected} but got {actual}")
            }
            Error::NonZeroStateIndexOrFoundryCounter => {
                write!(f, "non zero state index or foundry counter while alias ID is all zero")
            }
            Error::ParentsNotUniqueSorted => {
                write!(f, "parents are not unique and/or sorted")
            }
            Error::ProtocolVersionMismatch { expected, actual } => {
                write!(f, "protocol version mismatch: expected {expected} but got {actual}")
            }
            Error::Pow(e) => {
                write!(f, "proof of work error: {e}")
            }
            Error::ReceiptFundsNotUniqueSorted => {
                write!(f, "receipt funds are not unique and/or sorted")
            }
            Error::RemainingBytesAfterBlock => {
                write!(f, "remaining bytes after block")
            }
            Error::SelfControlledAliasOutput(alias_id) => {
                write!(f, "self controlled alias output, alias ID {alias_id}")
            }
            Error::SelfDepositNft(nft_id) => {
                write!(f, "self deposit nft output, NFT ID {nft_id}")
            }
            Error::SignaturePublicKeyMismatch { expected, actual } => {
                write!(f, "signature public key mismatch: expected {expected} but got {actual}",)
            }
            Error::StorageDepositReturnOverflow => {
                write!(f, "storage deposit return overflow",)
            }
            Error::TailTransactionHashNotUnique { previous, current } => {
                write!(
                    f,
                    "tail transaction hash is not unique at indices: {previous} and {current}",
                )
            }
            Error::TimelockUnlockConditionZero => {
                write!(
                    f,
                    "timelock unlock condition with milestone index and timestamp set to 0",
                )
            }
            Error::UnallowedFeature { index, kind } => {
                write!(f, "unallowed feature at index {index} with kind {kind}")
            }
            Error::UnallowedUnlockCondition { index, kind } => {
                write!(f, "unallowed unlock condition at index {index} with kind {kind}")
            }
            Error::UnlockConditionsNotUniqueSorted => write!(f, "unlock conditions are not unique and/or sorted"),
            Error::UnsupportedOutputKind(k) => write!(f, "unsupported output kind: {k}"),
        }
    }
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Error::Crypto(error)
    }
}

impl From<Infallible> for Error {
    fn from(error: Infallible) -> Self {
        match error {}
    }
}

impl From<PowError> for Error {
    fn from(error: PowError) -> Self {
        Error::Pow(error)
    }
}

#[cfg(feature = "dto")]
#[allow(missing_docs)]
pub mod dto {
    use super::*;

    #[derive(Debug)]
    pub enum DtoError {
        InvalidField(&'static str),
        Block(Error),
    }

    impl fmt::Display for DtoError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                DtoError::InvalidField(field) => write!(f, "{field}"),
                DtoError::Block(error) => write!(f, "{error}"),
            }
        }
    }

    impl From<Error> for DtoError {
        fn from(error: Error) -> Self {
            DtoError::Block(error)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for DtoError {}
}

#[cfg(feature = "inx")]
#[allow(missing_docs)]
pub mod inx {
    use super::*;

    #[derive(Debug)]
    #[allow(missing_docs)]
    pub enum InxError {
        InvalidId(&'static str, Vec<u8>),
        InvalidString(String),
        InvalidRawBytes(String),
        MissingField(&'static str),
        Block(Error),
    }

    impl fmt::Display for InxError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                InxError::InvalidId(ty, bytes) => write!(f, "invalid `{ty}` with bytes `{}`", hex::encode(bytes)),
                InxError::InvalidString(error) => write!(f, "invalid string: {error}"),
                InxError::InvalidRawBytes(error) => write!(f, "invalid raw bytes: {error}"),
                InxError::MissingField(field) => write!(f, "missing field `{field}`"),
                InxError::Block(error) => write!(f, "{error}"),
            }
        }
    }

    impl From<Error> for InxError {
        fn from(error: Error) -> Self {
            InxError::Block(error)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for InxError {}
}
