//! Reusable, recoverable SNIP wallet primitives for the Usernet research
//! prototype.
//!
//! The crate intentionally does not depend on `epic_chain`. Chain access is
//! abstracted through [`ChainView`], so the same wallet logic can be used by a
//! node, a wallet, or a test harness. All cryptography, transaction building,
//! and consensus validation are reused from `epic_core` and `epic_keychain`.
//!
//! Private keys are never written to the persistent store. Payment records
//! contain public receipt metadata only; all secrets are re-derived from the
//! wallet seed and the payment index.

pub mod build;
pub mod derive;
pub mod scan;
pub mod store;

use std::path::PathBuf;

use epic_core::core::receipt_claim::{ReceiptStealthHint, StealthReceiptDescriptor};
use epic_core::core::{Block, Output, OutputFeatures, OutputIdentifier};
use epic_keychain::ExtKeychain;
use epic_util::secp;
use epic_util::secp::key::SecretKey;

pub use build::CreatedPayment;
pub use derive::{
    alice_authorization_key, alice_ephemeral_secret, bob_secrets, destination_blind, path,
    KEY_ALICE_AUTH, KEY_ALICE_EPHEMERAL, KEY_BOB_SCAN, KEY_BOB_SPEND, KEY_DESTINATION, ROLE_ALICE,
    ROLE_BOB, SNIP_PURPOSE,
};
pub use scan::{RefreshReport, RestoreReport, ScanMode, ScanReport};
pub use store::{
    DescriptorRecord, Direction, PaymentRecord, PaymentStatus, SnipStore, StoreState,
};

/// Errors returned by the reusable SNIP wallet.
#[derive(Debug, thiserror::Error)]
pub enum SnipError {
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("core error: {0}")]
    Core(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("chain view error: {0}")]
    Chain(String),
    #[error("payment not found: {0}")]
    PaymentNotFound(String),
    #[error("duplicate payment index: {0}")]
    DuplicateIndex(u32),
    #[error("the recipient descriptor is required to reclaim this payment")]
    DescriptorRequired,
    #[error("invalid payment record: {0}")]
    InvalidRecord(String),
}

pub type Result<T> = std::result::Result<T, SnipError>;

/// Minimal chain view needed for scanning, UTXO checks, and reorg detection.
///
/// `is_unspent` must return [`ChainViewError::NotFound`] when the output is not
/// in the current UTXO set. The wallet distinguishes a spent output from an
/// orphaned output by asking [`ChainView::contains_output`].
pub trait ChainView {
    fn tip_height(&self) -> u64;
    fn block_at_height(&self, height: u64) -> Option<Block>;
    fn block_hash_at_height(&self, height: u64) -> Option<String>;
    fn is_unspent(&self, id: &OutputIdentifier) -> std::result::Result<(), ChainViewError>;

    /// Returns true if the exact output is present in any canonical block.
    fn contains_output(&self, id: &OutputIdentifier) -> bool {
        for height in 0..=self.tip_height() {
            if let Some(block) = self.block_at_height(height) {
                if block
                    .outputs()
                    .iter()
                    .any(|output| OutputIdentifier::from_output(output) == *id)
                {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainViewError {
    NotFound,
    Other(String),
}

/// The reusable SNIP wallet.
///
/// One instance owns one Epic keychain seed and one persistent store. The same
/// type acts as Bob (incoming receipts) and Alice (outgoing receipts); the
/// direction is recorded per payment.
pub struct SnipWallet {
    keychain: ExtKeychain,
    store: SnipStore,
    secp: secp::Secp256k1,
}

impl SnipWallet {
    /// Opens a wallet from an Epic keychain and a JSON store path.
    pub fn open(keychain: ExtKeychain, store_path: impl Into<PathBuf>) -> Result<Self> {
        let store = SnipStore::open(store_path)?;
        Ok(Self {
            keychain,
            store,
            secp: secp::Secp256k1::with_caps(secp::ContextFlag::Commit),
        })
    }

    pub fn keychain(&self) -> &ExtKeychain {
        &self.keychain
    }

    pub fn store(&self) -> &SnipStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut SnipStore {
        &mut self.store
    }

    pub fn secp(&self) -> &secp::Secp256k1 {
        &self.secp
    }

    /// Bob's reusable descriptor, derived deterministically from the seed.
    pub fn create_descriptor(&self) -> Result<StealthReceiptDescriptor> {
        let secrets = bob_secrets(&self.keychain)?;
        secrets
            .descriptor(&self.secp)
            .map_err(|e| SnipError::Core(format!("descriptor: {}", e)))
    }

    /// Registers a public recipient descriptor and returns its stable id.
    pub fn register_descriptor(
        &mut self,
        descriptor: &StealthReceiptDescriptor,
    ) -> Result<String> {
        self.store.register_descriptor(descriptor, &self.secp)
    }

    /// Derives a destination blind for a claim or reclaim.
    pub fn destination_blind(&self, role: u32, index: u32) -> Result<SecretKey> {
        destination_blind(&self.keychain, role, index)
    }

    /// Derives Alice's per-payment authorization key.
    pub fn alice_authorization_key(
        &self,
        payment_index: u32,
    ) -> Result<epic_core::core::receipt_claim::AliceReceiptAuthorizationKey> {
        alice_authorization_key(&self.keychain, payment_index, &self.secp)
    }

    /// Derives Alice's per-payment ephemeral secret.
    pub fn alice_ephemeral_secret(&self, payment_index: u32) -> Result<SecretKey> {
        alice_ephemeral_secret(&self.keychain, payment_index)
    }
}

/// Serializes a public receipt output for the persistent record.
pub(crate) fn serialize_output(output: &Output) -> Result<String> {
    let mut bytes = Vec::new();
    epic_core::ser::serialize_default(&mut bytes, output)
        .map_err(|e| SnipError::Core(format!("serialize output: {}", e)))?;
    Ok(epic_util::to_hex(bytes))
}

/// Deserializes a public receipt output from the persistent record.
pub(crate) fn deserialize_output(hex: &str) -> Result<Output> {
    let bytes = epic_util::from_hex(hex.to_owned())
        .map_err(|e| SnipError::InvalidRecord(format!("output hex: {}", e)))?;
    epic_core::ser::deserialize_default(&mut &bytes[..])
        .map_err(|e| SnipError::InvalidRecord(format!("output: {}", e)))
}

/// Builds the exact UTXO identifier for a receipt output.
pub(crate) fn receipt_identifier(output: &Output) -> OutputIdentifier {
    OutputIdentifier {
        features: OutputFeatures::Receipt,
        commit: output.commit,
        receipt_key_hashes: output.receipt_key_hashes,
        receipt_stealth_hint: output.receipt_stealth_hint,
    }
}

/// Extracts the public hint from a receipt output.
pub(crate) fn receipt_hint(output: &Output) -> Result<ReceiptStealthHint> {
    output
        .receipt_stealth_hint
        .ok_or_else(|| SnipError::InvalidRecord("receipt output has no stealth hint".into()))
}


