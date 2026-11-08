//! Duplicate-safe, restart-safe persistent payment records.
//!
//! The store contains only public metadata. Private keys are re-derived from
//! the wallet seed; they are never serialized here.

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use fs2::FileExt;

use epic_core::core::receipt_claim::StealthReceiptDescriptor;
use epic_core::core::{Output, OutputIdentifier};
use epic_util::secp;
use epic_util::secp::key::PublicKey;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::derive::HARDENED;
use crate::{deserialize_output, receipt_identifier, Result, SnipError};

pub const STORE_VERSION: u32 = 1;
pub const DERIVATION_VERSION: u32 = 1;
pub const DEFAULT_GAP_LIMIT: u32 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Direction {
    Incoming,
    Outgoing,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Incoming => "incoming",
            Direction::Outgoing => "outgoing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Created or discovered, not yet confirmed by a UTXO check.
    Pending,
    /// The receipt output is unspent in the canonical UTXO set.
    Confirmed,
    /// The receipt output is in a canonical block but no longer unspent.
    Spent,
    /// The receipt output is not in any canonical block (reorged out).
    Orphaned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentRecord {
    pub payment_id: String,
    pub receipt_commit: String,
    pub receipt_output_hex: String,
    pub direction: Direction,
    pub amount: u64,
    pub amount_known: bool,
    pub payment_index: Option<u32>,
    pub derivation_version: u32,
    pub descriptor_id: Option<String>,
    pub funding_tx_id: Option<String>,
    pub block_hash: Option<String>,
    pub confirmation_height: Option<u64>,
    pub status: PaymentStatus,
    pub reclaimable: bool,
    pub spent_by: Option<String>,
}

impl PaymentRecord {
    /// Stable store key: a receipt can be incoming and outgoing in one wallet.
    pub fn key(&self) -> String {
        format!("{}:{}", self.direction.as_str(), self.payment_id)
    }

    pub fn output(&self) -> Result<Output> {
        deserialize_output(&self.receipt_output_hex)
    }

    pub fn identifier(&self) -> Result<OutputIdentifier> {
        Ok(receipt_identifier(&self.output()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DescriptorRecord {
    pub descriptor_id: String,
    pub scan_public_key: String,
    pub receipt_spend_public_key: String,
}

impl DescriptorRecord {
    pub fn to_descriptor(&self, secp: &secp::Secp256k1) -> Result<StealthReceiptDescriptor> {
        let scan = epic_util::from_hex(self.scan_public_key.clone())
            .map_err(|e| SnipError::InvalidRecord(format!("scan key hex: {}", e)))?;
        let spend = epic_util::from_hex(self.receipt_spend_public_key.clone())
            .map_err(|e| SnipError::InvalidRecord(format!("spend key hex: {}", e)))?;
        Ok(StealthReceiptDescriptor {
            scan_public_key: PublicKey::from_slice(secp, &scan)
                .map_err(|e| SnipError::InvalidRecord(format!("scan key: {}", e)))?,
            receipt_spend_public_key: PublicKey::from_slice(secp, &spend)
                .map_err(|e| SnipError::InvalidRecord(format!("spend key: {}", e)))?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreState {
    pub version: u32,
    pub next_payment_index: u32,
    pub last_scanned_height: u64,
    pub last_scanned_hash: Option<String>,
    pub records: BTreeMap<String, PaymentRecord>,
    pub descriptors: BTreeMap<String, DescriptorRecord>,
}

impl Default for StoreState {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            next_payment_index: 0,
            last_scanned_height: 0,
            last_scanned_hash: None,
            records: BTreeMap::new(),
            descriptors: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertOutcome {
    Inserted,
    Duplicate,
}

pub struct SnipStore {
    path: PathBuf,
    state: StoreState,
    /// Held for the lifetime of the store to keep the advisory file lock.
    _lock: File,
}

impl SnipStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        // Acquire an advisory exclusive lock so two writers cannot corrupt the
        // JSON store. The lock is released when this store is dropped.
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| SnipError::Store(format!("create {}: {}", parent.display(), e)))?;
        }
        let lock_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)
            .map_err(|e| SnipError::Store(format!("open lock {}: {}", lock_path.display(), e)))?;
        lock_file
            .try_lock_exclusive()
            .map_err(|e| SnipError::Store(format!("wallet is already open: {}", e)))?;

        let state = if path.exists() {
            let data = fs::read_to_string(&path)
                .map_err(|e| SnipError::Store(format!("read {}: {}", path.display(), e)))?;
            serde_json::from_str(&data)
                .map_err(|e| SnipError::Store(format!("parse {}: {}", path.display(), e)))?
        } else {
            StoreState::default()
        };
        if state.version != STORE_VERSION {
            return Err(SnipError::Store(format!(
                "unsupported store version {} (expected {})",
                state.version, STORE_VERSION
            )));
        }
        Ok(Self {
            path,
            state,
            _lock: lock_file,
        })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn state(&self) -> &StoreState {
        &self.state
    }

    pub fn records(&self) -> impl Iterator<Item = &PaymentRecord> {
        self.state.records.values()
    }

    pub fn get(&self, key: &str) -> Option<&PaymentRecord> {
        self.state.records.get(key)
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| SnipError::Store(format!("create {}: {}", parent.display(), e)))?;
        }
        let data = serde_json::to_string_pretty(&self.state)
            .map_err(|e| SnipError::Store(format!("serialize: {}", e)))?;
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, data)
            .map_err(|e| SnipError::Store(format!("write {}: {}", tmp.display(), e)))?;
        fs::rename(&tmp, &self.path)
            .map_err(|e| SnipError::Store(format!("rename {}: {}", self.path.display(), e)))?;
        Ok(())
    }

    /// Inserts a new record. Existing records are never duplicated.
    pub fn insert(&mut self, record: PaymentRecord) -> Result<InsertOutcome> {
        let key = record.key();
        if self.state.records.contains_key(&key) {
            return Ok(InsertOutcome::Duplicate);
        }
        self.state.records.insert(key, record);
        self.save()?;
        Ok(InsertOutcome::Inserted)
    }

    /// Inserts or refreshes a record seen again during a rescan.
    pub fn upsert_seen(&mut self, record: PaymentRecord) -> Result<InsertOutcome> {
        let key = record.key();
        if let Some(existing) = self.state.records.get_mut(&key) {
            existing.amount = record.amount;
            existing.amount_known = record.amount_known;
            existing.confirmation_height = record.confirmation_height;
            existing.status = record.status;
            existing.reclaimable = record.reclaimable;
            existing.receipt_output_hex = record.receipt_output_hex;
            // A chain scan cannot recover the funding transaction id, so keep
            // the value that `create_payment` recorded.
            if record.funding_tx_id.is_some() {
                existing.funding_tx_id = record.funding_tx_id;
            }
            existing.block_hash = record.block_hash;
            self.save()?;
            return Ok(InsertOutcome::Duplicate);
        }
        self.state.records.insert(key, record);
        self.save()?;
        Ok(InsertOutcome::Inserted)
    }

    pub fn update_status(
        &mut self,
        key: &str,
        status: PaymentStatus,
        spent_by: Option<String>,
    ) -> Result<()> {
        if let Some(record) = self.state.records.get_mut(key) {
            record.status = status;
            if spent_by.is_some() {
                record.spent_by = spent_by;
            }
            self.save()?;
        }
        Ok(())
    }

    /// Allocates and persists the next unique payment index.
    pub fn allocate_payment_index(&mut self) -> Result<u32> {
        let index = self.state.next_payment_index;
        if index >= HARDENED {
            return Err(SnipError::Store(
                "payment index exhausted the hardened derivation range".into(),
            ));
        }
        self.state.next_payment_index = index
            .checked_add(1)
            .ok_or_else(|| SnipError::Store("payment index overflow".into()))?;
        self.save()?;
        Ok(index)
    }

    /// Raises the index watermark after a recovery scan.
    pub fn bump_next_payment_index(&mut self, next: u32) -> Result<()> {
        if next > HARDENED {
            return Err(SnipError::Store(
                "payment index watermark is outside the hardened derivation range".into(),
            ));
        }
        if next > self.state.next_payment_index {
            self.state.next_payment_index = next;
            self.save()?;
        }
        Ok(())
    }

    pub fn set_scan_checkpoint(&mut self, height: u64, hash: Option<String>) -> Result<()> {
        self.state.last_scanned_height = height;
        self.state.last_scanned_hash = hash;
        self.save()
    }

    pub fn register_descriptor(
        &mut self,
        descriptor: &StealthReceiptDescriptor,
        secp: &secp::Secp256k1,
    ) -> Result<String> {
        let scan = descriptor.scan_public_key.serialize_vec(secp, true);
        let spend = descriptor.receipt_spend_public_key.serialize_vec(secp, true);
        let id = descriptor_id(&scan, &spend);
        let record = DescriptorRecord {
            descriptor_id: id.clone(),
            scan_public_key: epic_util::to_hex(scan.to_vec()),
            receipt_spend_public_key: epic_util::to_hex(spend.to_vec()),
        };
        self.state.descriptors.insert(id.clone(), record);
        self.save()?;
        Ok(id)
    }

    pub fn descriptor(
        &self,
        descriptor_id: &str,
        secp: &secp::Secp256k1,
    ) -> Result<StealthReceiptDescriptor> {
        self.state
            .descriptors
            .get(descriptor_id)
            .ok_or_else(|| SnipError::DescriptorRequired)?
            .to_descriptor(secp)
    }
}

/// Stable id for a public descriptor: SHA-256 of both compressed public keys.
pub fn descriptor_id(scan: &[u8], spend: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(scan);
    hash.update(spend);
    epic_util::to_hex(hash.finalize().to_vec())
}
