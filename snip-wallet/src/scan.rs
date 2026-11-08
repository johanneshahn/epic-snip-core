//! Receipt scanning and recovery.
//!
//! Incoming scanning derives Bob's one-time keys from each public hint.
//! Outgoing scanning re-derives Alice's ephemeral and authorization keys from
//! the seed and payment index, so no per-payment private key is stored.

use epic_core::core::receipt_claim::{
    rewind_shared_receipt_output, StealthReceiptDescriptor, StealthReceiptSecrets,
};
use epic_core::core::Output;
use epic_keychain::ExtKeychain;
use epic_util::secp;
use epic_util::secp::key::PublicKey;

use crate::derive::{
    alice_authorization_key, alice_ephemeral_secret, bob_secrets,
};
use crate::store::{
    Direction, InsertOutcome, PaymentRecord, PaymentStatus, DEFAULT_GAP_LIMIT,
    DERIVATION_VERSION,
};
use crate::{
    receipt_identifier, serialize_output, ChainView, ChainViewError, Result, SnipError, SnipWallet,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    Incoming,
    Outgoing,
    Both,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanReport {
    pub blocks_scanned: u64,
    pub new_records: usize,
    pub duplicates: usize,
    pub incoming: usize,
    pub outgoing: usize,
}

impl ScanReport {
    fn merge(&mut self, other: ScanReport) {
        self.blocks_scanned = self.blocks_scanned.max(other.blocks_scanned);
        self.new_records += other.new_records;
        self.duplicates += other.duplicates;
        self.incoming += other.incoming;
        self.outgoing += other.outgoing;
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RestoreReport {
    pub incoming_found: usize,
    pub outgoing_found: usize,
    pub descriptor_required: bool,
    pub next_payment_index: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RefreshReport {
    pub confirmed: usize,
    pub spent: usize,
    pub orphaned: usize,
    pub reorg_detected: bool,
}

struct ScannedIncoming {
    amount: u64,
}

struct ScannedOutgoing {
    index: u32,
    amount: u64,
}

/// Returns the payment amount if the output belongs to Bob.
fn scan_incoming_output(
    secrets: &StealthReceiptSecrets,
    descriptor: &StealthReceiptDescriptor,
    output: &Output,
    secp: &secp::Secp256k1,
) -> Option<ScannedIncoming> {
    if !output.features.is_receipt() {
        return None;
    }
    let hint = output.receipt_stealth_hint?;
    let hashes = output.receipt_key_hashes?;
    let shared_blind = secrets
        .derive_shared_spend_blind(descriptor, &hint, secp)
        .ok()?;
    let bob_key = secrets
        .derive_receipt_key(descriptor, &hint, secp)
        .ok()?;
    let bob_pub = PublicKey::from_secret_key(secp, &bob_key).ok()?;
    if !hashes.matches_bob(&bob_pub) {
        return None;
    }
    let amount = rewind_shared_receipt_output(output, &shared_blind, secp).ok()?;
    Some(ScannedIncoming { amount })
}

/// Returns Alice's payment index and amount if the output belongs to her.
fn scan_outgoing_output(
    keychain: &ExtKeychain,
    descriptor: &StealthReceiptDescriptor,
    output: &Output,
    max_index: u32,
    secp: &secp::Secp256k1,
) -> Option<ScannedOutgoing> {
    if !output.features.is_receipt() {
        return None;
    }
    let hint = output.receipt_stealth_hint?;
    let hashes = output.receipt_key_hashes?;
    let ephemeral = hint.public_key(secp).ok()?;
    let ephemeral_bytes = ephemeral.serialize_vec(secp, true);
    for index in 0..max_index {
        let r_i = alice_ephemeral_secret(keychain, index).ok()?;
        let candidate = PublicKey::from_secret_key(secp, &r_i).ok()?;
        if candidate.serialize_vec(secp, true) != ephemeral_bytes {
            continue;
        }
        let auth = alice_authorization_key(keychain, index, secp).ok()?;
        if !hashes.matches_alice(auth.public_key()) {
            continue;
        }
        let shared_blind = descriptor
            .derive_shared_spend_blind_for_sender(&r_i, secp)
            .ok()?;
        let amount = rewind_shared_receipt_output(output, &shared_blind, secp).ok()?;
        return Some(ScannedOutgoing { index, amount });
    }
    None
}

/// Identifies Alice's payment index without the recipient descriptor.
///
/// This is sufficient to recognise an outgoing receipt from the seed and the
/// chain, but not to derive the shared blind, learn the amount, or reclaim.
fn identify_outgoing_output(
    keychain: &ExtKeychain,
    output: &Output,
    max_index: u32,
    secp: &secp::Secp256k1,
) -> Option<u32> {
    if !output.features.is_receipt() {
        return None;
    }
    let hashes = output.receipt_key_hashes?;
    for index in 0..max_index {
        let auth = alice_authorization_key(keychain, index, secp).ok()?;
        if hashes.matches_alice(auth.public_key()) {
            return Some(index);
        }
    }
    None
}

fn payment_status(view: &dyn ChainView, output: &Output) -> Result<PaymentStatus> {
    let id = receipt_identifier(output);
    match view.is_unspent(&id) {
        Ok(()) => Ok(PaymentStatus::Confirmed),
        // The output is in the canonical block being scanned, so it is spent.
        Err(ChainViewError::NotFound) => Ok(PaymentStatus::Spent),
        Err(ChainViewError::Other(message)) => Err(SnipError::Chain(message)),
    }
}

fn incoming_record(
    output: &Output,
    amount: u64,
    height: u64,
    block_hash: Option<String>,
    descriptor_id: String,
    status: PaymentStatus,
) -> Result<PaymentRecord> {
    let commit = epic_util::to_hex(output.commit.0.to_vec());
    Ok(PaymentRecord {
        payment_id: commit.clone(),
        receipt_commit: commit,
        receipt_output_hex: serialize_output(output)?,
        direction: Direction::Incoming,
        amount,
        amount_known: true,
        payment_index: None,
        derivation_version: DERIVATION_VERSION,
        descriptor_id: Some(descriptor_id),
        funding_tx_id: None,
        block_hash,
        confirmation_height: Some(height),
        status,
        reclaimable: true,
        spent_by: None,
    })
}

fn outgoing_record(
    output: &Output,
    index: u32,
    amount: u64,
    amount_known: bool,
    height: u64,
    block_hash: Option<String>,
    descriptor_id: Option<String>,
    reclaimable: bool,
    status: PaymentStatus,
) -> Result<PaymentRecord> {
    let commit = epic_util::to_hex(output.commit.0.to_vec());
    Ok(PaymentRecord {
        payment_id: commit.clone(),
        receipt_commit: commit,
        receipt_output_hex: serialize_output(output)?,
        direction: Direction::Outgoing,
        amount,
        amount_known,
        payment_index: Some(index),
        derivation_version: DERIVATION_VERSION,
        descriptor_id,
        funding_tx_id: None,
        block_hash,
        confirmation_height: Some(height),
        status,
        reclaimable,
        spent_by: None,
    })
}

impl SnipWallet {
    /// Scans the canonical chain for incoming receipts belonging to Bob.
    pub fn scan_incoming(
        &mut self,
        view: &dyn ChainView,
        from: u64,
        to: u64,
    ) -> Result<ScanReport> {
        let descriptor = self.create_descriptor()?;
        let descriptor_id = self.register_descriptor(&descriptor)?;
        let secrets = bob_secrets(self.keychain())?;
        let tip = view.tip_height();
        let to = to.min(tip);
        let mut report = ScanReport::default();
        if from > to {
            return Ok(report);
        }
        for height in from..=to {
            let block = match view.block_at_height(height) {
                Some(block) => block,
                None => continue,
            };
            report.blocks_scanned += 1;
            let block_hash = view.block_hash_at_height(height);
            for output in block.outputs() {
                if let Some(scanned) =
                    scan_incoming_output(&secrets, &descriptor, output, self.secp())
                {
                    let status = payment_status(view, output)?;
                    let record = incoming_record(
                        output,
                        scanned.amount,
                        height,
                        block_hash.clone(),
                        descriptor_id.clone(),
                        status,
                    )?;
                    match self.store_mut().upsert_seen(record)? {
                        InsertOutcome::Inserted => {
                            report.new_records += 1;
                            report.incoming += 1;
                        }
                        InsertOutcome::Duplicate => report.duplicates += 1,
                    }
                }
            }
        }
        self.store_mut()
            .set_scan_checkpoint(to, view.block_hash_at_height(to))?;
        Ok(report)
    }

    /// Scans the canonical chain for Alice's outgoing receipts.
    pub fn scan_outgoing(
        &mut self,
        view: &dyn ChainView,
        descriptor: &StealthReceiptDescriptor,
        from: u64,
        to: u64,
        max_index: u32,
    ) -> Result<ScanReport> {
        let descriptor_id = self.register_descriptor(descriptor)?;
        let tip = view.tip_height();
        let to = to.min(tip);
        let mut report = ScanReport::default();
        if from > to {
            return Ok(report);
        }
        for height in from..=to {
            let block = match view.block_at_height(height) {
                Some(block) => block,
                None => continue,
            };
            report.blocks_scanned += 1;
            let block_hash = view.block_hash_at_height(height);
            for output in block.outputs() {
                if let Some(scanned) = scan_outgoing_output(
                    self.keychain(),
                    descriptor,
                    output,
                    max_index,
                    self.secp(),
                ) {
                    let status = payment_status(view, output)?;
                    let record = outgoing_record(
                        output,
                        scanned.index,
                        scanned.amount,
                        true,
                        height,
                        block_hash.clone(),
                        Some(descriptor_id.clone()),
                        true,
                        status,
                    )?;
                    match self.store_mut().upsert_seen(record)? {
                        InsertOutcome::Inserted => {
                            report.new_records += 1;
                            report.outgoing += 1;
                        }
                        InsertOutcome::Duplicate => report.duplicates += 1,
                    }
                }
            }
        }
        self.store_mut()
            .set_scan_checkpoint(to, view.block_hash_at_height(to))?;
        Ok(report)
    }

    /// Identifies outgoing receipts without the recipient descriptor.
    ///
    /// The amount is unknown and the payment is not reclaimable. This exists to
    /// make the seed-only limitation explicit and testable.
    pub fn scan_outgoing_identify(
        &mut self,
        view: &dyn ChainView,
        from: u64,
        to: u64,
        max_index: u32,
    ) -> Result<ScanReport> {
        let tip = view.tip_height();
        let to = to.min(tip);
        let mut report = ScanReport::default();
        if from > to {
            return Ok(report);
        }
        for height in from..=to {
            let block = match view.block_at_height(height) {
                Some(block) => block,
                None => continue,
            };
            report.blocks_scanned += 1;
            let block_hash = view.block_hash_at_height(height);
            for output in block.outputs() {
                if let Some(index) = identify_outgoing_output(
                    self.keychain(),
                    output,
                    max_index,
                    self.secp(),
                ) {
                    let status = payment_status(view, output)?;
                    let record = outgoing_record(
                        output,
                        index,
                        0,
                        false,
                        height,
                        block_hash.clone(),
                        None,
                        false,
                        status,
                    )?;
                    match self.store_mut().upsert_seen(record)? {
                        InsertOutcome::Inserted => {
                            report.new_records += 1;
                            report.outgoing += 1;
                        }
                        InsertOutcome::Duplicate => report.duplicates += 1,
                    }
                }
            }
        }
        Ok(report)
    }

    /// Convenience dispatcher for the requested `scan_receipts` surface.
    pub fn scan_receipts(
        &mut self,
        view: &dyn ChainView,
        from: u64,
        to: u64,
        mode: ScanMode,
        descriptor: Option<&StealthReceiptDescriptor>,
        max_index: u32,
    ) -> Result<ScanReport> {
        let mut report = ScanReport::default();
        if matches!(mode, ScanMode::Incoming | ScanMode::Both) {
            report.merge(self.scan_incoming(view, from, to)?);
        }
        if matches!(mode, ScanMode::Outgoing | ScanMode::Both) {
            let descriptor = descriptor.ok_or(SnipError::DescriptorRequired)?;
            report.merge(self.scan_outgoing(view, descriptor, from, to, max_index)?);
        }
        Ok(report)
    }

    /// Restores wallet state from the seed and the canonical chain.
    pub fn restore_wallet_state(
        &mut self,
        view: &dyn ChainView,
        descriptor: Option<&StealthReceiptDescriptor>,
    ) -> Result<RestoreReport> {
        let tip = view.tip_height();
        let next = self.store().state().next_payment_index;
        let max_index = next
            .saturating_add(DEFAULT_GAP_LIMIT)
            .max(DEFAULT_GAP_LIMIT);

        let incoming = self.scan_incoming(view, 0, tip)?;
        let outgoing = match descriptor {
            Some(descriptor) => self.scan_outgoing(view, descriptor, 0, tip, max_index)?,
            None => self.scan_outgoing_identify(view, 0, tip, max_index)?,
        };

        let max_found = self
            .store()
            .records()
            .filter_map(|record| record.payment_index)
            .max();
        if let Some(index) = max_found {
            self.store_mut().bump_next_payment_index(index + 1)?;
        }

        Ok(RestoreReport {
            incoming_found: incoming.incoming,
            outgoing_found: outgoing.outgoing,
            descriptor_required: descriptor.is_none() && outgoing.outgoing > 0,
            next_payment_index: self.store().state().next_payment_index,
        })
    }

    /// Reconciles records with the canonical UTXO set and detects reorgs.
    pub fn refresh_payment_states(&mut self, view: &dyn ChainView) -> Result<RefreshReport> {
        let mut report = RefreshReport::default();
        if let Some(hash) = self.store().state().last_scanned_hash.clone() {
            let height = self.store().state().last_scanned_height;
            if view.block_hash_at_height(height).as_deref() != Some(hash.as_str()) {
                report.reorg_detected = true;
            }
        }

        let keys: Vec<String> = self.store().records().map(|record| record.key()).collect();
        for key in keys {
            let id = match self.store().get(&key).and_then(|record| record.identifier().ok()) {
                Some(id) => id,
                None => continue,
            };
            match view.is_unspent(&id) {
                Ok(()) => {
                    self.store_mut()
                        .update_status(&key, PaymentStatus::Confirmed, None)?;
                    report.confirmed += 1;
                }
                Err(ChainViewError::NotFound) => {
                    let status = if view.contains_output(&id) {
                        PaymentStatus::Spent
                    } else {
                        PaymentStatus::Orphaned
                    };
                    if status == PaymentStatus::Spent {
                        report.spent += 1;
                    } else {
                        report.orphaned += 1;
                    }
                    self.store_mut().update_status(&key, status, None)?;
                }
                Err(ChainViewError::Other(message)) => return Err(SnipError::Chain(message)),
            }
        }
        Ok(report)
    }
}
