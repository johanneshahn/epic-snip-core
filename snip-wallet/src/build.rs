//! Payment creation and claim/reclaim transaction builders.
//!
//! All transaction construction is delegated to the existing
//! `epic_core::core` receipt builders. This module only derives the required
//! keys and persists the non-secret payment metadata.

use epic_core::core::hash::Hashed;
use epic_core::core::receipt_claim::{ReceiptChainId, StealthReceiptDescriptor};
use epic_core::core::transaction::Weighting;
use epic_core::core::{
    build_alice_spend_transaction, build_bob_claim_transaction,
    build_receipt_funding_transaction, Input, Output, SharedReceiptKeyHashes, Transaction,
};
use epic_util::secp::key::SecretKey;

use crate::derive::{alice_authorization_key, alice_ephemeral_secret, bob_secrets};
use crate::store::{
    Direction, PaymentRecord, PaymentStatus, DERIVATION_VERSION,
};
use crate::{receipt_hint, Result, SnipError, SnipWallet};

/// A payment Alice created and can later reclaim.
pub struct CreatedPayment {
    pub payment_index: u32,
    pub payment_id: String,
    pub receipt_output: Output,
    pub funding_tx: Transaction,
}

impl SnipWallet {
    /// Creates a funding transaction for a new outgoing SNIP payment.
    ///
    /// The payment index is allocated and persisted before the transaction is
    /// built, so a crash can burn an index but can never reuse one. The funding
    /// transaction must be mined by the caller; the record starts as `Pending`.
    pub fn create_payment(
        &mut self,
        descriptor: &StealthReceiptDescriptor,
        input: Input,
        input_value: u64,
        input_blind: &SecretKey,
        fee: u64,
    ) -> Result<CreatedPayment> {
        let descriptor_id = self.register_descriptor(descriptor)?;
        let payment_index = self.store_mut().allocate_payment_index()?;

        let authorization = alice_authorization_key(self.keychain(), payment_index, self.secp())?;
        let ephemeral = alice_ephemeral_secret(self.keychain(), payment_index)?;
        let (hint, bob_receipt_public_key) = descriptor
            .derive_for_sender(&ephemeral, self.secp())
            .map_err(|e| SnipError::Core(format!("derive_for_sender: {}", e)))?;
        let shared_blind = descriptor
            .derive_shared_spend_blind_for_sender(&ephemeral, self.secp())
            .map_err(|e| SnipError::Core(format!("derive_shared_spend_blind: {}", e)))?;
        let hashes =
            SharedReceiptKeyHashes::from_public_keys(&bob_receipt_public_key, authorization.public_key());

        let funding_tx = build_receipt_funding_transaction(
            input,
            input_value,
            input_blind,
            &shared_blind,
            hashes,
            hint,
            fee,
            self.secp(),
        )
        .map_err(|e| SnipError::Core(format!("build_receipt_funding_transaction: {}", e)))?;
        funding_tx
            .validate(Weighting::AsTransaction)
            .map_err(|e| SnipError::Core(format!("funding tx validate: {}", e)))?;

        let receipt_output = funding_tx.outputs()[0].clone();
        let receipt_value = input_value
            .checked_sub(fee)
            .ok_or_else(|| SnipError::InvalidRecord("fee exceeds input value".into()))?;
        let payment_id = epic_util::to_hex(receipt_output.commit.0.to_vec());
        let record = PaymentRecord {
            payment_id: payment_id.clone(),
            receipt_commit: payment_id.clone(),
            receipt_output_hex: crate::serialize_output(&receipt_output)?,
            direction: Direction::Outgoing,
            amount: receipt_value,
            amount_known: true,
            payment_index: Some(payment_index),
            derivation_version: DERIVATION_VERSION,
            descriptor_id: Some(descriptor_id),
            funding_tx_id: Some(funding_tx.hash().to_string()),
            block_hash: None,
            confirmation_height: None,
            status: PaymentStatus::Pending,
            reclaimable: true,
            spent_by: None,
        };
        self.store_mut().insert(record)?;

        Ok(CreatedPayment {
            payment_index,
            payment_id,
            receipt_output,
            funding_tx,
        })
    }

    /// Builds Bob's claim for a discovered incoming receipt.
    pub fn build_bob_claim(
        &self,
        payment_id: &str,
        destination_blind: &SecretKey,
        fee: u64,
    ) -> Result<Transaction> {
        let key = format!("incoming:{}", payment_id);
        let record = self
            .store()
            .get(&key)
            .ok_or_else(|| SnipError::PaymentNotFound(payment_id.to_string()))?;
        if record.direction != Direction::Incoming {
            return Err(SnipError::InvalidRecord(
                "payment is not an incoming receipt".into(),
            ));
        }

        let output = record.output()?;
        let hint = receipt_hint(&output)?;
        let secrets = bob_secrets(self.keychain())?;
        let descriptor = self.create_descriptor()?;
        let shared_blind = secrets
            .derive_shared_spend_blind(&descriptor, &hint, self.secp())
            .map_err(|e| SnipError::Core(format!("derive_shared_spend_blind: {}", e)))?;
        let bob_receipt_key = secrets
            .derive_receipt_key(&descriptor, &hint, self.secp())
            .map_err(|e| SnipError::Core(format!("derive_receipt_key: {}", e)))?;

        build_bob_claim_transaction(
            &output,
            record.amount,
            &shared_blind,
            &bob_receipt_key,
            destination_blind,
            fee,
            self.secp(),
        )
        .map_err(|e| SnipError::Core(format!("build_bob_claim_transaction: {}", e)))
    }

    /// Builds Alice's independent reclaim for an outgoing receipt.
    ///
    /// If `descriptor` is `None`, the public recipient descriptor registered in
    /// the store is used. If no descriptor is available, the reclaim is
    /// impossible and [`SnipError::DescriptorRequired`] is returned. This is the
    /// explicit seed-only limitation: the receipt output does not commit to the
    /// recipient descriptor.
    pub fn build_alice_reclaim(
        &self,
        payment_id: &str,
        descriptor: Option<&StealthReceiptDescriptor>,
        destination_blind: &SecretKey,
        fee: u64,
        chain_id: ReceiptChainId,
    ) -> Result<Transaction> {
        let key = format!("outgoing:{}", payment_id);
        let record = self
            .store()
            .get(&key)
            .ok_or_else(|| SnipError::PaymentNotFound(payment_id.to_string()))?;
        if record.direction != Direction::Outgoing {
            return Err(SnipError::InvalidRecord(
                "payment is not an outgoing receipt".into(),
            ));
        }
        if !record.amount_known {
            return Err(SnipError::DescriptorRequired);
        }
        if !record.reclaimable {
            return Err(SnipError::InvalidRecord(
                "payment is not reclaimable".into(),
            ));
        }

        let descriptor = match descriptor {
            Some(descriptor) => descriptor.clone(),
            None => {
                let descriptor_id = record
                    .descriptor_id
                    .as_ref()
                    .ok_or(SnipError::DescriptorRequired)?;
                self.store().descriptor(descriptor_id, self.secp())?
            }
        };
        let payment_index = record
            .payment_index
            .ok_or_else(|| SnipError::InvalidRecord("missing payment index".into()))?;
        let output = record.output()?;
        let authorization = alice_authorization_key(self.keychain(), payment_index, self.secp())?;
        let ephemeral = alice_ephemeral_secret(self.keychain(), payment_index)?;
        let shared_blind = descriptor
            .derive_shared_spend_blind_for_sender(&ephemeral, self.secp())
            .map_err(|e| SnipError::Core(format!("derive_shared_spend_blind: {}", e)))?;

        build_alice_spend_transaction(
            &output,
            record.amount,
            &shared_blind,
            &authorization,
            destination_blind,
            fee,
            chain_id,
            self.secp(),
        )
        .map_err(|e| SnipError::Core(format!("build_alice_spend_transaction: {}", e)))
    }
}
