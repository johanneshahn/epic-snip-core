//! Experimental Usernet-only receipt-claim primitives.
//!
//! These types are deliberately not wired into transaction serialization or
//! consensus validation yet. They define the canonical, domain-separated
//! receipt message that later `AliceReclaim` and `BobClaim` kernel features
//! must validate.

use crate::core::transaction::{
    Input, KernelFeatures, Output, OutputFeatures, OutputIdentifier, Transaction, TxKernel,
};
use crate::libtx::secp_ser;
use crate::ser::{self, Readable, Reader, Writeable, Writer};
use crate::util::secp;
use crate::util::secp::ecdh::SharedSecret;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen::Commitment;
use crate::util::secp::Signature;
use crate::util::static_secp_instance;
use crate::util::{from_hex, to_hex};
use serde::{Deserialize as SerdeDeserialize, Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"EPIC-SNIP-USERNET-v1|receipt-claim|";

/// A one-time public hint that lets Bob scan and derive his receipt key.
///
/// This is encoded as compressed secp256k1 public-key bytes to keep receipt
/// outputs `Copy` and to make the bytes committed by the output MMR explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptStealthHint {
    #[serde(with = "stealth_hint_serde")]
    pub ephemeral_public_key: [u8; 33],
}

mod stealth_hint_serde {
    use super::*;
    use serde::de::Error;

    pub fn serialize<S>(bytes: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&to_hex(bytes.to_vec()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = from_hex(String::deserialize(deserializer)?)
            .map_err(|err| Error::custom(err.to_string()))?;
        bytes
            .try_into()
            .map_err(|_| Error::custom("receipt stealth hint must be 33 bytes"))
    }
}

impl ReceiptStealthHint {
    pub fn from_public_key(key: &PublicKey, secp: &secp::Secp256k1) -> Self {
        let bytes = key.serialize_vec(secp, true);
        let mut ephemeral_public_key = [0; 33];
        ephemeral_public_key.copy_from_slice(&bytes);
        Self {
            ephemeral_public_key,
        }
    }

    pub fn public_key(&self, secp: &secp::Secp256k1) -> Result<PublicKey, ser::Error> {
        PublicKey::from_slice(secp, &self.ephemeral_public_key)
            .map_err(|_| ser::Error::CorruptedData)
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
        self.public_key(&secp).is_ok()
    }
}

impl Writeable for ReceiptStealthHint {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        let bytes: &[u8] = &self.ephemeral_public_key;
        writer.write_fixed_bytes(&bytes)
    }
}

impl Readable for ReceiptStealthHint {
    fn read(reader: &mut dyn Reader) -> Result<Self, ser::Error> {
        let bytes = reader.read_fixed_bytes(33)?;
        let mut ephemeral_public_key = [0; 33];
        ephemeral_public_key.copy_from_slice(&bytes);
        let hint = Self {
            ephemeral_public_key,
        };
        let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
        hint.public_key(&secp)?;
        Ok(hint)
    }
}

/// Bob's public, reusable descriptor for deriving one-time receipt keys.
#[derive(Clone, Debug)]
pub struct StealthReceiptDescriptor {
    pub scan_public_key: PublicKey,
    pub receipt_spend_public_key: PublicKey,
}

/// Bob's private counterpart to [`StealthReceiptDescriptor`].
#[derive(Clone)]
pub struct StealthReceiptSecrets {
    scan_secret_key: SecretKey,
    receipt_spend_secret_key: SecretKey,
}

impl StealthReceiptSecrets {
    pub fn new(scan_secret_key: SecretKey, receipt_spend_secret_key: SecretKey) -> Self {
        Self {
            scan_secret_key,
            receipt_spend_secret_key,
        }
    }

    pub fn descriptor(&self, secp: &secp::Secp256k1) -> Result<StealthReceiptDescriptor, ser::Error> {
        Ok(StealthReceiptDescriptor {
            scan_public_key: PublicKey::from_secret_key(secp, &self.scan_secret_key)
                .map_err(|_| ser::Error::CorruptedData)?,
            receipt_spend_public_key: PublicKey::from_secret_key(secp, &self.receipt_spend_secret_key)
                .map_err(|_| ser::Error::CorruptedData)?,
        })
    }

    /// Bob scans `hint` and derives the private receipt key for this output.
    pub fn derive_receipt_key(
        &self,
        descriptor: &StealthReceiptDescriptor,
        hint: &ReceiptStealthHint,
        secp: &secp::Secp256k1,
    ) -> Result<SecretKey, ser::Error> {
        let ephemeral = hint.public_key(secp)?;
        let tweak = receipt_tweak(
            secp,
            &self.scan_secret_key,
            &ephemeral,
            &ephemeral,
            &descriptor.receipt_spend_public_key,
        )?;
        let mut receipt_key = self.receipt_spend_secret_key.clone();
        receipt_key
            .add_assign(secp, &tweak)
            .map_err(|_| ser::Error::CorruptedData)?;
        Ok(receipt_key)
    }

    /// Derives the experimental shared Mimblewimble spend blind for a receipt
    /// output whose public hint Bob has scanned.
    ///
    /// Alice can derive the identical scalar from her ephemeral secret and
    /// Bob's public descriptor. It is deliberately distinct from the
    /// one-time receipt authorization key derived by [`Self::derive_receipt_key`].
    /// This primitive alone does not construct a valid output or range proof.
    pub fn derive_shared_spend_blind(
        &self,
        descriptor: &StealthReceiptDescriptor,
        hint: &ReceiptStealthHint,
        secp: &secp::Secp256k1,
    ) -> Result<SecretKey, ser::Error> {
        let ephemeral = hint.public_key(secp)?;
        shared_spend_blind(
            secp,
            &self.scan_secret_key,
            &ephemeral,
            &ephemeral,
            &descriptor.scan_public_key,
        )
    }
}

impl StealthReceiptDescriptor {
    /// Alice creates a new public hint and the corresponding Bob receipt
    /// public key. She cannot derive the matching private receipt key.
    pub fn derive_for_sender(
        &self,
        ephemeral_secret_key: &SecretKey,
        secp: &secp::Secp256k1,
    ) -> Result<(ReceiptStealthHint, PublicKey), ser::Error> {
        let ephemeral = PublicKey::from_secret_key(secp, ephemeral_secret_key)
            .map_err(|_| ser::Error::CorruptedData)?;
        let hint = ReceiptStealthHint::from_public_key(&ephemeral, secp);
        let tweak = receipt_tweak(
            secp,
            ephemeral_secret_key,
            &self.scan_public_key,
            &ephemeral,
            &self.receipt_spend_public_key,
        )?;
        let mut receipt_public_key = self.receipt_spend_public_key.clone();
        receipt_public_key
            .add_exp_assign(secp, &tweak)
            .map_err(|_| ser::Error::CorruptedData)?;
        Ok((hint, receipt_public_key))
    }

    /// Derives the experimental shared Mimblewimble spend blind for Alice.
    ///
    /// The recipient independently derives this scalar with
    /// [`StealthReceiptSecrets::derive_shared_spend_blind`] after scanning the
    /// hint. Both parties can therefore construct the output commitment. This
    /// intentionally reflects the proposed threat model: Alice also retains
    /// the ability to spend the shared output before Bob confirms a claim.
    pub fn derive_shared_spend_blind_for_sender(
        &self,
        ephemeral_secret_key: &SecretKey,
        secp: &secp::Secp256k1,
    ) -> Result<SecretKey, ser::Error> {
        let ephemeral = PublicKey::from_secret_key(secp, ephemeral_secret_key)
            .map_err(|_| ser::Error::CorruptedData)?;
        shared_spend_blind(
            secp,
            ephemeral_secret_key,
            &self.scan_public_key,
            &ephemeral,
            &self.scan_public_key,
        )
    }
}

fn receipt_tweak(
    secp: &secp::Secp256k1,
    secret: &SecretKey,
    peer: &PublicKey,
    ephemeral: &PublicKey,
    receipt_spend_public_key: &PublicKey,
) -> Result<SecretKey, ser::Error> {
    let shared = SharedSecret::new(secp, peer, secret);
    for counter in 0_u8..=255 {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(b"stealth-receipt-tweak|");
        hash.update(&shared[..]);
        hash.update(ephemeral.serialize_vec(secp, true).as_slice());
        hash.update(receipt_spend_public_key.serialize_vec(secp, true).as_slice());
        hash.update([counter]);
        if let Ok(tweak) = SecretKey::from_slice(secp, &hash.finalize()) {
            return Ok(tweak);
        }
    }
    Err(ser::Error::CorruptedData)
}

/// Produces a scalar known to the sender of a fresh hint and the scanning
/// recipient, but not to an observer of the output. The domain differs from
/// `receipt_tweak` so this cannot be mistaken for, or reused as, a receipt
/// authorization key.
fn shared_spend_blind(
    secp: &secp::Secp256k1,
    secret: &SecretKey,
    peer: &PublicKey,
    ephemeral: &PublicKey,
    scan_public_key: &PublicKey,
) -> Result<SecretKey, ser::Error> {
    let shared = SharedSecret::new(secp, peer, secret);
    for counter in 0_u8..=255 {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(b"shared-spend-blind|");
        hash.update(&shared[..]);
        hash.update(ephemeral.serialize_vec(secp, true).as_slice());
        hash.update(scan_public_key.serialize_vec(secp, true).as_slice());
        hash.update([counter]);
        if let Ok(blind) = SecretKey::from_slice(secp, &hash.finalize()) {
            return Ok(blind);
        }
    }
    Err(ser::Error::CorruptedData)
}

/// Builds the experimental shared receipt output from the blind that Alice and
/// Bob derive independently.
///
/// The range proof is rewindable only through `rewind_shared_receipt_output`,
/// not through the ordinary wallet proof builder. This is intentional for the
/// terminal Usernet prototype and is not a wallet recovery design.
pub fn build_shared_receipt_output(
    value: u64,
    shared_blind: &SecretKey,
    receipt_key_hashes: SharedReceiptKeyHashes,
    receipt_stealth_hint: ReceiptStealthHint,
    secp: &secp::Secp256k1,
) -> Result<Output, ser::Error> {
    let commit = secp
        .commit(value, shared_blind.clone())
        .map_err(|_| ser::Error::CorruptedData)?;
    let rewind_nonce = shared_rewind_nonce(secp, shared_blind, &commit)?;
    let proof = secp.bullet_proof(
        value,
        shared_blind.clone(),
        rewind_nonce,
        SecretKey::new(secp, &mut rand::rng()),
        None,
        None,
    );
    Ok(Output {
        features: OutputFeatures::Receipt,
        commit,
        proof,
        receipt_key_hashes: Some(receipt_key_hashes),
        receipt_stealth_hint: Some(receipt_stealth_hint),
    })
}

/// Rewinds the experimental receipt range proof after Bob has derived the
/// shared blind. This is only for the local research flow; it has no standard
/// wallet message, recovery path, or audited key-management story.
pub fn rewind_shared_receipt_output(
    output: &Output,
    shared_blind: &SecretKey,
    secp: &secp::Secp256k1,
) -> Result<u64, ser::Error> {
    if !output.features.is_receipt() {
        return Err(ser::Error::CorruptedData);
    }
    let rewind_nonce = shared_rewind_nonce(secp, shared_blind, &output.commit)?;
    let info = secp
        .rewind_bullet_proof(output.commit, rewind_nonce, None, output.proof)
        .map_err(|_| ser::Error::CorruptedData)?;
    Ok(info.value)
}

/// Builds Bob's one-input, one-output receipt-claim transaction.
///
/// This creates a valid Core transaction only when the caller supplies the
/// actual receipt amount and controls the global Usernet test-mode gate before
/// validation. It does not submit to a node, update a txhashset, handle
/// reorgs, or provide wallet persistence/recovery.
pub fn build_bob_claim_transaction(
    receipt_output: &Output,
    receipt_value: u64,
    shared_blind: &SecretKey,
    bob_receipt_key: &SecretKey,
    destination_blind: &SecretKey,
    fee: u64,
    secp: &secp::Secp256k1,
) -> Result<Transaction, ser::Error> {
    if !receipt_output.features.is_receipt() {
        return Err(ser::Error::CorruptedData);
    }
    let hashes = receipt_output
        .receipt_key_hashes
        .ok_or(ser::Error::CorruptedData)?;
    let hint = receipt_output
        .receipt_stealth_hint
        .ok_or(ser::Error::CorruptedData)?;
    let destination_value = receipt_value
        .checked_sub(fee)
        .ok_or(ser::Error::CorruptedData)?;
    let destination_commit = secp
        .commit(destination_value, destination_blind.clone())
        .map_err(|_| ser::Error::CorruptedData)?;
    let destination_proof = secp.bullet_proof(
        destination_value,
        destination_blind.clone(),
        SecretKey::new(secp, &mut rand::rng()),
        SecretKey::new(secp, &mut rand::rng()),
        None,
        None,
    );

    // `outputs + fee - inputs` is the kernel excess, hence b_destination -
    // b_shared for this one-input, one-output transaction.
    let kernel_secret = secp
        .blind_sum(
            vec![destination_blind.clone()],
            vec![shared_blind.clone()],
        )
        .map_err(|_| ser::Error::CorruptedData)?;
    let features = KernelFeatures::BobClaim { fee };
    let excess = secp
        .commit(0, kernel_secret.clone())
        .map_err(|_| ser::Error::CorruptedData)?;
    let message = features
        .kernel_sig_msg()
        .map_err(|_| ser::Error::CorruptedData)?;
    let excess_public_key = excess
        .to_pubkey(secp)
        .map_err(|_| ser::Error::CorruptedData)?;
    let excess_sig = secp::aggsig::sign_single(
        secp,
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .map_err(|_| ser::Error::CorruptedData)?;
    let receipt_claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        receipt_output.commit,
        excess,
        fee,
        bob_receipt_key,
    )?;

    Ok(Transaction::new(
        vec![Input {
            features: OutputFeatures::Receipt,
            commit: receipt_output.commit,
            receipt_key_hashes: Some(hashes),
            receipt_stealth_hint: Some(hint),
        }],
        vec![Output {
            features: OutputFeatures::Plain,
            commit: destination_commit,
            proof: destination_proof,
            receipt_key_hashes: None,
            receipt_stealth_hint: None,
        }],
        vec![TxKernel {
            features,
            excess,
            excess_sig,
            receipt_claim: Some(receipt_claim),
        }],
    ))
}

/// Builds Alice's funding transaction for a shared receipt output from one
/// known existing input.
///
/// This is deliberately a narrow research helper, not a wallet coin-selection
/// API. The caller owns and supplies the input blind and amount. The resulting
/// transaction has a regular funding kernel, while the later Bob transaction
/// carries the `BobClaim` receipt kernel.
pub fn build_receipt_funding_transaction(
    input: Input,
    input_value: u64,
    input_blind: &SecretKey,
    shared_blind: &SecretKey,
    receipt_key_hashes: SharedReceiptKeyHashes,
    receipt_stealth_hint: ReceiptStealthHint,
    fee: u64,
    secp: &secp::Secp256k1,
) -> Result<Transaction, ser::Error> {
    if input.features.is_receipt() {
        return Err(ser::Error::CorruptedData);
    }
    let expected_input = secp
        .commit(input_value, input_blind.clone())
        .map_err(|_| ser::Error::CorruptedData)?;
    if expected_input != input.commit {
        return Err(ser::Error::CorruptedData);
    }
    let receipt_value = input_value
        .checked_sub(fee)
        .ok_or(ser::Error::CorruptedData)?;
    let receipt_output = build_shared_receipt_output(
        receipt_value,
        shared_blind,
        receipt_key_hashes,
        receipt_stealth_hint,
        secp,
    )?;

    // `outputs + fee - inputs` is the excess: b_shared - b_input.
    let kernel_secret = secp
        .blind_sum(vec![shared_blind.clone()], vec![input_blind.clone()])
        .map_err(|_| ser::Error::CorruptedData)?;
    let features = KernelFeatures::Plain { fee };
    let excess = secp
        .commit(0, kernel_secret.clone())
        .map_err(|_| ser::Error::CorruptedData)?;
    let message = features
        .kernel_sig_msg()
        .map_err(|_| ser::Error::CorruptedData)?;
    let excess_public_key = excess
        .to_pubkey(secp)
        .map_err(|_| ser::Error::CorruptedData)?;
    let excess_sig = secp::aggsig::sign_single(
        secp,
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .map_err(|_| ser::Error::CorruptedData)?;

    Ok(Transaction::new(
        vec![input],
        vec![receipt_output],
        vec![TxKernel {
            features,
            excess,
            excess_sig,
            receipt_claim: None,
        }],
    ))
}

fn shared_rewind_nonce(
    secp: &secp::Secp256k1,
    shared_blind: &SecretKey,
    commit: &Commitment,
) -> Result<SecretKey, ser::Error> {
    for counter in 0_u8..=255 {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(b"shared-output-rewind-nonce|");
        hash.update(&shared_blind.0);
        hash.update(commit.as_ref());
        hash.update([counter]);
        if let Ok(nonce) = SecretKey::from_slice(secp, &hash.finalize()) {
            return Ok(nonce);
        }
    }
    Err(ser::Error::CorruptedData)
}

/// Public commitment material intended for a future special output. The raw
/// receipt keys remain absent until the eventual resolution kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SharedReceiptKeyHashes {
    pub alice: [u8; 32],
    pub bob: [u8; 32],
}

/// Experimental UTXO identity for a future shared-receipt output. It keeps the
/// existing output identifier intact while binding the two receipt-key hashes
/// into the same serialized identity.
#[derive(Clone, Debug, PartialEq)]
pub struct SharedReceiptOutputIdentifier {
    pub output: OutputIdentifier,
    pub receipt_keys: SharedReceiptKeyHashes,
}

impl Writeable for SharedReceiptOutputIdentifier {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        self.output.write(writer)?;
        self.receipt_keys.write(writer)
    }
}

impl Readable for SharedReceiptOutputIdentifier {
    fn read(reader: &mut dyn Reader) -> Result<Self, ser::Error> {
        Ok(Self {
            output: OutputIdentifier::read(reader)?,
            receipt_keys: SharedReceiptKeyHashes::read(reader)?,
        })
    }
}

impl SharedReceiptKeyHashes {
    #[must_use]
    pub fn from_public_keys(alice: &PublicKey, bob: &PublicKey) -> Self {
        let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
        Self {
            alice: receipt_key_hash(alice, &secp),
            bob: receipt_key_hash(bob, &secp),
        }
    }

    /// Returns whether `key` is the registered one-time key for `path`.
    /// The public key itself is revealed only in the resolution kernel.
    #[must_use]
    pub fn matches(&self, path: ReceiptPath, key: &PublicKey) -> bool {
        let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
        let expected = match path {
            ReceiptPath::AliceReclaim => self.alice,
            ReceiptPath::BobClaim => self.bob,
        };
        expected == receipt_key_hash(key, &secp)
    }
}

impl Writeable for SharedReceiptKeyHashes {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        writer.write_fixed_bytes(&self.alice)?;
        writer.write_fixed_bytes(&self.bob)
    }
}

impl Readable for SharedReceiptKeyHashes {
    fn read(reader: &mut dyn Reader) -> Result<Self, ser::Error> {
        let alice = reader.read_fixed_bytes(32)?;
        let bob = reader.read_fixed_bytes(32)?;
        Ok(Self {
            alice: alice.try_into().map_err(|_| ser::Error::CorruptedData)?,
            bob: bob.try_into().map_err(|_| ser::Error::CorruptedData)?,
        })
    }
}

fn receipt_key_hash(key: &PublicKey, secp: &secp::Secp256k1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"receipt-key|");
    hash.update(key.serialize_vec(secp, true).as_slice());
    hash.finalize().into()
}

/// The only permitted resolution paths for a future shared receipt output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReceiptPath {
    AliceReclaim,
    BobClaim,
}

impl ReceiptPath {
    fn tag(self) -> u8 {
        match self {
            Self::AliceReclaim => 0,
            Self::BobClaim => 1,
        }
    }
}

impl Writeable for ReceiptPath {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        writer.write_u8(self.tag())
    }
}

impl Readable for ReceiptPath {
    fn read(reader: &mut dyn Reader) -> Result<Self, ser::Error> {
        match reader.read_u8()? {
            0 => Ok(Self::AliceReclaim),
            1 => Ok(Self::BobClaim),
            _ => Err(ser::Error::CorruptedData),
        }
    }
}

/// A receipt signature binds a one-time receipt key to a specific consumed
/// output and the final transaction kernel excess. It intentionally does not
/// identify the claim transaction's destination output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptClaim {
    pub path: ReceiptPath,
    #[serde(
        serialize_with = "secp_ser::as_hex",
        deserialize_with = "secp_ser::commitment_from_hex"
    )]
    pub original_commitment: Commitment,
    #[serde(
        serialize_with = "secp_ser::as_hex",
        deserialize_with = "secp_ser::commitment_from_hex"
    )]
    pub kernel_excess: Commitment,
    pub fee: u64,
    #[serde(with = "secp_ser::pubkey_serde")]
    pub receipt_public_key: PublicKey,
    #[serde(with = "secp_ser::sig_serde")]
    pub receipt_signature: Signature,
}

impl ReceiptClaim {
    /// Builds the canonical signature message. This is a proposal until the
    /// feature is versioned and activated in Usernet consensus.
    pub fn message(
        path: ReceiptPath,
        original_commitment: Commitment,
        kernel_excess: Commitment,
        fee: u64,
    ) -> Result<secp::Message, ser::Error> {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update([path.tag()]);
        hash.update(original_commitment.as_ref());
        hash.update(kernel_excess.as_ref());
        hash.update(fee.to_le_bytes());
        secp::Message::from_slice(&hash.finalize()).map_err(|_| ser::Error::CorruptedData)
    }

    pub fn sign(
        path: ReceiptPath,
        original_commitment: Commitment,
        kernel_excess: Commitment,
        fee: u64,
        receipt_secret_key: &SecretKey,
    ) -> Result<Self, ser::Error> {
        let message = Self::message(path, original_commitment, kernel_excess, fee)?;
        let secp = static_secp_instance();
        let secp = secp.lock();
        let receipt_public_key = PublicKey::from_secret_key(&secp, receipt_secret_key)
            .map_err(|_| ser::Error::CorruptedData)?;
        let receipt_signature = secp::aggsig::sign_single(
            &secp,
            &message,
            receipt_secret_key,
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|_| ser::Error::CorruptedData)?;
        Ok(Self {
            path,
            original_commitment,
            kernel_excess,
            fee,
            receipt_public_key,
            receipt_signature,
        })
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let Ok(message) = Self::message(
            self.path,
            self.original_commitment,
            self.kernel_excess,
            self.fee,
        ) else {
            return false;
        };
        let secp = static_secp_instance();
        let secp = secp.lock();
        secp::aggsig::verify_single(
            &secp,
            &self.receipt_signature,
            &message,
            None,
            &self.receipt_public_key,
            None,
            None,
            false,
        )
    }
}

impl Writeable for ReceiptClaim {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        self.path.write(writer)?;
        self.original_commitment.write(writer)?;
        self.kernel_excess.write(writer)?;
        writer.write_u64(self.fee)?;
        self.receipt_public_key.write(writer)?;
        self.receipt_signature.write(writer)
    }
}

impl Readable for ReceiptClaim {
    fn read(reader: &mut dyn Reader) -> Result<Self, ser::Error> {
        Ok(Self {
            path: ReceiptPath::read(reader)?,
            original_commitment: Commitment::read(reader)?,
            kernel_excess: Commitment::read(reader)?,
            fee: reader.read_u64()?,
            receipt_public_key: PublicKey::read(reader)?,
            receipt_signature: Signature::read(reader)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::secp::{ContextFlag, Secp256k1};

    fn key() -> SecretKey {
        SecretKey::new(&Secp256k1::with_caps(ContextFlag::Commit), &mut rand::rng())
    }

    #[test]
    fn receipt_claim_is_bound_to_path_original_and_kernel() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let receipt_key = key();
        let original = secp.commit(10, key()).unwrap();
        let kernel = secp.commit(0, key()).unwrap();
        let proof =
            ReceiptClaim::sign(ReceiptPath::BobClaim, original, kernel, 2, &receipt_key).unwrap();
        assert!(proof.verify());
        assert!(!ReceiptClaim {
            path: ReceiptPath::AliceReclaim,
            ..proof.clone()
        }
        .verify());
        assert!(!ReceiptClaim { fee: 3, ..proof }.verify());
    }

    #[test]
    fn receipt_claim_binary_roundtrip_preserves_the_proof() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let proof = ReceiptClaim::sign(
            ReceiptPath::AliceReclaim,
            secp.commit(10, key()).unwrap(),
            secp.commit(0, key()).unwrap(),
            2,
            &key(),
        )
        .unwrap();
        let bytes = ser::ser_vec(&proof, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        let decoded: ReceiptClaim = ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert!(decoded.verify());
        assert_eq!(decoded.path, ReceiptPath::AliceReclaim);
    }

    #[test]
    fn shared_receipt_key_hashes_are_role_bound() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let alice = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let bob = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&alice, &bob);
        assert_ne!(hashes.alice, hashes.bob);
        assert_ne!(
            hashes,
            SharedReceiptKeyHashes::from_public_keys(&bob, &alice)
        );
    }

    #[test]
    fn shared_receipt_key_hashes_binary_roundtrip() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let alice = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let bob = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&alice, &bob);
        let bytes = ser::ser_vec(&hashes, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        let decoded: SharedReceiptKeyHashes = ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, hashes);
    }

    #[test]
    fn stealth_receipt_derivation_matches_for_sender_and_bob() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let secrets = StealthReceiptSecrets::new(key(), key());
        let descriptor = secrets.descriptor(&secp).unwrap();
        let ephemeral = key();

        let (hint, sender_bob_public_key) = descriptor
            .derive_for_sender(&ephemeral, &secp)
            .unwrap();
        let bob_receipt_key = secrets
            .derive_receipt_key(&descriptor, &hint, &secp)
            .unwrap();
        let bob_receipt_public_key =
            PublicKey::from_secret_key(&secp, &bob_receipt_key).unwrap();

        assert_eq!(sender_bob_public_key, bob_receipt_public_key);
        assert_ne!(sender_bob_public_key, descriptor.receipt_spend_public_key);

        let bytes = ser::ser_vec(&hint, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        let decoded: ReceiptStealthHint = ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, hint);
    }

    #[test]
    fn shared_spend_blind_matches_for_sender_and_bob() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let secrets = StealthReceiptSecrets::new(key(), key());
        let descriptor = secrets.descriptor(&secp).unwrap();
        let ephemeral = key();
        let (hint, _) = descriptor.derive_for_sender(&ephemeral, &secp).unwrap();

        let alice_blind = descriptor
            .derive_shared_spend_blind_for_sender(&ephemeral, &secp)
            .unwrap();
        let bob_blind = secrets
            .derive_shared_spend_blind(&descriptor, &hint, &secp)
            .unwrap();

        assert_eq!(alice_blind, bob_blind);
        assert_eq!(secp.commit(42, alice_blind).unwrap(), secp.commit(42, bob_blind).unwrap());
    }

    #[test]
    fn bob_claim_roundtrip_builds_a_fully_valid_usernet_transaction() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let bob_secrets = StealthReceiptSecrets::new(key(), key());
        let descriptor = bob_secrets.descriptor(&secp).unwrap();
        let alice_ephemeral = key();
        let (hint, bob_receipt_public_key) = descriptor
            .derive_for_sender(&alice_ephemeral, &secp)
            .unwrap();
        let alice_reclaim_public_key = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(
            &alice_reclaim_public_key,
            &bob_receipt_public_key,
        );
        let alice_shared_blind = descriptor
            .derive_shared_spend_blind_for_sender(&alice_ephemeral, &secp)
            .unwrap();
        let bob_shared_blind = bob_secrets
            .derive_shared_spend_blind(&descriptor, &hint, &secp)
            .unwrap();
        let bob_receipt_key = bob_secrets
            .derive_receipt_key(&descriptor, &hint, &secp)
            .unwrap();
        assert_eq!(alice_shared_blind, bob_shared_blind);

        let receipt = build_shared_receipt_output(42, &alice_shared_blind, hashes, hint, &secp)
            .unwrap();
        receipt.verify_proof().unwrap();
        assert_eq!(
            rewind_shared_receipt_output(&receipt, &bob_shared_blind, &secp).unwrap(),
            42
        );

        let destination_blind = key();
        let tx = build_bob_claim_transaction(
            &receipt,
            42,
            &bob_shared_blind,
            &bob_receipt_key,
            &destination_blind,
            2,
            &secp,
        )
        .unwrap();
        crate::global::set_mining_mode(crate::global::ChainTypes::UserTesting);
        tx.validate(crate::core::transaction::Weighting::AsTransaction)
            .unwrap();
        assert_eq!(tx.outputs()[0].commit, secp.commit(40, destination_blind).unwrap());
        assert!(tx.kernels()[0].receipt_claim.as_ref().unwrap().verify());
    }
}
