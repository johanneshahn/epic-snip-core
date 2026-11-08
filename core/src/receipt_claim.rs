//! Experimental Usernet-only receipt-claim primitives.
//!
//! These types define the canonical, domain-separated receipt message that
//! the `BobClaim` kernel feature must validate.

use crate::core::hash::{Hash, Hashed};
use crate::core::transaction::{
    Input, KernelFeatures, Output, OutputFeatures, OutputIdentifier, Transaction, TxKernel,
};
use crate::global::ChainTypes;
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

/// Domain separation for Alice's independent receipt-spend authorization.
const SPEND_AUTHORIZATION_DOMAIN: &[u8] = b"receipt-spend-authorization|";

/// Version of the Alice receipt-spend authorization message.
const SPEND_AUTHORIZATION_VERSION: u8 = 1;

/// The network identifier bound into an Alice receipt-spend authorization.
///
/// The identifier is part of the signed message, so an authorization created
/// for one network is cryptographically invalid on any other network.
/// Non-empty identifiers of at most 64 bytes are accepted so that future
/// chains can define their own identifiers without a protocol change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptChainId {
    bytes: Vec<u8>,
}

impl ReceiptChainId {
    /// Builds an identifier from raw network bytes.
    ///
    /// Empty identifiers and identifiers longer than 64 bytes are rejected so
    /// that the length-prefixed encoding is unambiguous and bounded.
    pub fn new(bytes: &[u8]) -> Result<Self, ser::Error> {
        if bytes.is_empty() || bytes.len() > 64 {
            return Err(ser::Error::CorruptedData);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Stable per-network identifiers for the supported [`ChainTypes`].
    pub fn from_chain_type(chain_type: &ChainTypes) -> Self {
        match chain_type {
            ChainTypes::AutomatedTesting => Self::automated_testing(),
            ChainTypes::UserTesting => Self::usernet(),
            ChainTypes::Floonet => Self::floonet(),
            ChainTypes::Mainnet => Self::mainnet(),
        }
    }

    /// Raw identifier bytes, as bound into the signed message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Experimental Usernet identifier.
    pub fn usernet() -> Self {
        Self {
            bytes: b"epic-usernet".to_vec(),
        }
    }
    /// Floonet identifier.
    pub fn floonet() -> Self {
        Self {
            bytes: b"epic-floonet".to_vec(),
        }
    }
    /// Mainnet identifier.
    pub fn mainnet() -> Self {
        Self {
            bytes: b"epic-mainnet".to_vec(),
        }
    }
    /// Automated testing identifier.
    pub fn automated_testing() -> Self {
        Self {
            bytes: b"epic-automated-testing".to_vec(),
        }
    }
}

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
            receipt_spend_authorization: None,
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

/// Builds Alice's independent spend of a shared receipt output.
///
/// The transaction is a regular one-input, one-output `Plain` spend: the input
/// is the receipt output, the kernel is an ordinary `Plain` kernel, and the
/// input carries a [`ReceiptSpendAuthorization`] signed with Alice's
/// per-payment secret `a_i`.
///
/// The transaction passes consensus validation: `verify_receipt_resolution`
/// accepts the Alice branch (authorization present, no matching BobClaim
/// kernel), and `verify_receipt_spend_authorizations` cryptographically
/// verifies the authorization against the kernel.
pub fn build_alice_spend_transaction(
    receipt_output: &Output,
    receipt_value: u64,
    shared_blind: &SecretKey,
    alice: &AliceReceiptAuthorizationKey,
    destination_blind: &SecretKey,
    fee: u64,
    chain_id: ReceiptChainId,
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

    // The caller must supply the real receipt value and shared blind: the
    // expected commitment and rewindable range proof pin them.
    let expected_input = secp
        .commit(receipt_value, shared_blind.clone())
        .map_err(|_| ser::Error::CorruptedData)?;
    if expected_input != receipt_output.commit {
        return Err(ser::Error::CorruptedData);
    }
    if !rewind_shared_receipt_output(receipt_output, shared_blind, secp)? == receipt_value {
        return Err(ser::Error::CorruptedData);
    }

    // The authorization must be keyed to the receipt output's committed Alice
    // key; a different `A_i` does not bind to this receipt.
    if !hashes.matches_alice(alice.public_key()) {
        return Err(ser::Error::CorruptedData);
    }

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
        .blind_sum(vec![destination_blind.clone()], vec![shared_blind.clone()])
        .map_err(|_| ser::Error::CorruptedData)?;
    let features = KernelFeatures::Plain { fee };
    let excess = secp
        .commit(0, kernel_secret.clone())
        .map_err(|_| ser::Error::CorruptedData)?;
    let excess_public_key = excess
        .to_pubkey(secp)
        .map_err(|_| ser::Error::CorruptedData)?;
    let excess_sig = secp::aggsig::sign_single(
        secp,
        &features
            .kernel_sig_msg()
            .map_err(|_| ser::Error::CorruptedData)?,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .map_err(|_| ser::Error::CorruptedData)?;

    // The authorization binds the *final* kernel: excess, fee, and the kernel
    // hash that includes the excess signature.
    let kernel = TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: None,
    };
    let authorization = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_output.commit,
        excess,
        fee,
        kernel.hash(),
        chain_id,
        alice.secret_key(),
    )?;

    Ok(Transaction::new(
        vec![Input {
            features: OutputFeatures::Receipt,
            commit: receipt_output.commit,
            receipt_key_hashes: Some(hashes),
            receipt_stealth_hint: Some(hint),
            receipt_spend_authorization: Some(authorization),
        }],
        vec![Output {
            features: OutputFeatures::Plain,
            commit: destination_commit,
            proof: destination_proof,
            receipt_key_hashes: None,
            receipt_stealth_hint: None,
        }],
        vec![kernel],
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

/// A fresh, per-payment authorization key owned exclusively by Alice.
///
/// The secret half is never serialized into a receipt output or any other
/// public structure. `A_i = a_i G` is committed as `hashes.alice` in the
/// receipt output; `a_i` remains private to Alice.
#[derive(Clone)]
pub struct AliceReceiptAuthorizationKey {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl AliceReceiptAuthorizationKey {
    /// Generates a fresh random authorization key for one payment.
    pub fn generate(secp: &secp::Secp256k1) -> Result<Self, ser::Error> {
        let secret_key = SecretKey::new(secp, &mut rand::rng());
        Self::from_secret_key(secret_key, secp)
    }

    /// Reconstructs the keypair from an existing secret.
    ///
    /// This is intentionally separate from [`Self::generate`]; callers must
    /// not derive `a_i` from the shared ECDH secret, Bob's descriptor, or any
    /// other value known to Bob.
    pub fn from_secret_key(
        secret_key: SecretKey,
        secp: &secp::Secp256k1,
    ) -> Result<Self, ser::Error> {
        let public_key = PublicKey::from_secret_key(secp, &secret_key)
            .map_err(|_| ser::Error::CorruptedData)?;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Alice's private authorization scalar `a_i`.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Alice's public authorization key `A_i`.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Public commitment material binding the shared receipt output to Bob's
/// one-time receipt key hash and Alice's independent authorization key hash.
/// The raw keys remain absent until the corresponding spend reveals them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SharedReceiptKeyHashes {
    pub bob: [u8; 32],
    pub alice: [u8; 32],
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
    /// Constructs both role-separated receipt key hashes.
    #[must_use]
    pub fn from_public_keys(
        bob_receipt_key: &PublicKey,
        alice_authorization_key: &PublicKey,
    ) -> Self {
        let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
        Self {
            bob: receipt_key_hash(bob_receipt_key, &secp),
            alice: alice_receipt_key_hash(alice_authorization_key, &secp),
        }
    }

    /// Returns whether `key` is the registered Bob receipt key.
    /// The public key itself is revealed only in the resolution kernel.
    #[must_use]
    pub fn matches_bob(&self, key: &PublicKey) -> bool {
        let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
        self.bob == receipt_key_hash(key, &secp)
    }

    /// Returns whether `key` is the registered Alice authorization key.
    #[must_use]
    pub fn matches_alice(&self, key: &PublicKey) -> bool {
        let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
        self.alice == alice_receipt_key_hash(key, &secp)
    }
}

impl Writeable for SharedReceiptKeyHashes {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        writer.write_fixed_bytes(&self.bob)?;
        writer.write_fixed_bytes(&self.alice)
    }
}

impl Readable for SharedReceiptKeyHashes {
    fn read(reader: &mut dyn Reader) -> Result<Self, ser::Error> {
        let bob = reader.read_fixed_bytes(32)?;
        let alice = reader.read_fixed_bytes(32)?;
        Ok(Self {
            bob: bob.try_into().map_err(|_| ser::Error::CorruptedData)?,
            alice: alice.try_into().map_err(|_| ser::Error::CorruptedData)?,
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

fn alice_receipt_key_hash(key: &PublicKey, secp: &secp::Secp256k1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"receipt-key|alice|");
    hash.update(key.serialize_vec(secp, true).as_slice());
    hash.finalize().into()
}

/// The permitted resolution paths for a shared receipt output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReceiptPath {
    /// Bob's existing claim path, backed by a `ReceiptClaim` signed by `b_i`.
    BobClaim,
    /// Alice's independent spend path, backed by an input-level
    /// `ReceiptSpendAuthorization` signed by `a_i`.
    AliceSpend,
}

impl ReceiptPath {
    fn tag(self) -> u8 {
        match self {
            Self::BobClaim => 0,
            Self::AliceSpend => 1,
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
            0 => Ok(Self::BobClaim),
            1 => Ok(Self::AliceSpend),
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

/// Alice's independent authorization to spend a shared receipt output with an
/// ordinary `Plain` kernel.
///
/// This is the cryptographic foundation only. It is deliberately not yet
/// carried by [`Input`] and is not yet enforced by transaction consensus.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ReceiptSpendAuthorization {
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
    pub kernel_hash: Hash,
    #[serde(with = "secp_ser::pubkey_serde")]
    pub alice_public_key: PublicKey,
    #[serde(with = "secp_ser::sig_serde")]
    pub alice_signature: Signature,
}

impl ReceiptSpendAuthorization {
    /// Version of the signed authorization message.
    pub const VERSION: u8 = SPEND_AUTHORIZATION_VERSION;

    /// Builds the canonical signed message for the active version and an
    /// explicit chain identifier.
    ///
    /// Only [`ReceiptPath::AliceSpend`] authorizations exist: this type signs
    /// an independent spend of a receipt output, never Bob's claim path.
    pub fn message(
        path: ReceiptPath,
        original_commitment: Commitment,
        kernel_excess: Commitment,
        fee: u64,
        kernel_hash: Hash,
        chain_id: ReceiptChainId,
        alice_public_key: &PublicKey,
    ) -> Result<secp::Message, ser::Error> {
        if path != ReceiptPath::AliceSpend {
            return Err(ser::Error::CorruptedData);
        }
        Self::message_with(
            Self::VERSION,
            chain_id,
            path,
            original_commitment,
            kernel_excess,
            fee,
            kernel_hash,
            alice_public_key,
        )
    }

    /// Builds a message with explicit version, chain identifier, and path.
    ///
    /// `sign` and `verify` always use [`Self::VERSION`] and enforce
    /// [`ReceiptPath::AliceSpend`]. This parameterized form exists so tests
    /// can prove that a signature over a different version, chain identifier,
    /// or path is rejected.
    pub fn message_with(
        version: u8,
        chain_id: ReceiptChainId,
        path: ReceiptPath,
        original_commitment: Commitment,
        kernel_excess: Commitment,
        fee: u64,
        kernel_hash: Hash,
        alice_public_key: &PublicKey,
    ) -> Result<secp::Message, ser::Error> {
        let public_key_bytes = {
            let secp = secp::Secp256k1::with_caps(secp::ContextFlag::None);
            alice_public_key.serialize_vec(&secp, true)
        };

        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(SPEND_AUTHORIZATION_DOMAIN);
        hash.update([version]);
        // Length-prefix the chain identifier so concatenation is unambiguous.
        hash.update((chain_id.bytes.len() as u64).to_le_bytes());
        hash.update(chain_id.bytes.as_slice());
        hash.update([path.tag()]);
        hash.update(original_commitment.as_ref());
        hash.update(kernel_excess.as_ref());
        hash.update(fee.to_le_bytes());
        hash.update(kernel_hash.as_bytes());
        hash.update(public_key_bytes);
        secp::Message::from_slice(&hash.finalize()).map_err(|_| ser::Error::CorruptedData)
    }

    /// Signs an Alice authorization with the per-payment secret `a_i`.
    ///
    /// Only [`ReceiptPath::AliceSpend`] can be signed; this type is not a
    /// stand-in for the `BobClaim` receipt claim.
    pub fn sign(
        path: ReceiptPath,
        original_commitment: Commitment,
        kernel_excess: Commitment,
        fee: u64,
        kernel_hash: Hash,
        chain_id: ReceiptChainId,
        alice_secret_key: &SecretKey,
    ) -> Result<Self, ser::Error> {
        if path != ReceiptPath::AliceSpend {
            return Err(ser::Error::CorruptedData);
        }
        let alice_public_key = {
            let secp = static_secp_instance();
            let secp = secp.lock();
            PublicKey::from_secret_key(&secp, alice_secret_key)
                .map_err(|_| ser::Error::CorruptedData)?
        };
        let message = Self::message(
            path,
            original_commitment,
            kernel_excess,
            fee,
            kernel_hash,
            chain_id,
            &alice_public_key,
        )?;

        let secp = static_secp_instance();
        let secp = secp.lock();
        let alice_signature = secp::aggsig::sign_single(
            &secp,
            &message,
            alice_secret_key,
            None,
            None,
            None,
            Some(&alice_public_key),
            None,
        )
        .map_err(|_| ser::Error::CorruptedData)?;

        Ok(Self {
            path,
            original_commitment,
            kernel_excess,
            fee,
            kernel_hash,
            alice_public_key,
            alice_signature,
        })
    }

    /// Verifies the signature and all message-bound fields for the given chain.
    ///
    /// Only [`ReceiptPath::AliceSpend`] verifies; an authorization carrying any
    /// other path is invalid, even if its signature is otherwise well-formed.
    #[must_use]
    pub fn verify(&self, chain_id: ReceiptChainId) -> bool {
        if self.path != ReceiptPath::AliceSpend {
            return false;
        }
        let Ok(message) = Self::message(
            self.path,
            self.original_commitment,
            self.kernel_excess,
            self.fee,
            self.kernel_hash,
            chain_id,
            &self.alice_public_key,
        ) else {
            return false;
        };

        let secp = static_secp_instance();
        let secp = secp.lock();
        secp::aggsig::verify_single(
            &secp,
            &self.alice_signature,
            &message,
            None,
            &self.alice_public_key,
            Some(&self.alice_public_key),
            None,
            false,
        )
    }

    /// Verifies both the signature and the receipt-output key commitment for
    /// the given chain.
    ///
    /// A valid signature under an unrelated public key is not sufficient:
    /// `A_i` must hash to the `alice` field committed by the receipt output.
    #[must_use]
    pub fn verify_with_hashes(
        &self,
        hashes: &SharedReceiptKeyHashes,
        chain_id: ReceiptChainId,
    ) -> bool {
        hashes.matches_alice(&self.alice_public_key) && self.verify(chain_id)
    }

    /// Verifies this authorization against the specific receipt input and
    /// kernel it is carried by, for the given chain.
    ///
    /// This is the input-level binding used by a future consensus rule: the
    /// signed message covers the input's original commitment, the kernel
    /// excess, fee, and the final kernel hash, and `A_i` matches the `alice`
    /// hash committed in the receipt output.
    #[must_use]
    pub fn verify_for_receipt_input(
        &self,
        input: &Input,
        kernel: &TxKernel,
        chain_id: ReceiptChainId,
    ) -> bool {
        if !input.features.is_receipt() || !kernel.features.is_plain() {
            return false;
        }
        let key_hash_match = match input.receipt_key_hashes {
            Some(h) => self.verify_with_hashes(&h, chain_id),
            None => false,
        };
        key_hash_match
            && self.original_commitment == input.commit
            && self.kernel_excess == kernel.excess
            && self.fee == kernel.features.fee()
            && self.kernel_hash == kernel.hash()
    }
}

impl Writeable for ReceiptSpendAuthorization {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        self.path.write(writer)?;
        self.original_commitment.write(writer)?;
        self.kernel_excess.write(writer)?;
        writer.write_u64(self.fee)?;
        self.kernel_hash.write(writer)?;
        self.alice_public_key.write(writer)?;
        self.alice_signature.write(writer)
    }
}

impl Readable for ReceiptSpendAuthorization {
    fn read(reader: &mut dyn Reader) -> Result<Self, ser::Error> {
        Ok(Self {
            path: ReceiptPath::read(reader)?,
            original_commitment: Commitment::read(reader)?,
            kernel_excess: Commitment::read(reader)?,
            fee: reader.read_u64()?,
            kernel_hash: Hash::read(reader)?,
            alice_public_key: PublicKey::read(reader)?,
            alice_signature: Signature::read(reader)?,
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
    fn receipt_claim_is_bound_to_original_and_kernel() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let receipt_key = key();
        let original = secp.commit(10, key()).unwrap();
        let kernel = secp.commit(0, key()).unwrap();
        let proof =
            ReceiptClaim::sign(ReceiptPath::BobClaim, original, kernel, 2, &receipt_key).unwrap();
        assert!(proof.verify());
        assert!(!ReceiptClaim { fee: 3, ..proof }.verify());
    }

    #[test]
    fn receipt_claim_binary_roundtrip_preserves_the_proof() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let proof = ReceiptClaim::sign(
            ReceiptPath::BobClaim,
            secp.commit(10, key()).unwrap(),
            secp.commit(0, key()).unwrap(),
            2,
            &key(),
        )
        .unwrap();
        let bytes = ser::ser_vec(&proof, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        let decoded: ReceiptClaim = ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert!(decoded.verify());
        assert_eq!(decoded.path, ReceiptPath::BobClaim);
    }

    #[test]
    fn shared_receipt_key_hashes_binary_roundtrip() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let bob = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let alice = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&bob, &alice);
        let bytes = ser::ser_vec(&hashes, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        let decoded: SharedReceiptKeyHashes = ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, hashes);
    }

    #[test]
    fn shared_receipt_key_hashes_match_only_the_correct_key() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let bob = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let alice = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let other = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&bob, &alice);
        assert!(hashes.matches_bob(&bob));
        assert!(!hashes.matches_bob(&other));
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
        let alice_authorization_key = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(
            &bob_receipt_public_key,
            alice_authorization_key.public_key(),
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

#[cfg(test)]
mod step3a_tests {
    use super::*;
    use crate::core::hash::Hash;
    use crate::util::secp::{ContextFlag, Secp256k1};

    fn key() -> SecretKey {
        SecretKey::new(&Secp256k1::with_caps(ContextFlag::Commit), &mut rand::rng())
    }

    fn commitment(secp: &Secp256k1, value: u64) -> Commitment {
        secp.commit(value, key()).unwrap()
    }

    fn kernel_hash(byte: u8) -> Hash {
        Hash::from_vec(&[byte; 32])
    }

    struct AuthFixture {
        alice: AliceReceiptAuthorizationKey,
        original: Commitment,
        excess: Commitment,
        fee: u64,
        kernel_hash: Hash,
        auth: ReceiptSpendAuthorization,
    }

    fn auth_fixture(secp: &Secp256k1) -> AuthFixture {
        let alice = AliceReceiptAuthorizationKey::generate(secp).unwrap();
        let original = commitment(secp, 10);
        let excess = commitment(secp, 0);
        let fee = 2;
        let kernel_hash = kernel_hash(7);
        let auth = ReceiptSpendAuthorization::sign(
            ReceiptPath::AliceSpend,
            original,
            excess,
            fee,
            kernel_hash,
            ReceiptChainId::usernet(),
            alice.secret_key(),
        )
        .unwrap();
        AuthFixture {
            alice,
            original,
            excess,
            fee,
            kernel_hash,
            auth,
        }
    }

    // --- Key separation -------------------------------------------------

    #[test]
    fn alice_authorization_key_is_a_valid_independent_keypair() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let alice = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        assert_eq!(
            *alice.public_key(),
            PublicKey::from_secret_key(&secp, alice.secret_key()).unwrap()
        );

        let other = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        assert_ne!(alice.secret_key(), other.secret_key());
        assert_ne!(alice.public_key(), other.public_key());
    }

    #[test]
    fn three_payments_generate_distinct_alice_authorization_keys() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let keys: Vec<_> = (0..3)
            .map(|_| AliceReceiptAuthorizationKey::generate(&secp).unwrap())
            .collect();
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].secret_key(), keys[j].secret_key());
                assert_ne!(keys[i].public_key(), keys[j].public_key());
            }
        }
    }

    #[test]
    fn alice_authorization_key_is_not_the_shared_blind_or_bob_receipt_key() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let bob_secrets = StealthReceiptSecrets::new(key(), key());
        let descriptor = bob_secrets.descriptor(&secp).unwrap();
        let alice_ephemeral = key();
        let (hint, _) = descriptor
            .derive_for_sender(&alice_ephemeral, &secp)
            .unwrap();

        let alice_blind = descriptor
            .derive_shared_spend_blind_for_sender(&alice_ephemeral, &secp)
            .unwrap();
        let bob_blind = bob_secrets
            .derive_shared_spend_blind(&descriptor, &hint, &secp)
            .unwrap();
        let bob_receipt_key = bob_secrets
            .derive_receipt_key(&descriptor, &hint, &secp)
            .unwrap();

        assert_eq!(alice_blind, bob_blind);

        let alice = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        assert_ne!(alice.secret_key(), &alice_blind);
        assert_ne!(alice.secret_key(), &bob_receipt_key);
        assert_ne!(
            alice.public_key(),
            &PublicKey::from_secret_key(&secp, &alice_blind).unwrap()
        );
        assert_ne!(
            alice.public_key(),
            &PublicKey::from_secret_key(&secp, &bob_receipt_key).unwrap()
        );
    }

    // --- Hash binding ---------------------------------------------------

    #[test]
    fn shared_receipt_key_hashes_bind_both_roles() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let bob = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let alice = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&bob, &alice);

        assert!(hashes.matches_bob(&bob));
        assert!(hashes.matches_alice(&alice));
        assert!(!hashes.matches_bob(&alice));
        assert!(!hashes.matches_alice(&bob));
        assert_ne!(hashes.bob, hashes.alice);
    }

    #[test]
    fn alice_and_bob_hash_domains_are_distinct() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let key = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&key, &key);
        assert_ne!(hashes.bob, hashes.alice);
    }

    #[test]
    fn authorization_public_key_must_match_the_receipt_hash() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let bob = PublicKey::from_secret_key(&secp, &key()).unwrap();

        let matching =
            SharedReceiptKeyHashes::from_public_keys(&bob, &fixture.auth.alice_public_key);
        assert!(fixture.auth.verify_with_hashes(&matching, ReceiptChainId::usernet()));

        let unrelated = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        let mismatching = SharedReceiptKeyHashes::from_public_keys(&bob, unrelated.public_key());
        assert!(!fixture.auth.verify_with_hashes(&mismatching, ReceiptChainId::usernet()));
    }

    // --- Signature verification ----------------------------------------

    #[test]
    fn valid_alice_authorization_verifies() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        assert_eq!(fixture.auth.path, ReceiptPath::AliceSpend);
        assert!(fixture.auth.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_signature_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let other = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        let other_auth = ReceiptSpendAuthorization::sign(
            ReceiptPath::AliceSpend,
            fixture.original,
            fixture.excess,
            fixture.fee,
            fixture.kernel_hash,
            ReceiptChainId::usernet(),
            other.secret_key(),
        )
        .unwrap();

        let mut forged = fixture.auth.clone();
        forged.alice_signature = other_auth.alice_signature;
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_public_key_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let other = AliceReceiptAuthorizationKey::generate(&secp).unwrap();

        let mut forged = fixture.auth.clone();
        forged.alice_public_key = other.public_key().clone();
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_commitment_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let mut forged = fixture.auth.clone();
        forged.original_commitment = commitment(&secp, 11);
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_excess_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let mut forged = fixture.auth.clone();
        forged.kernel_excess = commitment(&secp, 1);
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_fee_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let mut forged = fixture.auth.clone();
        forged.fee = fixture.fee + 1;
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_kernel_hash_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let mut forged = fixture.auth.clone();
        forged.kernel_hash = kernel_hash(8);
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_path_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let mut forged = fixture.auth.clone();
        forged.path = ReceiptPath::BobClaim;
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_version_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let message = ReceiptSpendAuthorization::message_with(
            2,
            ReceiptChainId::usernet(),
            ReceiptPath::AliceSpend,
            fixture.original,
            fixture.excess,
            fixture.fee,
            fixture.kernel_hash,
            fixture.alice.public_key(),
        )
        .unwrap();
        let signature = secp::aggsig::sign_single(
            &secp,
            &message,
            fixture.alice.secret_key(),
            None,
            None,
            None,
            Some(fixture.alice.public_key()),
            None,
        )
        .unwrap();

        let mut forged = fixture.auth.clone();
        forged.alice_signature = signature;
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    #[test]
    fn wrong_chain_identifier_fails() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let message = ReceiptSpendAuthorization::message_with(
            ReceiptSpendAuthorization::VERSION,
            ReceiptChainId::mainnet(),
            ReceiptPath::AliceSpend,
            fixture.original,
            fixture.excess,
            fixture.fee,
            fixture.kernel_hash,
            fixture.alice.public_key(),
        )
        .unwrap();
        let signature = secp::aggsig::sign_single(
            &secp,
            &message,
            fixture.alice.secret_key(),
            None,
            None,
            None,
            Some(fixture.alice.public_key()),
            None,
        )
        .unwrap();

        let mut forged = fixture.auth.clone();
        forged.alice_signature = signature;
        assert!(!forged.verify(ReceiptChainId::usernet()));
    }

    // --- Serialization --------------------------------------------------

    #[test]
    fn shared_receipt_key_hashes_roundtrip() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let bob = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let alice = PublicKey::from_secret_key(&secp, &key()).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&bob, &alice);
        let bytes = ser::ser_vec(&hashes, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        assert_eq!(bytes.len(), 64);
        let decoded: SharedReceiptKeyHashes = ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, hashes);
    }

    #[test]
    fn alice_spend_path_roundtrips() {
        let bytes = ser::ser_vec(
            &ReceiptPath::AliceSpend,
            ser::ProtocolVersion(ser::ProtocolVersion::MAX),
        )
        .unwrap();
        let decoded: ReceiptPath = ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, ReceiptPath::AliceSpend);
    }

    #[test]
    fn unknown_receipt_path_tag_is_rejected() {
        let bytes = [2u8];
        let mut source = &bytes[..];
        let mut reader = ser::BinReader::new(
            &mut source,
            ser::ProtocolVersion(ser::ProtocolVersion::MAX),
        );
        assert!(ReceiptPath::read(&mut reader).is_err());
    }

    #[test]
    fn receipt_spend_authorization_roundtrips() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let bytes = ser::ser_vec(
            &fixture.auth,
            ser::ProtocolVersion(ser::ProtocolVersion::MAX),
        )
        .unwrap();
        let decoded: ReceiptSpendAuthorization =
            ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert_eq!(decoded.path, ReceiptPath::AliceSpend);
        assert!(decoded.verify(ReceiptChainId::usernet()));
        assert_eq!(decoded.alice_public_key, fixture.auth.alice_public_key);
    }

    #[test]
    fn malformed_public_key_is_rejected() {
        let invalid = [0xffu8; 33];
        let mut source = &invalid[..];
        let mut reader = ser::BinReader::new(
            &mut source,
            ser::ProtocolVersion(ser::ProtocolVersion::MAX),
        );
        assert!(PublicKey::read(&mut reader).is_err());
    }

    #[test]
    fn malformed_signature_does_not_verify() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let fixture = auth_fixture(&secp);
        let invalid = [0xffu8; 64];
        let mut source = &invalid[..];
        let mut reader = ser::BinReader::new(
            &mut source,
            ser::ProtocolVersion(ser::ProtocolVersion::MAX),
        );
        if let Ok(signature) = Signature::read(&mut reader) {
            let mut forged = fixture.auth.clone();
            forged.alice_signature = signature;
            assert!(!forged.verify(ReceiptChainId::usernet()));
        }
    }
}

#[cfg(test)]
mod step3b_tests {
    use super::*;
    use crate::core::hash::Hashed;
    use crate::core::transaction::{Error as TxError, Weighting};
    use crate::core::Committed;
    use crate::global::ChainTypes;
    use crate::util::secp::{ContextFlag, Secp256k1};

    fn key(secp: &Secp256k1) -> SecretKey {
        SecretKey::new(secp, &mut rand::rng())
    }

    fn alice_auth_fixture(
        secp: &Secp256k1,
    ) -> (AliceReceiptAuthorizationKey, ReceiptSpendAuthorization) {
        let alice = AliceReceiptAuthorizationKey::generate(secp).unwrap();
        let original = secp.commit(10, key(secp)).unwrap();
        let excess = secp.commit(0, key(secp)).unwrap();
        let auth = ReceiptSpendAuthorization::sign(
            ReceiptPath::AliceSpend,
            original,
            excess,
            2,
            Hash::from_vec(&[7; 32]),
            ReceiptChainId::usernet(),
            alice.secret_key(),
        )
        .unwrap();
        (alice, auth)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_over_path(
        secp: &Secp256k1,
        alice: &AliceReceiptAuthorizationKey,
        path: ReceiptPath,
        original: Commitment,
        excess: Commitment,
        fee: u64,
        kernel_hash: Hash,
        chain_id: ReceiptChainId,
    ) -> Signature {
        let message = ReceiptSpendAuthorization::message_with(
            ReceiptSpendAuthorization::VERSION,
            chain_id,
            path,
            original,
            excess,
            fee,
            kernel_hash,
            alice.public_key(),
        )
        .unwrap();
        secp::aggsig::sign_single(
            secp,
            &message,
            alice.secret_key(),
            None,
            None,
            None,
            Some(alice.public_key()),
            None,
        )
        .unwrap()
    }

    // --- Issue A: Alice path validation ---------------------------------

    #[test]
    fn valid_alice_authorization_is_accepted() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let (alice, auth) = alice_auth_fixture(&secp);
        let hashes = SharedReceiptKeyHashes::from_public_keys(
            &PublicKey::from_secret_key(&secp, &key(&secp)).unwrap(),
            alice.public_key(),
        );
        assert_eq!(auth.path, ReceiptPath::AliceSpend);
        assert!(auth.verify(ReceiptChainId::usernet()));
        assert!(auth.verify_with_hashes(&hashes, ReceiptChainId::usernet()));
    }

    #[test]
    fn valid_signature_over_bob_claim_path_is_rejected() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let (alice, auth) = alice_auth_fixture(&secp);
        let signature = sign_over_path(
            &secp,
            &alice,
            ReceiptPath::BobClaim,
            auth.original_commitment,
            auth.kernel_excess,
            auth.fee,
            auth.kernel_hash,
            ReceiptChainId::usernet(),
        );
        let hashes = SharedReceiptKeyHashes::from_public_keys(
            &PublicKey::from_secret_key(&secp, &key(&secp)).unwrap(),
            alice.public_key(),
        );

        let mut bob_path = auth;
        bob_path.path = ReceiptPath::BobClaim;
        bob_path.alice_signature = signature;
        assert!(!bob_path.verify(ReceiptChainId::usernet()));
        assert!(!bob_path.verify_with_hashes(&hashes, ReceiptChainId::usernet()));
    }

    #[test]
    fn sign_rejects_non_alice_path() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let alice = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        let result = ReceiptSpendAuthorization::sign(
            ReceiptPath::BobClaim,
            secp.commit(10, key(&secp)).unwrap(),
            secp.commit(0, key(&secp)).unwrap(),
            2,
            Hash::from_vec(&[7; 32]),
            ReceiptChainId::usernet(),
            alice.secret_key(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn message_rejects_non_alice_path() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let alice = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        let result = ReceiptSpendAuthorization::message(
            ReceiptPath::BobClaim,
            secp.commit(10, key(&secp)).unwrap(),
            secp.commit(0, key(&secp)).unwrap(),
            2,
            Hash::from_vec(&[7; 32]),
            ReceiptChainId::usernet(),
            alice.public_key(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn tampered_serialized_path_tag_is_rejected() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let (_, auth) = alice_auth_fixture(&secp);
        let bytes = ser::ser_vec(&auth, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();

        let mut bob_path_bytes = bytes.clone();
        bob_path_bytes[0] = 0;
        let decoded: ReceiptSpendAuthorization =
            ser::deserialize_default(&mut &bob_path_bytes[..]).unwrap();
        assert_eq!(decoded.path, ReceiptPath::BobClaim);
        assert!(!decoded.verify(ReceiptChainId::usernet()));

        let mut unknown_path_bytes = bytes;
        unknown_path_bytes[0] = 2;
        let result: Result<ReceiptSpendAuthorization, _> =
            ser::deserialize_default(&mut &unknown_path_bytes[..]);
        assert!(result.is_err());
    }

    // --- Issue B: explicit chain identifier -----------------------------

    #[test]
    fn chain_id_binding_rejects_a_different_chain() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let (_, auth) = alice_auth_fixture(&secp);
        assert!(auth.verify(ReceiptChainId::usernet()));
        assert!(!auth.verify(ReceiptChainId::floonet()));
        assert!(!auth.verify(ReceiptChainId::mainnet()));
        assert!(!auth.verify(ReceiptChainId::automated_testing()));
    }

    #[test]
    fn chain_id_survives_serialization() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let (_, auth) = alice_auth_fixture(&secp);
        let bytes = ser::ser_vec(&auth, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        let decoded: ReceiptSpendAuthorization =
            ser::deserialize_default(&mut &bytes[..]).unwrap();
        assert!(decoded.verify(ReceiptChainId::usernet()));
        assert!(!decoded.verify(ReceiptChainId::floonet()));
    }

    #[test]
    fn invalid_custom_chain_ids_are_rejected() {
        assert!(ReceiptChainId::new(b"").is_err());
        assert!(ReceiptChainId::new(&[0u8; 65]).is_err());
        assert!(ReceiptChainId::new(b"epic-usernet").is_ok());
    }

    #[test]
    fn chain_types_map_to_stable_ids() {
        assert_eq!(
            ReceiptChainId::from_chain_type(&ChainTypes::AutomatedTesting),
            ReceiptChainId::automated_testing()
        );
        assert_eq!(
            ReceiptChainId::from_chain_type(&ChainTypes::UserTesting),
            ReceiptChainId::usernet()
        );
        assert_eq!(
            ReceiptChainId::from_chain_type(&ChainTypes::Floonet),
            ReceiptChainId::floonet()
        );
        assert_eq!(
            ReceiptChainId::from_chain_type(&ChainTypes::Mainnet),
            ReceiptChainId::mainnet()
        );
    }

    // --- Alice spend builder --------------------------------------------

    struct SpendFixture {
        secp: Secp256k1,
        receipt: Output,
        receipt_value: u64,
        shared_blind: SecretKey,
        alice: AliceReceiptAuthorizationKey,
        destination_blind: SecretKey,
        fee: u64,
    }

    fn spend_fixture() -> SpendFixture {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let bob_secrets = StealthReceiptSecrets::new(key(&secp), key(&secp));
        let descriptor = bob_secrets.descriptor(&secp).unwrap();
        let alice_ephemeral = key(&secp);
        let (hint, bob_receipt_public_key) = descriptor
            .derive_for_sender(&alice_ephemeral, &secp)
            .unwrap();
        let alice = AliceReceiptAuthorizationKey::generate(&secp).unwrap();
        let hashes =
            SharedReceiptKeyHashes::from_public_keys(&bob_receipt_public_key, alice.public_key());
        let shared_blind = descriptor
            .derive_shared_spend_blind_for_sender(&alice_ephemeral, &secp)
            .unwrap();
        let receipt = build_shared_receipt_output(42, &shared_blind, hashes, hint, &secp).unwrap();
        let destination_blind = key(&secp);
        SpendFixture {
            secp,
            receipt,
            receipt_value: 42,
            shared_blind,
            alice,
            destination_blind,
            fee: 2,
        }
    }

    fn build_alice(fixture: &SpendFixture) -> Transaction {
        build_alice_spend_transaction(
            &fixture.receipt,
            fixture.receipt_value,
            &fixture.shared_blind,
            &fixture.alice,
            &fixture.destination_blind,
            fixture.fee,
            ReceiptChainId::usernet(),
            &fixture.secp,
        )
        .unwrap()
    }

    #[test]
    fn build_alice_spend_transaction_builds_a_valid_plain_spend() {
        let fixture = spend_fixture();
        let tx = build_alice(&fixture);

        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.outputs().len(), 1);
        assert_eq!(tx.kernels().len(), 1);

        let input = &tx.inputs()[0];
        assert_eq!(input.features, OutputFeatures::Receipt);
        assert_eq!(input.commit, fixture.receipt.commit);
        assert_eq!(input.receipt_key_hashes, fixture.receipt.receipt_key_hashes);
        assert_eq!(input.receipt_stealth_hint, fixture.receipt.receipt_stealth_hint);
        assert_eq!(
            OutputIdentifier::from_input(input),
            OutputIdentifier::from_output(&fixture.receipt)
        );
        let auth = input
            .receipt_spend_authorization
            .expect("authorization attached");
        assert_eq!(auth.path, ReceiptPath::AliceSpend);

        let output = &tx.outputs()[0];
        assert_eq!(output.features, OutputFeatures::Plain);
        let destination_value = fixture.receipt_value - fixture.fee;
        assert_eq!(
            output.commit,
            fixture
                .secp
                .commit(destination_value, fixture.destination_blind.clone())
                .unwrap()
        );
        assert!(output.receipt_key_hashes.is_none());
        assert!(output.receipt_stealth_hint.is_none());
        output.verify_proof().unwrap();

        let kernel = &tx.kernels()[0];
        assert_eq!(kernel.features, KernelFeatures::Plain { fee: fixture.fee });
        assert!(kernel.receipt_claim.is_none());
        let expected_secret = fixture
            .secp
            .blind_sum(
                vec![fixture.destination_blind.clone()],
                vec![fixture.shared_blind.clone()],
            )
            .unwrap();
        assert_eq!(
            kernel.excess,
            fixture.secp.commit(0, expected_secret).unwrap()
        );
        TxKernel::batch_sig_verify(tx.kernels()).unwrap();
        tx.verify_kernel_sums(tx.overage(), tx.offset.clone())
            .unwrap();

        assert_eq!(auth.original_commitment, fixture.receipt.commit);
        assert_eq!(auth.kernel_excess, kernel.excess);
        assert_eq!(auth.fee, fixture.fee);
        assert_eq!(auth.kernel_hash, kernel.hash());
        let hashes = input.receipt_key_hashes.unwrap();
        assert!(auth.verify_with_hashes(&hashes, ReceiptChainId::usernet()));
        assert!(auth.verify_for_receipt_input(input, kernel, ReceiptChainId::usernet()));
        assert!(!auth.verify_for_receipt_input(input, kernel, ReceiptChainId::floonet()));
    }

    #[test]
    fn alice_spend_authorization_binds_the_final_kernel() {
        let fixture = spend_fixture();
        let tx = build_alice(&fixture);
        let input = &tx.inputs()[0];
        let auth = input.receipt_spend_authorization.unwrap();

        let mut substituted = tx.kernels()[0].clone();
        substituted.features = KernelFeatures::Plain {
            fee: fixture.fee + 1,
        };
        assert_ne!(substituted.hash(), auth.kernel_hash);
        assert!(!auth.verify_for_receipt_input(input, &substituted, ReceiptChainId::usernet()));
    }

    #[test]
    fn alice_spend_builder_rejects_non_receipt_output() {
        let fixture = spend_fixture();
        let plain = Output {
            features: OutputFeatures::Plain,
            commit: fixture.receipt.commit,
            proof: fixture.receipt.proof,
            receipt_key_hashes: None,
            receipt_stealth_hint: None,
        };
        let result = build_alice_spend_transaction(
            &plain,
            fixture.receipt_value,
            &fixture.shared_blind,
            &fixture.alice,
            &fixture.destination_blind,
            fixture.fee,
            ReceiptChainId::usernet(),
            &fixture.secp,
        );
        assert!(result.is_err());
    }

    #[test]
    fn alice_spend_builder_rejects_wrong_value_or_blind() {
        let fixture = spend_fixture();
        let wrong_value = build_alice_spend_transaction(
            &fixture.receipt,
            fixture.receipt_value + 1,
            &fixture.shared_blind,
            &fixture.alice,
            &fixture.destination_blind,
            fixture.fee,
            ReceiptChainId::usernet(),
            &fixture.secp,
        );
        assert!(wrong_value.is_err());

        let wrong_blind = build_alice_spend_transaction(
            &fixture.receipt,
            fixture.receipt_value,
            &key(&fixture.secp),
            &fixture.alice,
            &fixture.destination_blind,
            fixture.fee,
            ReceiptChainId::usernet(),
            &fixture.secp,
        );
        assert!(wrong_blind.is_err());
    }

    #[test]
    fn alice_spend_builder_rejects_mismatched_alice_key() {
        let fixture = spend_fixture();
        let other = AliceReceiptAuthorizationKey::generate(&fixture.secp).unwrap();
        let result = build_alice_spend_transaction(
            &fixture.receipt,
            fixture.receipt_value,
            &fixture.shared_blind,
            &other,
            &fixture.destination_blind,
            fixture.fee,
            ReceiptChainId::usernet(),
            &fixture.secp,
        );
        assert!(result.is_err());
    }

    #[test]
    fn alice_spend_builder_does_not_serialize_alice_secret() {
        let fixture = spend_fixture();
        let tx = build_alice(&fixture);
        let bytes = ser::ser_vec(&tx, ser::ProtocolVersion(ser::ProtocolVersion::MAX)).unwrap();
        assert!(!bytes
            .windows(32)
            .any(|window| window == fixture.alice.secret_key().0));
    }

    // NOTE: the Step 3B test `alice_spend_is_rejected_only_by_the_disabled_consensus_rule`
    // has been removed. It asserted that the Alice `Plain` spend is rejected by the
    // old count rule in `verify_receipt_resolution()`. Step 3C replaces that rule
    // with the two-branch matching rule and wires `verify_receipt_spend_authorizations`
    // into `validate_read()`, so a correctly authorized Alice spend is now accepted.
    // The acceptance case is covered by `step3c_valid_alice_spend_passes_validate_read`
    // in `core/tests/transaction.rs` and by the chain-level E2E test
    // `step3c_alice_reclaim_via_plain_kernel_consensus_accepted` in
    // `chain/tests/spend_attribution.rs`.
}
