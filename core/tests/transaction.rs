// Copyright 2019 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transaction integration tests

pub mod common;

use self::core::core::{Input, Output, OutputFeatures, TxKernel};
use self::core::core::receipt_claim::{
    ReceiptChainId, ReceiptClaim, ReceiptPath, ReceiptSpendAuthorization, ReceiptStealthHint,
    SharedReceiptKeyHashes,
};
use self::core::core::hash::Hash;
use self::core::core::hash::Hashed;
use self::core::libtx::proof;
use self::core::ser;
use epic_core as core;
use keychain::{ExtKeychain, Keychain};
use util::secp;
use util::secp::pedersen::Commitment;
use util::static_secp_instance;
use core::global::{self, ChainTypes};

#[test]
fn test_output_ser_deser() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let switch = &keychain::SwitchCommitmentType::Regular;
	let commit = keychain.commit(5, &key_id, switch).unwrap();
	let builder = proof::ProofBuilder::new(&keychain);
	let proof = proof::create(&keychain, &builder, 5, &key_id, switch, commit, None).unwrap();

	let out = Output {
		features: OutputFeatures::Plain,
		commit: commit,
		proof: proof,
		receipt_key_hashes: None,
		receipt_stealth_hint: None,
	};

	let mut vec = vec![];
	ser::serialize_default(&mut vec, &out).expect("serialized failed");
	let dout: Output = ser::deserialize_default(&mut &vec[..]).unwrap();

	assert_eq!(dout.features, OutputFeatures::Plain);
	assert_eq!(dout.commit, out.commit);
	assert_eq!(dout.proof, out.proof);
}

/// Helper: build a minimal valid Receipt input for serialization tests.
fn receipt_input_with_authorization(
    auth: Option<ReceiptSpendAuthorization>,
) -> Input {
    let secp = secp::Secp256k1::new();
    let secret = secp::SecretKey::from_slice(&secp, &[7u8; 32]).unwrap();
    let pk = secp::PublicKey::from_secret_key(&secp, &secret).unwrap();
    let hint = ReceiptStealthHint::from_public_key(&pk, &secp);
    let hashes = SharedReceiptKeyHashes::from_public_keys(&pk, &pk);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
    let commit = keychain
        .commit(42, &key_id, &keychain::SwitchCommitmentType::Regular)
        .unwrap();
    Input {
        features: OutputFeatures::Receipt,
        commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: auth,
    }
}

/// Helper: build a minimal valid Plain (non-receipt) input.
fn plain_input() -> Input {
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
    let commit = keychain
        .commit(42, &key_id, &keychain::SwitchCommitmentType::Regular)
        .unwrap();
    Input {
        features: OutputFeatures::Plain,
        commit,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
        receipt_spend_authorization: None,
    }
}

/// A plain (non-receipt) input serializes without a presence byte: the
/// serialized bytes must be exactly the same as before the field was added.
#[test]
fn plain_input_serialization_is_unchanged() {
    let input = plain_input();
    let mut buf = vec![];
    ser::serialize_default(&mut buf, &input).expect("serialize");
    let expected_len = 1 /* features */ + 33 /* commit (compressed point) */;
    assert_eq!(
        buf.len(),
        expected_len,
        "plain input must not carry a presence byte, got {} bytes",
        buf.len()
    );
    let back: Input = ser::deserialize_default(&mut &buf[..]).unwrap();
    assert_eq!(back.features, input.features);
    assert_eq!(back.commit, input.commit);
    assert!(back.receipt_spend_authorization.is_none());
}

/// A receipt input without authorization serializes with a zero presence byte
/// and roundtrips to an equal input.
#[test]
fn receipt_input_without_authorization_roundtrips() {
    let input = receipt_input_with_authorization(None);
    let mut buf = vec![];
    ser::serialize_default(&mut buf, &input).expect("serialize");
    // Last byte must be the presence byte 0.
    assert_eq!(
        *buf.last().unwrap(),
        0,
        "receipt input without authorization must end with presence byte 0"
    );
    let back: Input = ser::deserialize_default(&mut &buf[..]).unwrap();
    assert_eq!(back.features, input.features);
    assert_eq!(back.commit, input.commit);
    assert_eq!(back.receipt_key_hashes, input.receipt_key_hashes);
    assert_eq!(back.receipt_stealth_hint, input.receipt_stealth_hint);
    assert!(back.receipt_spend_authorization.is_none());
}

/// A receipt input with Some(authorization) serializes with a one presence
/// byte followed by the authorization bytes and roundtrips to an equal input.
#[test]
fn receipt_input_with_authorization_roundtrips() {
    let secp = secp::Secp256k1::new();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[42u8; 32]).unwrap();
    let fee = 10u64;
    let kernel_hash = Hash::from_vec(&[7u8; 32]);
    let kernel_excess = Commitment::from_vec(vec![8u8; 33]);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
    let commit = keychain
        .commit(42, &key_id, &keychain::SwitchCommitmentType::Regular)
        .unwrap();

    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        commit,
        kernel_excess,
        fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign authorization");

    let input = receipt_input_with_authorization(Some(auth));
    let mut buf = vec![];
    ser::serialize_default(&mut buf, &input).expect("serialize");
    // Layout: features(1) + commit(33) + hashes(64) + hint(33) + presence(1) = 132
    // The presence byte is at index 131 (0-based).
    let presence_idx = 1 + 33 + 64 + 33; // index of the presence byte
    assert_eq!(
        buf[presence_idx],
        1,
        "receipt input with authorization must have presence byte 1"
    );
    let back: Input = ser::deserialize_default(&mut &buf[..]).unwrap();
    assert!(back.receipt_spend_authorization.is_some());
    let back_auth = back.receipt_spend_authorization.unwrap();
    assert_eq!(back_auth.path, auth.path);
    assert_eq!(back_auth.original_commitment, auth.original_commitment);
    assert_eq!(back_auth.kernel_excess, auth.kernel_excess);
    assert_eq!(back_auth.fee, auth.fee);
    assert_eq!(back_auth.kernel_hash, auth.kernel_hash);
    assert_eq!(back_auth.alice_public_key, auth.alice_public_key);
    assert_eq!(back_auth.alice_signature, auth.alice_signature);
}

/// A presence byte greater than 1 is rejected with CorruptedData.
#[test]
fn receipt_input_rejects_invalid_presence_byte() {
    let input = receipt_input_with_authorization(None);
    let mut buf = vec![];
    ser::serialize_default(&mut buf, &input).expect("serialize");
    // Corrupt the last byte (presence byte) to 2.
    *buf.last_mut().unwrap() = 2;
    let result: Result<Input, _> = ser::deserialize_default(&mut &buf[..]);
    assert!(
        matches!(result, Err(ser::Error::CorruptedData)),
        "presence byte 2 must be rejected as CorruptedData, got {:?}",
        result.map(|_| "Ok").map_err(|e| format!("{:?}", e))
    );
}

/// A receipt input whose presence byte is corrupt (value 2) is rejected with
/// CorruptedData, not silently treated as absent.
///
/// (Complements the valid 0/1 roundtrip tests above by pinning the rejection
/// of out-of-range presence values.)
#[test]
fn receipt_input_rejects_presence_byte_two() {
    let input = receipt_input_with_authorization(None);
    let mut buf = vec![];
    ser::serialize_default(&mut buf, &input).expect("serialize");
    *buf.last_mut().unwrap() = 2;
    let result: Result<Input, _> = ser::deserialize_default(&mut &buf[..]);
    assert!(
        matches!(result, Err(ser::Error::CorruptedData)),
        "presence byte 2 must be rejected as CorruptedData"
    );
}

// ─── Step 3C: two-branch verify_receipt_resolution ─────────────────────────────
//
// The two-branch rule requires that every receipt input be resolved by exactly
// one of:
//   • Alice path: input carries Some(auth) with auth.path == AliceSpend,
//     auth.original_commitment == input.commit, hashes.matches_alice,
//     and exactly one Plain kernel matching (excess, fee, kernel_hash).
//   • Bob path: input carries None authorization, and exactly one BobClaim
//     kernel with matching original_commitment and hashes.matches_bob.
//
// Mixed-branch assignment (Bob claim present AND auth present on the same
// input) must be rejected unconditionally.
//
// These tests call TransactionBody::validate_read via Transaction::validate
// with Weighting::AsTransaction. Kernel signatures are not verified in
// validate_read, so dummy signatures are acceptable for the structural rules
// being tested here.

/// Helper: build a minimal valid Plain kernel (no valid signature –
/// validate_read does not verify kernel signatures).
fn plain_kernel(secp: &secp::Secp256k1, excess: Commitment, fee: u64) -> core::core::TxKernel {
    let features = core::core::KernelFeatures::Plain { fee };
    let message = features.kernel_sig_msg().unwrap();
    let secret = secp::SecretKey::from_slice(secp, &[1u8; 32]).unwrap();
    let excess_public_key = excess.to_pubkey(secp).unwrap();
    let sig = secp::aggsig::sign_single(
        secp,
        &message,
        &secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();
    core::core::TxKernel {
        features,
        excess,
        excess_sig: sig,
        receipt_claim: None,
    }
}

/// Helper: build a minimal BobClaim kernel bound to the given original
/// commitment and receipt secret key.
fn bob_claim_kernel(
    secp: &secp::Secp256k1,
    original_commitment: Commitment,
    receipt_secret_key: &secp::SecretKey,
    excess: Commitment,
    fee: u64,
) -> core::core::TxKernel {
    let features = core::core::KernelFeatures::BobClaim { fee };
    let message = features.kernel_sig_msg().unwrap();
    let secret = secp::SecretKey::from_slice(secp, &[2u8; 32]).unwrap();
    let excess_public_key = excess.to_pubkey(secp).unwrap();
    let sig = secp::aggsig::sign_single(
        secp,
        &message,
        &secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();
    // ReceiptClaim::sign locks the static secp instance internally.
    let claim = core::core::ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        original_commitment,
        excess,
        fee,
        receipt_secret_key,
    )
    .unwrap();
    core::core::TxKernel {
        features,
        excess,
        excess_sig: sig,
        receipt_claim: Some(claim),
    }
}


/// A valid BobClaim transaction (one receipt input, one BobClaim kernel,
/// one Plain output) must pass validate_read.
#[test]
fn step3c_valid_bob_claim_passes_validate_read() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap())
        .unwrap();
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[2u8; 32]).unwrap())
        .unwrap();
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap();
    let bob_public = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[6u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_public, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_public, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[7u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let kernel = bob_claim_kernel(secp, receipt_commit, &bob_secret, kernel_excess, fee);

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    tx.body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect("valid BobClaim transaction must pass validate_read");
}

/// A valid Alice-spend transaction (one receipt input with Some(auth), one
/// Plain kernel, one Plain output) must pass validate_read when the
/// authorization matches the kernel.
#[test]
fn step3c_valid_alice_spend_passes_validate_read() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap())
        .unwrap();
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[2u8; 32]).unwrap())
        .unwrap();
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap();
    let bob_public = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[8u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_public, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_public, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[9u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .unwrap();

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    tx.body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect("valid Alice-spend transaction must pass validate_read");
}

/// A receipt input with Some(auth) that also has a matching BobClaim kernel
/// must be rejected (mixed-branch assignment).
#[test]
fn step3c_mixed_branch_assignment_is_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap())
        .unwrap();
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[2u8; 32]).unwrap())
        .unwrap();
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap();
    let bob_public = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[8u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_public, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_public, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[9u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;

    // Both a BobClaim kernel AND a Plain kernel matching the authorization.
    let bob_kernel = bob_claim_kernel(secp, receipt_commit, &bob_secret, kernel_excess, fee);
    let plain_k = plain_kernel(secp, kernel_excess, fee);
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        plain_k.hash(),
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .unwrap();

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![bob_kernel, plain_k]);
    let err = tx
        .body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("mixed-branch assignment must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// A receipt input with no authorization (Bob path) but no matching BobClaim
/// kernel must be rejected.
#[test]
fn step3c_receipt_input_without_bob_claim_is_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap())
        .unwrap();
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[2u8; 32]).unwrap())
        .unwrap();
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap();
    let bob_public = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[6u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_public, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_public, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[9u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;

    // Only a Plain kernel, no BobClaim kernel.
    let plain_k = plain_kernel(secp, kernel_excess, fee);

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![plain_k]);
    let err = tx
        .body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("receipt input without BobClaim kernel must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// An Alice-spend authorization whose kernel_hash does not match any kernel
/// in the transaction must be rejected.
#[test]
fn step3c_alice_auth_with_wrong_kernel_hash_is_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap())
        .unwrap();
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[2u8; 32]).unwrap())
        .unwrap();
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap();
    let bob_public = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[8u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_public, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_public, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[9u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);

    // Auth binds to a DIFFERENT kernel hash.
    let wrong_hash = Hash::from_vec(&[0xffu8; 32]);
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        wrong_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .unwrap();

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("Alice auth with wrong kernel_hash must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// Two receipt inputs with two BobClaim kernels (both valid) must pass.
#[test]
fn step3c_two_bob_claims_passes_validate_read() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let commit_1 = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap())
        .unwrap();
    let commit_2 = secp
        .commit(43, secp::SecretKey::from_slice(&secp, &[4u8; 32]).unwrap())
        .unwrap();
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[2u8; 32]).unwrap())
        .unwrap();
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap();
    let bob_public = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[6u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_public, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_public, &secp);

    let fee = 2u64;
    let kernel_excess_1 = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[9u8; 32]).unwrap())
        .unwrap();
    let kernel_excess_2 = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[10u8; 32]).unwrap())
        .unwrap();

    let kernel_1 = bob_claim_kernel(secp, commit_1, &bob_secret, kernel_excess_1, fee);
    let kernel_2 = bob_claim_kernel(secp, commit_2, &bob_secret, kernel_excess_2, fee);

    let input_1 = Input {
        features: OutputFeatures::Receipt,
        commit: commit_1,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let input_2 = Input {
        features: OutputFeatures::Receipt,
        commit: commit_2,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(
        vec![input_1, input_2],
        vec![output],
        vec![kernel_1, kernel_2],
    );
    tx.body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect("two valid BobClaims must pass validate_read");
}

/// A BobClaim kernel whose original_commitment does not match any receipt
/// input must be rejected (unused kernel).
#[test]
fn step3c_unused_bob_claim_kernel_is_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap())
        .unwrap();
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[2u8; 32]).unwrap())
        .unwrap();
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap();
    let bob_public = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[6u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_public, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_public, &secp);

    let fee = 2u64;
    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[9u8; 32]).unwrap())
        .unwrap();
    let other_commit = secp
        .commit(43, secp::SecretKey::from_slice(&secp, &[3u8; 32]).unwrap())
        .unwrap();

    // BobClaim kernel bound to a DIFFERENT commitment than the input.
    let kernel = bob_claim_kernel(secp, other_commit, &bob_secret, kernel_excess, fee);

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("BobClaim kernel with wrong commitment must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// OutputIdentifier::from_input ignores the authorization field: two inputs
/// that differ only in receipt_spend_authorization produce the same identifier.
#[test]
fn output_identifier_ignores_authorization() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let secret = secp::SecretKey::from_slice(&secp, &[7u8; 32]).unwrap();
    let pk = secp::PublicKey::from_secret_key(&secp, &secret).unwrap();
    let hint = ReceiptStealthHint::from_public_key(&pk, &secp);
    let hashes = SharedReceiptKeyHashes::from_public_keys(&pk, &pk);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
    let commit = keychain
        .commit(42, &key_id, &keychain::SwitchCommitmentType::Regular)
        .unwrap();

    let base = Input {
        features: OutputFeatures::Receipt,
        commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };

    let alice_secret = secp::SecretKey::from_slice(&secp, &[43u8; 32]).unwrap();
    let kernel_excess = Commitment::from_vec(vec![9u8; 33]);
    let kernel_hash = Hash::from_vec(&[10u8; 32]);
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        commit,
        kernel_excess,
        5,
        kernel_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign");
    let with_auth = Input {
        receipt_spend_authorization: Some(auth),
        ..base
    };

    let id_no = core::core::OutputIdentifier::from_input(&base);
    let id_yes = core::core::OutputIdentifier::from_input(&with_auth);
    assert_eq!(
        id_no, id_yes,
        "OutputIdentifier must ignore the authorization field"
    );
}

// ─── Step 3C: verify_receipt_spend_authorizations ────────────────────────────

/// Helper: build a receipt input + plain kernel pair with a valid Alice
/// authorization, ready for validate_read. The kernel is passed in so that
/// its hash (which includes a random nonce) is the one bound in the
/// authorization.
fn alice_spend_body(
    receipt_commit: Commitment,
    kernel_excess: Commitment,
    fee: u64,
    kernel_hash: Hash,
    chain_id: ReceiptChainId,
    hashes: SharedReceiptKeyHashes,
    hint: ReceiptStealthHint,
    alice_secret: &secp::SecretKey,
    kernel: core::core::TxKernel,
) -> core::core::TransactionBody {
    let dest_commit = {
        let secp_arc = static_secp_instance();
        let secp = secp_arc.lock();
        secp.commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
            .unwrap()
    };
    let dest_proof = util::secp::pedersen::RangeProof::zero();

    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        kernel_hash,
        chain_id,
        alice_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    core::core::Transaction::new(vec![input], vec![output], vec![kernel]).body
}

/// A valid Alice-spend authorization passes validate_read (with matching
/// chain id from the global).
#[test]
fn step3c_valid_authorization_passes_validate_read() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[21u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[22u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[23u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[24u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;

    // Build a plain kernel first to get its hash. The kernel's signature
    // contains a random nonce, so we must use this exact kernel instance
    // in the body (not recreate it).
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    let body = alice_spend_body(
        receipt_commit,
        kernel_excess,
        fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        hashes,
        hint,
        &alice_secret,
        kernel,
    );
    body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect("valid authorization must pass validate_read");
}

/// An authorization signed with a different Alice key must be rejected.
#[test]
fn step3c_wrong_alice_key_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[31u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[32u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[33u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[34u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    // Sign with a DIFFERENT key (not Alice).
    let wrong_secret = secp::SecretKey::from_slice(&secp, &[35u8; 32]).unwrap();
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        &wrong_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body
        .validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("wrong Alice key must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// An authorization with a wrong original_commitment must be rejected.
#[test]
fn step3c_wrong_original_commitment_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[41u8; 32]).unwrap())
        .unwrap();
    let wrong_commit = secp
        .commit(99, secp::SecretKey::from_slice(&secp, &[42u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[43u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[44u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[45u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    // Sign with the WRONG original commitment.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        wrong_commit,
        kernel_excess,
        fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body
        .validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("wrong original commitment must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// An authorization with a wrong kernel_excess must be rejected.
#[test]
fn step3c_wrong_kernel_excess_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[51u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[52u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[53u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[54u8; 32]).unwrap())
        .unwrap();
    let wrong_excess = secp
        .commit(1, secp::SecretKey::from_slice(&secp, &[55u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    // Sign with the WRONG kernel excess.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        wrong_excess,
        fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body
        .validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("wrong kernel excess must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// An authorization with a wrong fee must be rejected.
#[test]
fn step3c_wrong_fee_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[61u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[62u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[63u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[64u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let wrong_fee = 99u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    // Sign with the WRONG fee.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        wrong_fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body
        .validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("wrong fee must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// An authorization with a wrong kernel_hash must be rejected.
#[test]
fn step3c_wrong_kernel_hash_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[71u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[72u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[73u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[74u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let wrong_hash = Hash::from_vec(&[99u8; 32]);

    // Sign with the WRONG kernel hash.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        wrong_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body
        .validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("wrong kernel hash must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

/// An authorization with a wrong chain id must be rejected.
#[test]
fn step3c_wrong_chain_id_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[81u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[82u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[83u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[84u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    // Sign with the WRONG chain id (floonet instead of usernet).
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        kernel_hash,
        ReceiptChainId::floonet(),
        &alice_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let err = tx
        .body
        .validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("wrong chain id must be rejected");
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "expected InvalidReceiptClaim, got {:?}",
        err
    );
}

// ─── Step 3C: Cut-through safety ─────────────────────────────────────────────

/// A BobClaim transaction with a receipt input must survive cut_through
/// without the receipt input being cut against any ordinary output.
#[test]
fn step3c_cut_through_bob_claim_preserves_receipt_input() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[21u8; 32]).unwrap())
        .unwrap();
    let bob_secret = secp::SecretKey::from_slice(&secp, &[23u8; 32]).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &bob_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let mut inputs = vec![input.clone()];
    let mut outputs = vec![output.clone()];
    core::core::transaction::cut_through(&mut inputs, &mut outputs)
        .expect("cut_through must succeed");
    // The receipt input must NOT be cut — it should remain.
    assert_eq!(inputs.len(), 1, "receipt input must survive cut_through");
    assert_eq!(outputs.len(), 1, "plain output must survive cut_through");
    assert_eq!(inputs[0].commit, receipt_commit, "receipt input must be preserved");
}

/// An AliceSpend transaction with a receipt input must survive cut_through
/// without the receipt input being cut against any ordinary output.
#[test]
fn step3c_cut_through_alice_spend_preserves_receipt_input() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[21u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[22u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(
        &secp,
        &secp::SecretKey::from_slice(&secp, &[23u8; 32]).unwrap(),
    )
    .unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[24u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit,
        kernel_excess,
        fee,
        kernel_hash,
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp
        .commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap())
        .unwrap();
    let output = Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let mut inputs = vec![input.clone()];
    let mut outputs = vec![output.clone()];
    core::core::transaction::cut_through(&mut inputs, &mut outputs)
        .expect("cut_through must succeed");
    assert_eq!(inputs.len(), 1, "receipt input must survive cut_through");
    assert_eq!(outputs.len(), 1, "plain output must survive cut_through");
}

/// Ordinary cut-through (same commitment in input and output) still works.
#[test]
fn step3c_cut_through_ordinary_still_cuts() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let commit = secp
        .commit(50, secp::SecretKey::from_slice(&secp, &[5u8; 32]).unwrap())
        .unwrap();

    let input = Input {
        features: OutputFeatures::Plain,
        commit,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
        receipt_spend_authorization: None,
    };
    let output = Output {
        features: OutputFeatures::Plain,
        commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let mut inputs = vec![input];
    let mut outputs = vec![output];
    core::core::transaction::cut_through(&mut inputs, &mut outputs)
        .expect("cut_through must succeed");
    assert_eq!(inputs.len(), 0, "ordinary input must be cut");
    assert_eq!(outputs.len(), 0, "ordinary output must be cut");
}

/// verify_cut_through must NOT reject a transaction where a receipt input
/// and a plain output share the same commitment (because the receipt
/// metadata makes their hashes differ).
#[test]
fn step3c_verify_cut_through_allows_receipt_input_same_commitment() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[21u8; 32]).unwrap())
        .unwrap();
    let bob_secret = secp::SecretKey::from_slice(&secp, &[23u8; 32]).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &bob_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[24u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    // The receipt secret key MUST match the bob_pk used in hashes, because
    // verify_receipt_resolution checks hashes.matches_bob(&claim.receipt_public_key).
    let claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        receipt_commit,
        kernel_excess,
        fee,
        &bob_secret,
    )
    .expect("sign");
    let kernel = TxKernel {
        features: core::core::KernelFeatures::BobClaim { fee },
        excess: kernel_excess,
        excess_sig: {
            let msg = core::core::KernelFeatures::BobClaim { fee }
                .kernel_sig_msg()
                .unwrap();
            let pk = kernel_excess.to_pubkey(secp).unwrap();
            secp::aggsig::sign_single(
                secp,
                &msg,
                &secp::SecretKey::from_slice(secp, &[2u8; 32]).unwrap(),
                None,
                None,
                None,
                Some(&pk),
                None,
            )
            .unwrap()
        },
        receipt_claim: Some(claim),
    };

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    // Output with the SAME commitment as the receipt input but as a plain output.
    // verify_cut_through should NOT reject this because the receipt input is
    // excluded from the comparison.
    let output = Output {
        features: OutputFeatures::Plain,
        commit: receipt_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };

    let body = core::core::Transaction::new(vec![input], vec![output], vec![kernel]).body;
    body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect("verify_cut_through must not reject receipt input with same commitment as plain output");
}

/// Aggregation of a BobClaim transaction and an AliceSpend transaction in
/// the same block must preserve all receipt evidence (inputs, outputs,
/// kernels).
#[test]
fn step3c_aggregation_preserves_receipt_evidence() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    // Build BobClaim tx
    let receipt_commit_b = secp
        .commit(42, secp::SecretKey::from_slice(&secp, &[21u8; 32]).unwrap())
        .unwrap();
    let bob_secret = secp::SecretKey::from_slice(&secp, &[23u8; 32]).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let hashes_b = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &bob_pk);
    let hint_b = ReceiptStealthHint::from_public_key(&bob_pk, &secp);
    let excess_b = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[24u8; 32]).unwrap())
        .unwrap();
    let fee = 2u64;
    let claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        receipt_commit_b,
        excess_b,
        fee,
        &bob_secret,
    )
    .expect("sign");
    let kernel_b = TxKernel {
        features: core::core::KernelFeatures::BobClaim { fee },
        excess: excess_b,
        excess_sig: {
            let msg = core::core::KernelFeatures::BobClaim { fee }.kernel_sig_msg().unwrap();
            let pk = excess_b.to_pubkey(secp).unwrap();
            secp::aggsig::sign_single(secp, &msg, &secp::SecretKey::from_slice(secp, &[2u8; 32]).unwrap(), None, None, None, Some(&pk), None).unwrap()
        },
        receipt_claim: Some(claim),
    };
    let input_b = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit_b,
        receipt_key_hashes: Some(hashes_b),
        receipt_stealth_hint: Some(hint_b),
        receipt_spend_authorization: None,
    };
    let output_b = Output {
        features: OutputFeatures::Plain,
        commit: secp.commit(40, secp::SecretKey::from_slice(&secp, &[20u8; 32]).unwrap()).unwrap(),
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let tx_bob = core::core::Transaction::new(vec![input_b], vec![output_b], vec![kernel_b]);

    // Build AliceSpend tx
    let receipt_commit_a = secp
        .commit(43, secp::SecretKey::from_slice(&secp, &[26u8; 32]).unwrap())
        .unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[22u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let hashes_a = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint_a = ReceiptStealthHint::from_public_key(&bob_pk, &secp);
    let excess_a = secp
        .commit(0, secp::SecretKey::from_slice(&secp, &[27u8; 32]).unwrap())
        .unwrap();
    let kernel_a = plain_kernel(secp, excess_a, fee);
    let auth_a = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        receipt_commit_a,
        excess_a,
        fee,
        kernel_a.hash(),
        ReceiptChainId::usernet(),
        &alice_secret,
    )
    .expect("sign");
    let input_a = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit_a,
        receipt_key_hashes: Some(hashes_a),
        receipt_stealth_hint: Some(hint_a),
        receipt_spend_authorization: Some(auth_a),
    };
    let output_a = Output {
        features: OutputFeatures::Plain,
        commit: secp.commit(41, secp::SecretKey::from_slice(&secp, &[28u8; 32]).unwrap()).unwrap(),
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let tx_alice = core::core::Transaction::new(vec![input_a], vec![output_a], vec![kernel_a]);

    // Aggregate
    let aggregated = core::core::transaction::aggregate(vec![tx_bob, tx_alice])
        .expect("aggregation must succeed");

    // Both receipt inputs must be present
    let receipt_inputs: Vec<_> = aggregated
        .inputs()
        .iter()
        .filter(|i| i.features.is_receipt())
        .collect();
    assert_eq!(receipt_inputs.len(), 2, "both receipt inputs must survive aggregation");

    // Both kernels must be present
    assert_eq!(aggregated.kernels().len(), 2, "both kernels must survive aggregation");

    // The BobClaim kernel must retain its receipt_claim
    let bob_kernel = aggregated
        .kernels()
        .iter()
        .find(|k| k.receipt_claim.is_some())
        .expect("BobClaim kernel must be present");
    assert!(bob_kernel.receipt_claim.is_some(), "BobClaim kernel must retain receipt_claim");

    // The AliceSpend input must retain its authorization
    let alice_input = aggregated
        .inputs()
        .iter()
        .find(|i| i.features.is_receipt() && i.receipt_spend_authorization.is_some())
        .expect("AliceSpend input with auth must be present");
    assert!(alice_input.receipt_spend_authorization.is_some());
}

// ─── Security Review: Adversarial Kernel Attribution ─────────────────────────

/// Two Bob inputs sharing one BobClaim kernel (same receipt_claim on both)
/// must be rejected: verify_receipt_resolution requires exactly one
/// matching kernel per input. With 1 kernel and 2 inputs, the count check
/// (receipt_kernels > receipt_inputs) does NOT fire, but per-input matching
/// must still enforce uniqueness.
#[test]
fn sec_review_shared_bobclaim_kernel_two_inputs_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let bob_secret = secp::SecretKey::from_slice(&secp, &[81u8; 32]).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[82u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp.commit(0, secp::SecretKey::from_slice(&secp, &[83u8; 32]).unwrap()).unwrap();
    let fee = 2u64;
    let commit1 = secp.commit(42, secp::SecretKey::from_slice(&secp, &[84u8; 32]).unwrap()).unwrap();
    let commit2 = secp.commit(43, secp::SecretKey::from_slice(&secp, &[85u8; 32]).unwrap()).unwrap();

    // BobClaim kernel bound to commit1.
    let kernel = bob_claim_kernel(secp, commit1, &bob_secret, kernel_excess, fee);

    // Two Bob inputs, both with no auth, both trying to use the same kernel.
    let input1 = Input {
        features: OutputFeatures::Receipt, commit: commit1,
        receipt_key_hashes: Some(hashes), receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let input2 = Input {
        features: OutputFeatures::Receipt, commit: commit2,
        receipt_key_hashes: Some(hashes), receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let dest_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[86u8; 32]).unwrap()).unwrap();
    let output = Output {
        features: OutputFeatures::Plain, commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    // 1 kernel, 2 inputs → count check (1 > 2) is false.
    // input1: bob_matches=1 (kernel bound to commit1), OK.
    // input2: bob_matches=0 (kernel NOT bound to commit2), len!=1 → REJECT.
    let body = core::core::Transaction::new(vec![input1, input2], vec![output], vec![kernel]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("shared BobClaim kernel for two inputs must be rejected");
    assert!(matches!(err, core::core::transaction::Error::InvalidReceiptClaim));
}

/// Alice input with a BobClaim kernel also present (mixed path) must be
/// rejected even when the Alice auth is valid.
#[test]
fn sec_review_alice_path_with_bobclaim_kernel_present_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[91u8; 32]).unwrap()).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[92u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[93u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp.commit(0, secp::SecretKey::from_slice(&secp, &[94u8; 32]).unwrap()).unwrap();
    let fee = 2u64;
    let plain_kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = plain_kernel.hash();

    // Also include a BobClaim kernel bound to the same commitment.
    let bob_secret = secp::SecretKey::from_slice(&secp, &[95u8; 32]).unwrap();
    let bob_kernel = bob_claim_kernel(secp, receipt_commit, &bob_secret, kernel_excess, fee);

    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend, receipt_commit, kernel_excess, fee,
        kernel_hash, ReceiptChainId::usernet(), &alice_secret,
    ).unwrap();

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[96u8; 32]).unwrap()).unwrap();
    let output = Output {
        features: OutputFeatures::Plain, commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    // Alice auth present + BobClaim kernel bound to same commitment → mixed path.
    let body = core::core::Transaction::new(vec![input], vec![output], vec![plain_kernel, bob_kernel]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("mixed path (Alice auth + BobClaim kernel) must be rejected");
    assert!(matches!(err, core::core::transaction::Error::InvalidReceiptClaim));
}

// ─── Security Review: Cut-Through Adversarial Tests ──────────────────────────

/// A Receipt input with the same commitment as a Receipt output in the same
/// transaction must NOT be cut through. verify_cut_through must reject it
/// (CutThrough error) because it compares all item hashes including receipt
/// items... wait, it EXCLUDES receipt items. So it should pass.
/// This test verifies that receipt items with the same commitment are
/// preserved (not cut) by cut_through() but also that verify_cut_through
/// does not reject them (they are excluded from the comparison).
#[test]
fn sec_review_cut_through_receipt_same_commitment_not_cut() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let secret = secp::SecretKey::from_slice(&secp, &[101u8; 32]).unwrap();
    let pk = secp::PublicKey::from_secret_key(&secp, &secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&pk, &pk);
    let hint = ReceiptStealthHint::from_public_key(&pk, &secp);
    let commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[102u8; 32]).unwrap()).unwrap();

    // Receipt input and output with the SAME commitment.
    let receipt_input = Input {
        features: OutputFeatures::Receipt, commit,
        receipt_key_hashes: Some(hashes), receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };
    let receipt_output = Output {
        features: OutputFeatures::Receipt, commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: Some(hashes), receipt_stealth_hint: Some(hint),
    };

    // Ordinary input/output with different commitments (will be cut if matching).
    let plain_commit_in = secp.commit(40, secp::SecretKey::from_slice(&secp, &[103u8; 32]).unwrap()).unwrap();
    let plain_commit_out = secp.commit(40, secp::SecretKey::from_slice(&secp, &[103u8; 32]).unwrap()).unwrap();
    assert_eq!(plain_commit_in, plain_commit_out, "must be same for cut-through test");
    let plain_input = Input {
        features: OutputFeatures::Plain, commit: plain_commit_in,
        receipt_key_hashes: None, receipt_stealth_hint: None,
        receipt_spend_authorization: None,
    };
    let plain_output = Output {
        features: OutputFeatures::Plain, commit: plain_commit_out,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    let kernel = plain_kernel(secp, secp.commit(0, secp::SecretKey::from_slice(&secp, &[104u8; 32]).unwrap()).unwrap(), 2);

    let mut inputs = vec![receipt_input, plain_input];
    let mut outputs = vec![receipt_output, plain_output];

    // cut_through must remove the plain pair but preserve the receipt pair.
    core::core::transaction::cut_through(&mut inputs, &mut outputs).unwrap();
    assert_eq!(inputs.len(), 1, "only receipt input should remain");
    assert_eq!(outputs.len(), 1, "only receipt output should remain");
    assert!(inputs[0].features.is_receipt(), "remaining input must be receipt");
    assert!(outputs[0].features.is_receipt(), "remaining output must be receipt");
}

/// verify_cut_through on a body where ordinary items have the same commitment
/// must reject with CutThrough (regression: ordinary cut-through still works).
/// Additionally, receipt items with the same commitment as ordinary items
/// must NOT trigger CutThrough (they are excluded).
#[test]
fn sec_review_verify_cut_through_ordinary_still_rejects() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    // Two ordinary items with the same commitment → CutThrough error.
    let commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[121u8; 32]).unwrap()).unwrap();
    let plain_input = Input {
        features: OutputFeatures::Plain, commit,
        receipt_key_hashes: None, receipt_stealth_hint: None,
        receipt_spend_authorization: None,
    };
    let plain_output = Output {
        features: OutputFeatures::Plain, commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };
    let kernel = plain_kernel(secp, secp.commit(0, secp::SecretKey::from_slice(&secp, &[122u8; 32]).unwrap()).unwrap(), 2);

    let body = core::core::Transaction::new(vec![plain_input], vec![plain_output], vec![kernel]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("ordinary same-commitment must trigger CutThrough");
    assert!(matches!(err, core::core::transaction::Error::CutThrough));
}

/// cut_through() must preserve receipt items even when they share a
/// commitment with an ordinary item that gets cut.
#[test]
fn sec_review_cut_through_preserves_receipt_when_ordinary_cuts() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let secret = secp::SecretKey::from_slice(&secp, &[131u8; 32]).unwrap();
    let pk = secp::PublicKey::from_secret_key(&secp, &secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&pk, &pk);
    let hint = ReceiptStealthHint::from_public_key(&pk, &secp);
    let receipt_commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[132u8; 32]).unwrap()).unwrap();

    let receipt_input = Input {
        features: OutputFeatures::Receipt, commit: receipt_commit,
        receipt_key_hashes: Some(hashes), receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: None,
    };

    // Ordinary pair with same commitment (will be cut).
    let plain_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[133u8; 32]).unwrap()).unwrap();
    let plain_input = Input {
        features: OutputFeatures::Plain, commit: plain_commit,
        receipt_key_hashes: None, receipt_stealth_hint: None,
        receipt_spend_authorization: None,
    };
    let plain_output = Output {
        features: OutputFeatures::Plain, commit: plain_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    let mut inputs = vec![receipt_input, plain_input];
    let mut outputs = vec![plain_output];

    core::core::transaction::cut_through(&mut inputs, &mut outputs).unwrap();
    // Plain pair is cut, receipt input is preserved.
    assert_eq!(inputs.len(), 1, "receipt input must survive cut-through");
    assert_eq!(outputs.len(), 0, "plain output must be cut");
    assert!(inputs[0].features.is_receipt());
}

// ─── Security Review: Adversarial Authorization Tests ───────────────────────

/// BobClaim kernel used as the "matching kernel" for an Alice authorization
/// must be rejected: verify_for_receipt_input checks kernel.features.is_plain().
/// The kernel lookup in verify_receipt_spend_authorizations filters out
/// is_receipt_resolution() kernels, so a BobClaim kernel can never be selected.
/// This test verifies the structural invariant.
#[test]
fn sec_review_bobclaim_kernel_cannot_satisfy_alice_auth() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[141u8; 32]).unwrap()).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[142u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_secret = secp::SecretKey::from_slice(&secp, &[143u8; 32]).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp.commit(0, secp::SecretKey::from_slice(&secp, &[144u8; 32]).unwrap()).unwrap();
    let fee = 2u64;

    // Only a BobClaim kernel is present (no Plain kernel).
    let bob_kernel = bob_claim_kernel(secp, receipt_commit, &bob_secret, kernel_excess, fee);

    // Alice auth bound to the BobClaim kernel's excess/fee/hash.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend, receipt_commit, kernel_excess, fee,
        bob_kernel.hash(), ReceiptChainId::usernet(), &alice_secret,
    ).unwrap();

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[145u8; 32]).unwrap()).unwrap();
    let output = Output {
        features: OutputFeatures::Plain, commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    // Alice path requires a Plain kernel; only BobClaim present → reject.
    let body = core::core::Transaction::new(vec![input], vec![output], vec![bob_kernel]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("BobClaim kernel cannot satisfy Alice auth");
    assert!(matches!(err, core::core::transaction::Error::InvalidReceiptClaim));
}

/// Authorization with a forged/altered signature (flip one byte) must be
/// rejected by the AgSig verification.
#[test]
fn sec_review_forged_signature_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[151u8; 32]).unwrap()).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[152u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[153u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp.commit(0, secp::SecretKey::from_slice(&secp, &[154u8; 32]).unwrap()).unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    let mut auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend, receipt_commit, kernel_excess, fee,
        kernel_hash, ReceiptChainId::usernet(), &alice_secret,
    ).unwrap();
    // Corrupt the signature via serialization round-trip with flipped byte.
    let mut sig_buf = vec![];
    ser::serialize_default(&mut sig_buf, &auth.alice_signature).unwrap();
    let last_len = sig_buf.len() - 1;
    sig_buf[last_len] ^= 0xff;
    let corrupted_sig = util::secp::Signature::from_raw_data(
        &sig_buf.as_slice().try_into().unwrap(),
    ).unwrap();
    auth.alice_signature = corrupted_sig;

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[155u8; 32]).unwrap()).unwrap();
    let output = Output {
        features: OutputFeatures::Plain, commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    let body = core::core::Transaction::new(vec![input], vec![output], vec![kernel]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("forged signature must be rejected");
    assert!(matches!(err, core::core::transaction::Error::InvalidReceiptClaim));
}

/// Authorization signed with Bob's key instead of Alice's key must be
/// rejected: the alice_public_key in the auth won't match the receipt's
/// committed alice hash.
#[test]
fn sec_review_bob_key_as_alice_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[161u8; 32]).unwrap()).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[162u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_secret = secp::SecretKey::from_slice(&secp, &[163u8; 32]).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &bob_secret).unwrap();
    // Receipt commits to alice_pk in the alice hash field.
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp.commit(0, secp::SecretKey::from_slice(&secp, &[164u8; 32]).unwrap()).unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    // Sign with Bob's key — alice_public_key will be bob_pk.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend, receipt_commit, kernel_excess, fee,
        kernel_hash, ReceiptChainId::usernet(), &bob_secret,
    ).unwrap();
    assert_eq!(auth.alice_public_key, bob_pk, "auth signed with Bob's key");

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[165u8; 32]).unwrap()).unwrap();
    let output = Output {
        features: OutputFeatures::Plain, commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    // Bob's key won't match the receipt's committed alice hash → reject.
    let body = core::core::Transaction::new(vec![input], vec![output], vec![kernel]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("Bob's key as Alice must be rejected");
    assert!(matches!(err, core::core::transaction::Error::InvalidReceiptClaim));
}

/// Authorization with the wrong path tag (BobClaim instead of AliceSpend)
/// must be rejected. ReceiptSpendAuthorization::sign rejects non-AliceSpend
/// paths at construction, so we test that verify() rejects it.
#[test]
fn sec_review_wrong_path_tag_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    // ReceiptSpendAuthorization::sign explicitly rejects BobClaim path:
    assert!(ReceiptSpendAuthorization::sign(
        ReceiptPath::BobClaim,
        Commitment::from_vec(vec![0u8; 33]),
        Commitment::from_vec(vec![0u8; 33]),
        0,
        Hash::from_vec(&[0u8; 32]),
        ReceiptChainId::usernet(),
        &secp::SecretKey::from_slice(&secp::Secp256k1::new(), &[1u8; 32]).unwrap(),
    ).is_err(), "sign must reject BobClaim path");
}

/// Authorization bound to one receipt input must not be reusable on a
/// different receipt input (different original_commitment in the message).
#[test]
fn sec_review_auth_reuse_across_inputs_rejected() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let alice_secret = secp::SecretKey::from_slice(&secp, &[171u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[172u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp.commit(0, secp::SecretKey::from_slice(&secp, &[173u8; 32]).unwrap()).unwrap();
    let fee = 2u64;
    let kernel = plain_kernel(secp, kernel_excess, fee);
    let kernel_hash = kernel.hash();

    let commit1 = secp.commit(42, secp::SecretKey::from_slice(&secp, &[174u8; 32]).unwrap()).unwrap();
    let commit2 = secp.commit(43, secp::SecretKey::from_slice(&secp, &[175u8; 32]).unwrap()).unwrap();

    // Auth signed for commit1.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend, commit1, kernel_excess, fee,
        kernel_hash, ReceiptChainId::usernet(), &alice_secret,
    ).unwrap();

    // Both inputs carry the SAME auth (reused).
    let input1 = Input {
        features: OutputFeatures::Receipt, commit: commit1,
        receipt_key_hashes: Some(hashes), receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth.clone()),
    };
    let input2 = Input {
        features: OutputFeatures::Receipt, commit: commit2,
        receipt_key_hashes: Some(hashes), receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[176u8; 32]).unwrap()).unwrap();
    let output = Output {
        features: OutputFeatures::Plain, commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    // input2's auth binds commit1 != commit2 → verify_for_receipt_input
    // rejects (original_commitment mismatch).
    let body = core::core::Transaction::new(vec![input1, input2], vec![output], vec![kernel]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("auth reuse across different inputs must be rejected");
    assert!(matches!(err, core::core::transaction::Error::InvalidReceiptClaim));
}

/// Two separately-built kernels with the same (excess, fee) but different
/// hashes: the auth must bind the hash of the actual kernel in the tx, not
/// one of the alternatives.
#[test]
fn sec_review_kernel_hash_binding_rejects_alternate_kernel() {
    global::set_mining_mode(ChainTypes::UserTesting);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let receipt_commit = secp.commit(42, secp::SecretKey::from_slice(&secp, &[181u8; 32]).unwrap()).unwrap();
    let alice_secret = secp::SecretKey::from_slice(&secp, &[182u8; 32]).unwrap();
    let alice_pk = secp::PublicKey::from_secret_key(&secp, &alice_secret).unwrap();
    let bob_pk = secp::PublicKey::from_secret_key(&secp, &secp::SecretKey::from_slice(&secp, &[183u8; 32]).unwrap()).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_pk, &alice_pk);
    let hint = ReceiptStealthHint::from_public_key(&bob_pk, &secp);

    let kernel_excess = secp.commit(0, secp::SecretKey::from_slice(&secp, &[184u8; 32]).unwrap()).unwrap();
    let fee = 2u64;
    // Two distinct kernels, same (excess, fee), different random-nonce hashes.
    let kernel_a = plain_kernel(secp, kernel_excess, fee);
    let kernel_b = plain_kernel(secp, kernel_excess, fee);
    assert_ne!(kernel_a.hash(), kernel_b.hash(), "kernels must differ");

    // Auth binds kernel_a's hash, but the tx contains kernel_b.
    let auth = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend, receipt_commit, kernel_excess, fee,
        kernel_a.hash(), ReceiptChainId::usernet(), &alice_secret,
    ).unwrap();

    let input = Input {
        features: OutputFeatures::Receipt,
        commit: receipt_commit,
        receipt_key_hashes: Some(hashes),
        receipt_stealth_hint: Some(hint),
        receipt_spend_authorization: Some(auth),
    };
    let dest_commit = secp.commit(40, secp::SecretKey::from_slice(&secp, &[185u8; 32]).unwrap()).unwrap();
    let output = Output {
        features: OutputFeatures::Plain, commit: dest_commit,
        proof: util::secp::pedersen::RangeProof::zero(),
        receipt_key_hashes: None, receipt_stealth_hint: None,
    };

    // kernel_b's hash != auth.kernel_hash → no matching kernel → reject.
    let body = core::core::Transaction::new(vec![input], vec![output], vec![kernel_b]).body;
    let err = body.validate_read(core::core::transaction::Weighting::AsTransaction)
        .expect_err("auth bound to a different kernel hash must be rejected");
    assert!(matches!(err, core::core::transaction::Error::InvalidReceiptClaim));
}
