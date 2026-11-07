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

use self::core::core::{Input, Output, OutputFeatures};
use self::core::core::receipt_claim::{
    ReceiptChainId, ReceiptPath, ReceiptSpendAuthorization, ReceiptStealthHint,
    SharedReceiptKeyHashes,
};
use self::core::core::hash::Hash;
use self::core::libtx::proof;
use self::core::ser;
use epic_core as core;
use keychain::{ExtKeychain, Keychain};
use util::secp;
use util::secp::pedersen::Commitment;

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

/// OutputIdentifier::from_input ignores the authorization field: two inputs
/// that differ only in receipt_spend_authorization produce the same identifier.
#[test]
fn output_identifier_ignores_authorization() {
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
