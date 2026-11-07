// Copyright 2026 The Epic Cash Developers
//
// Local Usernet-only regression test for the experimental SNIP receipt flow.
// It intentionally creates no network connection and no persistent wallet.

mod chain_test_helper;

use crate::chain_test_helper::{
    clean_output_dir, init_chain, prepare_block, process_block, set_foundation_path_for_test,
};
use epic_core as core;
use epic_keychain as keychain;
use epic_util as util;

use core::core::{
    build_bob_claim_transaction, build_receipt_funding_transaction,
    rewind_shared_receipt_output, Input, OutputFeatures, OutputIdentifier,
    SharedReceiptKeyHashes, StealthReceiptSecrets,
};
use core::global::{self, ChainTypes};
use core::pow;
use keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use util::secp;
use util::secp::key::SecretKey;

fn key(secp: &secp::Secp256k1) -> SecretKey {
    SecretKey::new(secp, &mut rand::rng())
}

#[test]
fn usernet_receipt_output_can_be_claimed_in_later_block() {
    util::init_test_logger();
    let chain_dir = ".epic_receipt_claim_roundtrip";
    clean_output_dir(chain_dir);

    // The receipt feature is deliberately gated to UserTesting mode. The
    // foundation helper sets AutomatedTesting, so select UserTesting before
    // producing genesis and all following blocks.
    set_foundation_path_for_test("foundation_floonet.json");
    global::set_mining_mode(ChainTypes::UserTesting);
    let genesis = pow::mine_genesis_block().unwrap();
    let chain = init_chain(chain_dir, genesis);
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    // Mine a coinbase and the Usernet maturity interval so Alice has one real
    // chain UTXO from which to create the shared receipt output.
    for n in 1..=4 {
        let previous = chain.head_header().unwrap();
        let block = prepare_block(&keychain, &previous, &chain, n, vec![], 1);
        process_block(&chain, &block);
    }

    let alice_input_value = core::consensus::reward_at_height(1);
    let alice_input_id = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
    let alice_input_blind = keychain
        .derive_key(
            alice_input_value,
            &alice_input_id,
            &SwitchCommitmentType::Regular,
        )
        .unwrap();
    let alice_input_commit = keychain
        .commit(
            alice_input_value,
            &alice_input_id,
            &SwitchCommitmentType::Regular,
        )
        .unwrap();

    // Bob publishes a reusable descriptor once. Alice creates one fresh hint
    // and the shared receipt blind without an interactive response.
    let bob_secrets = StealthReceiptSecrets::new(key(secp), key(secp));
    let descriptor = bob_secrets.descriptor(secp).unwrap();
    let alice_ephemeral = key(secp);
    let (hint, bob_receipt_public_key) = descriptor
        .derive_for_sender(&alice_ephemeral, secp)
        .unwrap();
    let alice_authorization_public_key =
        secp::key::PublicKey::from_secret_key(secp, &key(secp)).unwrap();
    let hashes = SharedReceiptKeyHashes::from_public_keys(
        &bob_receipt_public_key,
        &alice_authorization_public_key,
    );
    let alice_shared_blind = descriptor
        .derive_shared_spend_blind_for_sender(&alice_ephemeral, secp)
        .unwrap();

    let funding_fee = 2;
    let funding_tx = build_receipt_funding_transaction(
        Input::new(OutputFeatures::Coinbase, alice_input_commit),
        alice_input_value,
        &alice_input_blind,
        &alice_shared_blind,
        hashes,
        hint,
        funding_fee,
        secp,
    )
    .unwrap();
    funding_tx.validate(core::core::transaction::Weighting::AsTransaction).unwrap();
    let receipt_output = funding_tx.outputs()[0];

    let previous = chain.head_header().unwrap();
    let funding_block = prepare_block(&keychain, &previous, &chain, 5, vec![&funding_tx], 2);
    process_block(&chain, &funding_block);
    let receipt_id = OutputIdentifier::from_output(&receipt_output);
    assert!(chain.is_unspent(&receipt_id).is_ok());

    // Bob discovers the confirmed output, rewinds its amount, then spends it
    // in a later block with the mandatory BobClaim kernel.
    let bob_shared_blind = bob_secrets
        .derive_shared_spend_blind(&descriptor, &hint, secp)
        .unwrap();
    let bob_receipt_key = bob_secrets
        .derive_receipt_key(&descriptor, &hint, secp)
        .unwrap();
    let receipt_value = rewind_shared_receipt_output(&receipt_output, &bob_shared_blind, secp)
        .unwrap();
    assert_eq!(receipt_value, alice_input_value - funding_fee);
    let claim_fee = 2;
    let destination_blind = key(secp);
    let claim_tx = build_bob_claim_transaction(
        &receipt_output,
        receipt_value,
        &bob_shared_blind,
        &bob_receipt_key,
        &destination_blind,
        claim_fee,
        secp,
    )
    .unwrap();
    claim_tx.validate(core::core::transaction::Weighting::AsTransaction).unwrap();
    let destination_id = OutputIdentifier::from_output(&claim_tx.outputs()[0]);

    let previous = chain.head_header().unwrap();
    let claim_block = prepare_block(&keychain, &previous, &chain, 6, vec![&claim_tx], 2);
    process_block(&chain, &claim_block);

    assert!(chain.is_unspent(&receipt_id).is_err());
    assert!(chain.is_unspent(&destination_id).is_ok());
    chain.validate(false).unwrap();

    clean_output_dir(chain_dir);
}
