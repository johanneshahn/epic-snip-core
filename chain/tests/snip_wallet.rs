// Copyright 2026 The Epic Cash Developers
//
// Research test: wallet-side SNIP payment end-to-end on local Usernet.
// Demonstrates: Alice creates three payments to one Bob descriptor (Bob
// offline), Bob discovers them by scanning, Bob claims two, Alice reclaims
// one, all conflicts are rejected, and competing R4 spends resolve
// deterministically in both confirmation orders.
//
// No new consensus rules are introduced. No existing code is modified.
// This is a wallet-level prototype: it exercises real Epic
// transaction/consensus/chain validation end-to-end.

mod chain_test_helper;

use crate::chain_test_helper::{
    clean_output_dir, init_chain, prepare_block, process_block, set_foundation_path_for_test,
};
use epic_core as core;
use epic_core::core::{
    build_alice_spend_transaction, build_bob_claim_transaction,
    build_receipt_funding_transaction, rewind_shared_receipt_output,
    Input, Output, OutputFeatures, OutputIdentifier, SharedReceiptKeyHashes,
    StealthReceiptDescriptor, StealthReceiptSecrets, Transaction,
};
use epic_core::core::receipt_claim::{
    AliceReceiptAuthorizationKey, ReceiptChainId, ReceiptPath, ReceiptSpendAuthorization,
    ReceiptStealthHint,
};
use epic_core::core::hash::Hashed;
use epic_core::core::transaction::Weighting;
use epic_core::global::{self, ChainTypes};
use epic_core::pow;
use epic_keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use epic_util as util;
use epic_util::secp;
use util::secp::key::{PublicKey, SecretKey};

// ─── Alice wallet state ───────────────────────────────────────────────────────

/// One payment Alice created and wants to be able to reclaim.
struct AlicePayment {
    payment_index: u32,
    receipt_output: Output,
    receipt_id: OutputIdentifier,
    receipt_value: u64,
    shared_blind: SecretKey,
    alice_authorization_key: AliceReceiptAuthorizationKey,
}

/// Alice's wallet: holds her keychain, seed-derived authorization keys,
/// and the list of payments she created.
struct AliceWallet {
    keychain: ExtKeychain,
    seed: [u8; 32],
    payments: Vec<AlicePayment>,
}

impl AliceWallet {
    /// Create Alice's wallet with a deterministic seed.
    fn new(keychain: ExtKeychain) -> Self {
        // Deterministic seed for reproducibility in tests.
        let seed = [0xA1; 32];
        Self {
            keychain,
            seed,
            payments: vec![],
        }
    }

    /// Derive a deterministic Alice authorization key from seed + payment index.
    ///
    /// Option A: `a_i = H256(DOMAIN || "alice-authorization-key|" || seed || index_le)`
    /// with counter increment if the result is not a valid secret key.
    fn derive_authorization_key(
        &self,
        payment_index: u32,
        secp: &secp::Secp256k1,
    ) -> Result<AliceReceiptAuthorizationKey, String> {
        use sha2::{Digest, Sha256};
        const DOMAIN: &[u8] = b"EPIC-SNIP-USERNET-v1|receipt-claim|";

        for counter in 0u8..=255 {
            let mut hash = Sha256::new();
            hash.update(DOMAIN);
            hash.update(b"alice-authorization-key|");
            hash.update(&self.seed);
            hash.update(payment_index.to_le_bytes());
            hash.update([counter]);
            let digest = hash.finalize();
            if let Ok(secret_key) = SecretKey::from_slice(secp, &digest) {
                return AliceReceiptAuthorizationKey::from_secret_key(secret_key, secp)
                    .map_err(|e| format!("from_secret_key: {}", e));
            }
        }
        Err("derive_authorization_key: exhausted all counters".into())
    }

    /// Create a payment: derive a_i, compute q_i / hint / B_i, build funding
    /// transaction. Returns the receipt output and all state needed to reclaim.
    fn create_payment(
        &mut self,
        payment_index: u32,
        bob_descriptor: &core::core::StealthReceiptDescriptor,
        coinbase_input: Input,
        coinbase_value: u64,
        coinbase_blind: SecretKey,
        fee: u64,
        secp: &secp::Secp256k1,
    ) -> Result<(Output, Transaction), String> {
        let alice_auth_key = self
            .derive_authorization_key(payment_index, secp)
            .map_err(|e| format!("payment {}: {}", payment_index, e))?;

        // Ephemeral key r_i for this payment.
        let r_i = SecretKey::new(secp, &mut rand::rng());

        // Derive hint + Bob's one-time receipt public key B_i.
        let (hint, bob_receipt_public_key) = bob_descriptor
            .derive_for_sender(&r_i, secp)
            .map_err(|e| format!("derive_for_sender: {}", e))?;

        // Derive the shared spend blind q_i (same for Alice and Bob).
        let shared_blind = bob_descriptor
            .derive_shared_spend_blind_for_sender(&r_i, secp)
            .map_err(|e| format!("derive_shared_spend_blind_for_sender: {}", e))?;

        // Build key hashes: H(B_i) and H(A_i).
        let alice_pub = *alice_auth_key.public_key();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_receipt_public_key, &alice_pub);

        // Build the funding transaction.
        let funding_tx = build_receipt_funding_transaction(
            coinbase_input,
            coinbase_value,
            &coinbase_blind,
            &shared_blind,
            hashes,
            hint,
            fee,
            secp,
        )
        .map_err(|e| format!("build_receipt_funding_transaction: {}", e))?;

        funding_tx
            .validate(core::core::transaction::Weighting::AsTransaction)
            .map_err(|e| format!("funding tx validate: {}", e))?;

        let receipt_output = funding_tx.outputs()[0].clone();
        let receipt_id = OutputIdentifier::from_output(&receipt_output);

        // The actual receipt value is the full input minus fee.
        let receipt_value = coinbase_value - fee;

        // Store payment state for later reclaim.
        let payment = AlicePayment {
            payment_index,
            receipt_output: receipt_output.clone(),
            receipt_id,
            receipt_value,
            shared_blind,
            alice_authorization_key: alice_auth_key,
        };
        self.payments.push(payment);

        Ok((receipt_output, funding_tx))
    }

    /// Build a reclaim transaction for a given payment index.
    fn build_reclaim(
        &self,
        payment_index: u32,
        destination_blind: &SecretKey,
        fee: u64,
        chain_id: ReceiptChainId,
        secp: &secp::Secp256k1,
    ) -> Result<Transaction, String> {
        let payment = self
            .payments
            .iter()
            .find(|p| p.payment_index == payment_index)
            .ok_or(format!("payment {} not found", payment_index))?;

        let alice_chain_id = {
            let guard = global::CHAIN_TYPE.read();
            ReceiptChainId::from_chain_type(&guard)
        };
        let _ = chain_id;

        build_alice_spend_transaction(
            &payment.receipt_output,
            payment.receipt_value,
            &payment.shared_blind,
            &payment.alice_authorization_key,
            destination_blind,
            fee,
            alice_chain_id,
            secp,
        )
        .map_err(|e| format!("build_alice_spend_transaction: {}", e))
    }
}

// ─── Bob wallet state ─────────────────────────────────────────────────────────

/// One payment Bob discovered by scanning.
struct BobPayment {
    hint: ReceiptStealthHint,
    shared_blind: SecretKey,
    bob_receipt_key: SecretKey,
    receipt_output: Output,
    receipt_id: OutputIdentifier,
    receipt_value: u64,
    block_height: u64,
}

/// Bob's wallet: holds his secrets, descriptor, and discovered payments.
struct BobWallet {
    secrets: StealthReceiptSecrets,
    descriptor: StealthReceiptDescriptor,
    payments: Vec<BobPayment>,
}

impl BobWallet {
    /// Create Bob's wallet from secrets.
    fn new(secrets: StealthReceiptSecrets, secp: &secp::Secp256k1) -> Self {
        let descriptor = secrets.descriptor(secp).unwrap();
        Self {
            secrets,
            descriptor,
            payments: vec![],
        }
    }

    /// Build a claim transaction for a discovered payment.
    fn build_claim(
        &self,
        payment: &BobPayment,
        destination_blind: &SecretKey,
        fee: u64,
        secp: &secp::Secp256k1,
    ) -> Result<Transaction, String> {
        build_bob_claim_transaction(
            &payment.receipt_output,
            payment.receipt_value,
            &payment.shared_blind,
            &payment.bob_receipt_key,
            destination_blind,
            fee,
            secp,
        )
        .map_err(|e| format!("build_bob_claim_transaction: {}", e))
    }

    /// Add a discovered payment to Bob's wallet.
    fn push_payment(&mut self, payment: BobPayment) {
        self.payments.push(payment);
    }

    /// Scan a block's outputs for SharedReceipt outputs that belong to Bob.
    fn scan_block(
        &self,
        block: &core::core::Block,
        chain: &epic_chain::Chain,
        block_height: u64,
        secp: &secp::Secp256k1,
    ) -> Vec<BobPayment> {
        let mut found = vec![];
        for output in block.outputs() {
            if !output.features.is_receipt() {
                continue;
            }
            let hint = match output.receipt_stealth_hint {
                Some(ref h) => *h,
                None => continue,
            };
            let hashes = match output.receipt_key_hashes {
                Some(ref h) => *h,
                None => continue,
            };
            let shared_blind = match self
                .secrets
                .derive_shared_spend_blind(&self.descriptor, &hint, secp)
            {
                Ok(sb) => sb,
                Err(_) => continue,
            };
            let bob_receipt_key = match self
                .secrets
                .derive_receipt_key(&self.descriptor, &hint, secp)
            {
                Ok(rk) => rk,
                Err(_) => continue,
            };
            let bob_pub = PublicKey::from_secret_key(secp, &bob_receipt_key).unwrap();
            if !hashes.matches_bob(&bob_pub) {
                continue;
            }
            let receipt_id = OutputIdentifier::from_output(output);
            if chain.is_unspent(&receipt_id).is_err() {
                continue;
            }
            let value = match rewind_shared_receipt_output(output, &shared_blind, secp) {
                Ok(v) => v,
                Err(_) => continue,
            };
            found.push(BobPayment {
                hint,
                shared_blind,
                bob_receipt_key,
                receipt_output: output.clone(),
                receipt_id,
                receipt_value: value,
                block_height,
            });
        }
        found
    }
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

fn key(secp: &secp::Secp256k1) -> SecretKey {
    SecretKey::new(secp, &mut rand::rng())
}

/// Mine a block containing the given transactions.
fn mine_block_with_txs(
    chain: &epic_chain::Chain,
    keychain: &ExtKeychain,
    txs: Vec<&Transaction>,
    key_id_branch: u8,
) -> u64 {
    let previous = chain.head_header().unwrap();
    let height = previous.height + 1;
    let block = prepare_block(keychain, &previous, chain, height % 7 + 1, txs, key_id_branch);
    process_block(chain, &block);
    height
}

/// Mine an empty block.
fn mine_empty_block(
    chain: &epic_chain::Chain,
    keychain: &ExtKeychain,
    key_id_branch: u8,
) -> u64 {
    mine_block_with_txs(chain, keychain, vec![], key_id_branch)
}

/// Initialize a chain and mine coinbase + maturity blocks.
fn setup_chain(
    chain_dir: &str,
    keychain: &ExtKeychain,
) -> epic_chain::Chain {
    util::init_test_logger();
    clean_output_dir(chain_dir);

    set_foundation_path_for_test("foundation_floonet.json");
    global::set_mining_mode(ChainTypes::AutomatedTesting);
    let genesis = pow::mine_genesis_block().unwrap();
    let chain = init_chain(chain_dir, genesis);

    // Mine coinbase + maturity (4 blocks).
    for n in 1..=4 {
        let previous = chain.head_header().unwrap();
        let block = prepare_block(keychain, &previous, &chain, n, vec![], 1);
        process_block(&chain, &block);
    }

    chain
}

/// Get a matured coinbase input from block 1.
fn get_coinbase_input(
    keychain: &ExtKeychain,
) -> (Input, u64, SecretKey) {
    let alice_input_value = core::consensus::reward_at_height(1);
    let alice_input_id = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
    let alice_input_blind = keychain
        .derive_key(alice_input_value, &alice_input_id, &SwitchCommitmentType::Regular)
        .unwrap();
    let alice_input_commit = keychain
        .commit(alice_input_value, &alice_input_id, &SwitchCommitmentType::Regular)
        .unwrap();
    (
        Input::new(OutputFeatures::Coinbase, alice_input_commit),
        alice_input_value,
        alice_input_blind,
    )
}

// ─── Phase A: Alice funds R1, R2, R3 ──────────────────────────────────────────

#[test]
fn phase_a_alice_funds_three_payments() {
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let chain = setup_chain(".snip_wallet_phase_a", &keychain);

    // Bob publishes his descriptor once.
    let bob_secrets = StealthReceiptSecrets::new(key(secp), key(secp));
    let bob_descriptor = bob_secrets.descriptor(secp).unwrap();

    // Alice creates her wallet.
    let mut alice = AliceWallet::new(keychain.clone());

    // Fund three payments. Each receipt gets the full coinbase minus fee.
    let fee = 2;

    for i in 0..3 {
        let payment_index = (i + 1) as u32;
        // Each payment needs its own coinbase input. Mine a block for the
        // coinbase, then 3 empty blocks to mature it (USER_TESTING_MATURITY=3).
        let cb_input = {
            let prev = chain.head_header().unwrap();
            let height = prev.height + 1;
            let block = prepare_block(&keychain, &prev, &chain, 1, vec![], 1);
            process_block(&chain, &block);
            // Mine 3 empty blocks so the coinbase matures.
            for _ in 0..3 {
                let p = chain.head_header().unwrap();
                let b = prepare_block(&keychain, &p, &chain, 1, vec![], 1);
                process_block(&chain, &b);
            }
            let cb_value = core::consensus::reward_at_height(height);
            let cb_id = ExtKeychainPath::new(1, height as u32, 0, 0, 0).to_identifier();
            let cb_blind = keychain
                .derive_key(cb_value, &cb_id, &SwitchCommitmentType::Regular)
                .unwrap();
            let cb_commit = keychain
                .commit(cb_value, &cb_id, &SwitchCommitmentType::Regular)
                .unwrap();
            (Input::new(OutputFeatures::Coinbase, cb_commit), cb_value, cb_blind)
        };

        let (receipt_output, funding_tx) = alice
            .create_payment(
                payment_index,
                &bob_descriptor,
                cb_input.0,
                cb_input.1,
                cb_input.2,
                fee,
                secp,
            )
            .unwrap();

        // Mine the funding block.
        let funding_height = mine_block_with_txs(&chain, &keychain, vec![&funding_tx], 1);
        let _ = funding_height;

        // Verify the receipt output is in the UTXO set.
        let receipt_id = OutputIdentifier::from_output(&receipt_output);
        assert!(
            chain.is_unspent(&receipt_id).is_ok(),
            "R{}: receipt output should be unspent after funding",
            payment_index
        );

        // Verify the value by rewinding with the shared blind.
        // The receipt value is the full coinbase minus fee (build_receipt_funding_transaction
        // sends input_value - fee to the receipt output).
        let alice_payment = &alice.payments[(i as usize)];
        let verified_value =
            rewind_shared_receipt_output(&receipt_output, &alice_payment.shared_blind, secp)
                .unwrap();
        let expected_value = cb_input.1 - fee;
        assert_eq!(verified_value, expected_value, "R{}: value mismatch", payment_index);
    }

    // All three payments should have distinct hints.
    let hints: Vec<&ReceiptStealthHint> = alice
        .payments
        .iter()
        .map(|p| p.receipt_output.receipt_stealth_hint.as_ref().unwrap())
        .collect();
    assert_ne!(hints[0], hints[1], "R1 and R2 should have different hints");
    assert_ne!(hints[0], hints[2], "R1 and R3 should have different hints");
    assert_ne!(hints[1], hints[2], "R2 and R3 should have different hints");
}

// ─── Phase B: Bob scans the chain ─────────────────────────────────────────────

#[test]
fn phase_b_bob_discovers_three_payments_by_scan() {
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();
    let chain = setup_chain(".snip_wallet_phase_b", &keychain);

    // Bob publishes his descriptor once.
    let bob_secrets = StealthReceiptSecrets::new(key(secp), key(secp));
    let mut bob_wallet = BobWallet::new(bob_secrets, secp);

    // Alice creates three payments (Bob is offline — he does not participate).
    let mut alice = AliceWallet::new(keychain.clone());
    let fee = 2;

    for i in 0..3 {
        let payment_index = (i + 1) as u32;
        let cb_input = {
            let prev = chain.head_header().unwrap();
            let height = prev.height + 1;
            let block = prepare_block(&keychain, &prev, &chain, 1, vec![], 1);
            process_block(&chain, &block);
            for _ in 0..3 {
                let p = chain.head_header().unwrap();
                let b = prepare_block(&keychain, &p, &chain, 1, vec![], 1);
                process_block(&chain, &b);
            }
            let cb_value = core::consensus::reward_at_height(height);
            let cb_id = ExtKeychainPath::new(1, height as u32, 0, 0, 0).to_identifier();
            let cb_blind = keychain
                .derive_key(cb_value, &cb_id, &SwitchCommitmentType::Regular)
                .unwrap();
            let cb_commit = keychain
                .commit(cb_value, &cb_id, &SwitchCommitmentType::Regular)
                .unwrap();
            (Input::new(OutputFeatures::Coinbase, cb_commit), cb_value, cb_blind)
        };

        let (receipt_output, funding_tx) = alice
            .create_payment(payment_index, &bob_wallet.descriptor, cb_input.0, cb_input.1, cb_input.2, fee, secp)
            .unwrap();
        let _ = receipt_output;
        mine_block_with_txs(&chain, &keychain, vec![&funding_tx], 1);
    }

    // Bob comes online and scans the chain for his payments.
    // In a real wallet, Bob would scan from block 0. Here we scan all blocks
    // after the genesis by iterating through the chain's blocks.
    //
    // For the test, we know the payment outputs from Alice's state, but Bob
    // must discover them purely from the chain data. We simulate the scan by
    // iterating over the known block heights and checking each block's
    // transactions.
    //
    // Since the test chain does not expose a "scan all blocks" API directly,
    // we use the fact that we know the block heights where payments were
    // confirmed. In a real wallet, Bob would iterate from height 0 to tip.
    //
    // For this test, we scan by checking the UTXO set: Bob iterates over all
    // unspent outputs and checks each receipt output against his secrets.
    //
    // A more realistic approach: scan blocks from height 1 to tip.
    let tip_height = chain.head_header().unwrap().height;
    for height in 1..=tip_height {
        let header_hash = chain
            .header_pmmr()
            .read()
            .get_header_hash_by_height(height)
            .unwrap();
        let block_header = chain.get_block_header(&header_hash).unwrap();
        let block = chain.get_block(&block_header.hash()).unwrap();

        for payment in bob_wallet.scan_block(&block, &chain, height, secp) {
            bob_wallet.push_payment(payment);
        }
    }

    // Assert: Bob found exactly three payments.
    assert_eq!(
        bob_wallet.payments.len(),
        3,
        "Bob should discover exactly 3 payments, found {}",
        bob_wallet.payments.len()
    );

    // Assert: all three have positive values (coinbase minus fee).
    for (i, payment) in bob_wallet.payments.iter().enumerate() {
        assert!(
            payment.receipt_value > 0,
            "R{}: receipt value should be positive, got {}",
            i + 1,
            payment.receipt_value
        );
    }

    // Assert: all three have distinct shared blinds and receipt keys.
    let q0 = bob_wallet.payments[0].shared_blind.clone();
    let q1 = bob_wallet.payments[1].shared_blind.clone();
    let q2 = bob_wallet.payments[2].shared_blind.clone();
    assert_ne!(q0, q1, "R1 and R2 should have different shared blinds");
    assert_ne!(q0, q2, "R1 and R3 should have different shared blinds");
    assert_ne!(q1, q2, "R2 and R3 should have different shared blinds");

    let b0 = bob_wallet.payments[0].bob_receipt_key.clone();
    let b1 = bob_wallet.payments[1].bob_receipt_key.clone();
    let b2 = bob_wallet.payments[2].bob_receipt_key.clone();
    assert_ne!(b0, b1, "R1 and R2 should have different receipt keys");
    assert_ne!(b0, b2, "R1 and R3 should have different receipt keys");
    assert_ne!(b1, b2, "R2 and R3 should have different receipt keys");

    // Assert: all three are unspent.
    for (i, payment) in bob_wallet.payments.iter().enumerate() {
        assert!(
            chain.is_unspent(&payment.receipt_id).is_ok(),
            "R{}: should be unspent after scan",
            i + 1
        );
    }
}

// ─── Helpers for Phases C–E and adversarial tests ────────────────────────────

/// Mine a fresh coinbase block plus maturity blocks, then return the spendable
/// coinbase input (input, value, blind).
fn matured_coinbase_input(
    chain: &epic_chain::Chain,
    keychain: &ExtKeychain,
) -> (Input, u64, SecretKey) {
    let prev = chain.head_header().unwrap();
    let height = prev.height + 1;
    let block = prepare_block(keychain, &prev, chain, 1, vec![], 1);
    process_block(chain, &block);
    for _ in 0..3 {
        let p = chain.head_header().unwrap();
        let b = prepare_block(keychain, &p, chain, 1, vec![], 1);
        process_block(chain, &b);
    }
    let cb_value = core::consensus::reward_at_height(height);
    let cb_id = ExtKeychainPath::new(1, height as u32, 0, 0, 0).to_identifier();
    let cb_blind = keychain
        .derive_key(cb_value, &cb_id, &SwitchCommitmentType::Regular)
        .unwrap();
    let cb_commit = keychain
        .commit(cb_value, &cb_id, &SwitchCommitmentType::Regular)
        .unwrap();
    (
        Input::new(OutputFeatures::Coinbase, cb_commit),
        cb_value,
        cb_blind,
    )
}

/// Fund one payment to `bob_descriptor` and mine the funding block.
fn fund_payment(
    alice: &mut AliceWallet,
    bob_descriptor: &StealthReceiptDescriptor,
    chain: &epic_chain::Chain,
    keychain: &ExtKeychain,
    payment_index: u32,
    fee: u64,
    secp: &secp::Secp256k1,
) {
    let (cb_input, cb_value, cb_blind) = matured_coinbase_input(chain, keychain);
    let (_receipt_output, funding_tx) = alice
        .create_payment(
            payment_index,
            bob_descriptor,
            cb_input,
            cb_value,
            cb_blind,
            fee,
            secp,
        )
        .unwrap();
    mine_block_with_txs(chain, keychain, vec![&funding_tx], 1);
}

/// Scan every block from height 1 to the tip, adding discoveries to Bob.
fn scan_chain(bob: &mut BobWallet, chain: &epic_chain::Chain, secp: &secp::Secp256k1) {
    let tip_height = chain.head_header().unwrap().height;
    for height in 1..=tip_height {
        let header_hash = chain
            .header_pmmr()
            .read()
            .get_header_hash_by_height(height)
            .unwrap();
        let block_header = chain.get_block_header(&header_hash).unwrap();
        let block = chain.get_block(&block_header.hash()).unwrap();
        for payment in bob.scan_block(&block, chain, height, secp) {
            bob.push_payment(payment);
        }
    }
}

/// Process a block, returning the error instead of panicking on rejection.
fn try_process_block(
    chain: &epic_chain::Chain,
    block: &core::core::Block,
) -> Result<(), String> {
    chain
        .process_block(block.clone(), epic_chain::Options::SKIP_POW)
        .map(|_| ())
        .map_err(|e| format!("{}", e))
}

/// Mine a block containing `txs`, returning the rejection error if any.
fn try_mine_block_with_txs(
    chain: &epic_chain::Chain,
    keychain: &ExtKeychain,
    txs: Vec<&Transaction>,
    key_id_branch: u8,
) -> Result<u64, String> {
    // A conflicting transaction cannot even be included in a block built on
    // the current tip: `prepare_block` applies the block to the txhashset and
    // panics on the UTXO error. Surface that same check as a Result instead.
    for tx in &txs {
        chain.validate_tx(tx).map_err(|e| format!("{}", e))?;
    }
    let previous = chain.head_header().unwrap();
    let height = previous.height + 1;
    let block = prepare_block(
        keychain,
        &previous,
        chain,
        height % 7 + 1,
        txs,
        key_id_branch,
    );
    try_process_block(chain, &block)?;
    Ok(height)
}

/// Assert that a competing spend was rejected for the expected UTXO reason.
fn assert_conflict_rejected(result: Result<u64, String>, context: &str) {
    let err = result.expect_err(context);
    let lower = err.to_lowercase();
    assert!(
        lower.contains("already spent") || lower.contains("not found"),
        "{}: unexpected rejection reason: {}",
        context,
        err
    );
}

/// Set up a chain with `payment_count` payments to a fresh Bob descriptor,
/// then scan the chain with Bob's wallet.
#[allow(clippy::type_complexity)]
fn setup_n_payments(
    chain_dir: &str,
    payment_count: u32,
) -> (
    epic_chain::Chain,
    ExtKeychain,
    AliceWallet,
    BobWallet,
    StealthReceiptSecrets,
) {
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let chain = setup_chain(chain_dir, &keychain);
    let secp = keychain.secp();
    let bob_secrets = StealthReceiptSecrets::new(key(secp), key(secp));
    let mut bob = BobWallet::new(bob_secrets.clone(), secp);
    let mut alice = AliceWallet::new(keychain.clone());

    for i in 0..payment_count {
        fund_payment(
            &mut alice,
            &bob.descriptor,
            &chain,
            &keychain,
            i + 1,
            2,
            secp,
        );
    }
    scan_chain(&mut bob, &chain, secp);

    (chain, keychain, alice, bob, bob_secrets)
}

/// Current receipt chain id from the global test-mode chain type.
fn receipt_chain_id() -> ReceiptChainId {
    let guard = global::CHAIN_TYPE.read();
    ReceiptChainId::from_chain_type(&guard)
}

// ─── Phase C: claim, reclaim, then claim again after a wallet restart ────────

#[test]
fn phase_c_claims_reclaim_and_restart() {
    let (chain, keychain, alice, bob, bob_secrets) =
        setup_n_payments(".snip_wallet_phase_c", 3);
    let secp = keychain.secp();
    assert_eq!(bob.payments.len(), 3, "setup should discover 3 payments");

    // 1. Bob claims R1.
    let claim_r1 = bob
        .build_claim(&bob.payments[0], &key(secp), 2, secp)
        .unwrap();
    claim_r1.validate(Weighting::AsTransaction).unwrap();
    mine_block_with_txs(&chain, &keychain, vec![&claim_r1], 1);
    assert!(
        chain.is_unspent(&bob.payments[0].receipt_id).is_err(),
        "R1 should be spent after Bob's claim"
    );

    // 2. Alice reclaims R2.
    let reclaim_r2 = alice
        .build_reclaim(2, &key(secp), 2, receipt_chain_id(), secp)
        .unwrap();
    reclaim_r2.validate(Weighting::AsTransaction).unwrap();
    mine_block_with_txs(&chain, &keychain, vec![&reclaim_r2], 1);
    assert!(
        chain.is_unspent(&alice.payments[1].receipt_id).is_err(),
        "R2 should be spent after Alice's reclaim"
    );

    // 3. Bob restarts from the same secrets and re-scans the chain. R1 and R2
    //    are now spent, so only R3 should be discovered.
    drop(bob);
    let mut restarted = BobWallet::new(bob_secrets, secp);
    scan_chain(&mut restarted, &chain, secp);
    assert_eq!(
        restarted.payments.len(),
        1,
        "restart should discover only R3, found {}",
        restarted.payments.len()
    );
    assert_eq!(
        restarted.payments[0].receipt_id,
        alice.payments[2].receipt_id,
        "restart should discover R3"
    );

    // Bob claims R3 with the restarted wallet.
    let claim_r3 = restarted
        .build_claim(&restarted.payments[0], &key(secp), 2, secp)
        .unwrap();
    claim_r3.validate(Weighting::AsTransaction).unwrap();
    mine_block_with_txs(&chain, &keychain, vec![&claim_r3], 1);
    assert!(
        chain.is_unspent(&restarted.payments[0].receipt_id).is_err(),
        "R3 should be spent after Bob's claim"
    );
}

// ─── Phase D: every conflicting spend after Phase C must be rejected ─────────

#[test]
fn phase_d_conflicts_rejected_after_all_spent() {
    let (chain, keychain, alice, bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_phase_d", 3);
    let secp = keychain.secp();
    assert_eq!(bob.payments.len(), 3, "setup should discover 3 payments");

    // Spend all three: Bob claims R1, Alice reclaims R2, Bob claims R3.
    let claim_r1 = bob
        .build_claim(&bob.payments[0], &key(secp), 2, secp)
        .unwrap();
    mine_block_with_txs(&chain, &keychain, vec![&claim_r1], 1);
    let reclaim_r2 = alice
        .build_reclaim(2, &key(secp), 2, receipt_chain_id(), secp)
        .unwrap();
    mine_block_with_txs(&chain, &keychain, vec![&reclaim_r2], 1);
    let claim_r3 = bob
        .build_claim(&bob.payments[2], &key(secp), 2, secp)
        .unwrap();
    mine_block_with_txs(&chain, &keychain, vec![&claim_r3], 1);

    for (i, payment) in bob.payments.iter().enumerate() {
        assert!(
            chain.is_unspent(&payment.receipt_id).is_err(),
            "R{} should be spent before the conflict checks",
            i + 1
        );
    }

    // Conflict 1: Bob claims R1 a second time.
    let claim_r1_again = bob
        .build_claim(&bob.payments[0], &key(secp), 2, secp)
        .unwrap();
    let err = chain
        .validate_tx(&claim_r1_again)
        .expect_err("Bob's second claim of R1 must be rejected");
    assert!(
        err.to_string().to_lowercase().contains("already spent"),
        "R1: unexpected error: {}",
        err
    );

    // Conflict 2: Alice reclaims R2 a second time.
    let reclaim_r2_again = alice
        .build_reclaim(2, &key(secp), 2, receipt_chain_id(), secp)
        .unwrap();
    let err = chain
        .validate_tx(&reclaim_r2_again)
        .expect_err("Alice's second reclaim of R2 must be rejected");
    assert!(
        err.to_string().to_lowercase().contains("already spent"),
        "R2: unexpected error: {}",
        err
    );

    // Conflict 3: Bob claims R3 a second time.
    let claim_r3_again = bob
        .build_claim(&bob.payments[2], &key(secp), 2, secp)
        .unwrap();
    let err = chain
        .validate_tx(&claim_r3_again)
        .expect_err("Bob's second claim of R3 must be rejected");
    assert!(
        err.to_string().to_lowercase().contains("already spent"),
        "R3: unexpected error: {}",
        err
    );

    // A full block carrying a conflicting claim is also rejected by the chain.
    assert_conflict_rejected(
        try_mine_block_with_txs(&chain, &keychain, vec![&claim_r1_again], 1),
        "block containing a second claim of R1",
    );
}

// ─── Phase E1: Bob's R4 claim confirms before Alice's reclaim ────────────────

#[test]
fn phase_e1_bob_claim_wins_r4() {
    let (chain, keychain, alice, bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_phase_e1", 4);
    let secp = keychain.secp();
    assert_eq!(bob.payments.len(), 4, "setup should discover 4 payments");

    // Build BOTH competing spends before either is confirmed.
    let bob_claim = bob
        .build_claim(&bob.payments[3], &key(secp), 2, secp)
        .unwrap();
    let alice_spend = alice
        .build_reclaim(4, &key(secp), 2, receipt_chain_id(), secp)
        .unwrap();
    bob_claim.validate(Weighting::AsTransaction).unwrap();
    alice_spend.validate(Weighting::AsTransaction).unwrap();

    // Bob's claim confirms first.
    mine_block_with_txs(&chain, &keychain, vec![&bob_claim], 1);
    assert!(
        chain.is_unspent(&bob.payments[3].receipt_id).is_err(),
        "R4 should be spent after Bob's claim"
    );

    // Alice's competing reclaim can no longer be confirmed.
    assert_conflict_rejected(
        try_mine_block_with_txs(&chain, &keychain, vec![&alice_spend], 1),
        "Alice's R4 reclaim after Bob's claim confirmed",
    );
}

// ─── Phase E2: Alice's R4 reclaim confirms before Bob's claim ────────────────

#[test]
fn phase_e2_alice_reclaim_wins_r4() {
    let (chain, keychain, alice, bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_phase_e2", 4);
    let secp = keychain.secp();
    assert_eq!(bob.payments.len(), 4, "setup should discover 4 payments");

    // Build BOTH competing spends before either is confirmed.
    let bob_claim = bob
        .build_claim(&bob.payments[3], &key(secp), 2, secp)
        .unwrap();
    let alice_spend = alice
        .build_reclaim(4, &key(secp), 2, receipt_chain_id(), secp)
        .unwrap();
    bob_claim.validate(Weighting::AsTransaction).unwrap();
    alice_spend.validate(Weighting::AsTransaction).unwrap();

    // Alice's reclaim confirms first.
    mine_block_with_txs(&chain, &keychain, vec![&alice_spend], 1);
    assert!(
        chain.is_unspent(&alice.payments[3].receipt_id).is_err(),
        "R4 should be spent after Alice's reclaim"
    );

    // Bob's competing claim can no longer be confirmed.
    assert_conflict_rejected(
        try_mine_block_with_txs(&chain, &keychain, vec![&bob_claim], 1),
        "Bob's R4 claim after Alice's reclaim confirmed",
    );
}

// ─── Adversarial: wrong descriptor discovers nothing ─────────────────────────

#[test]
fn adversarial_wrong_descriptor_scan_finds_zero() {
    let (chain, keychain, _alice, bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_adv_wrong_descriptor", 3);
    let secp = keychain.secp();
    assert_eq!(bob.payments.len(), 3, "setup should discover 3 payments");

    // A wallet with unrelated scan and receipt keys cannot recognize outputs
    // addressed to the real descriptor.
    let wrong_secrets = StealthReceiptSecrets::new(key(secp), key(secp));
    let mut wrong_bob = BobWallet::new(wrong_secrets, secp);
    scan_chain(&mut wrong_bob, &chain, secp);

    assert_eq!(
        wrong_bob.payments.len(),
        0,
        "wrong descriptor should discover no payments"
    );
}

// ─── Adversarial: a reclaim signed by the wrong Alice key is rejected ────────

#[test]
fn adversarial_wrong_alice_key_reclaim_fails() {
    let (_chain, keychain, alice, _bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_adv_wrong_alice_key", 1);
    let secp = keychain.secp();
    let payment = &alice.payments[0];
    let chain_id = receipt_chain_id();

    // A spend built with Alice's real authorization key is valid.
    let mut tx = build_alice_spend_transaction(
        &payment.receipt_output,
        payment.receipt_value,
        &payment.shared_blind,
        &payment.alice_authorization_key,
        &key(secp),
        2,
        chain_id.clone(),
        secp,
    )
    .unwrap();
    tx.validate(Weighting::AsTransaction).unwrap();

    // Replace the authorization with a well-formed signature from a different
    // a_i. Its public key is not the A_i committed by the receipt output.
    let wrong_secret = key(secp);
    let kernel = &tx.kernels()[0];
    let forged = ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        payment.receipt_output.commit,
        kernel.excess,
        kernel.features.fee(),
        kernel.hash(),
        chain_id,
        &wrong_secret,
    )
    .unwrap();
    tx.body.inputs[0].receipt_spend_authorization = Some(forged);

    assert!(
        tx.validate(Weighting::AsTransaction).is_err(),
        "a reclaim signed by the wrong a_i must be rejected"
    );
}

// ─── Adversarial: a claim signed by a forged Bob receipt key is rejected ─────

#[test]
fn adversarial_forged_bob_claim_rejected() {
    let (_chain, keychain, _alice, bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_adv_forged_bob_claim", 1);
    let secp = keychain.secp();
    let payment = &bob.payments[0];

    // Sign the receipt claim with a key that is not Bob's receipt key. The
    // builder signs successfully, but the public key does not hash to the
    // `bob` field committed by the receipt output.
    let wrong_receipt_key = key(secp);
    let tx = build_bob_claim_transaction(
        &payment.receipt_output,
        payment.receipt_value,
        &payment.shared_blind,
        &wrong_receipt_key,
        &key(secp),
        2,
        secp,
    )
    .unwrap();

    assert!(
        tx.validate(Weighting::AsTransaction).is_err(),
        "a Bob claim signed by the wrong receipt key must be rejected"
    );
}

// ─── Adversarial: a second claim of the same receipt is rejected ─────────────

#[test]
fn adversarial_double_spend_rejected() {
    let (chain, keychain, _alice, bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_adv_double_spend", 1);
    let secp = keychain.secp();
    let payment = &bob.payments[0];

    let first = bob.build_claim(payment, &key(secp), 2, secp).unwrap();
    mine_block_with_txs(&chain, &keychain, vec![&first], 1);
    assert!(
        chain.is_unspent(&payment.receipt_id).is_err(),
        "receipt should be spent after the first claim"
    );

    let second = bob.build_claim(payment, &key(secp), 2, secp).unwrap();
    assert_conflict_rejected(
        try_mine_block_with_txs(&chain, &keychain, vec![&second], 1),
        "second claim of the same receipt",
    );
}

// ─── Adversarial: reusing a payment index reuses the Alice key ───────────────

#[test]
fn adversarial_key_reuse_detected() {
    let (chain, keychain, mut alice, bob, _bob_secrets) =
        setup_n_payments(".snip_wallet_adv_key_reuse", 0);
    let secp = keychain.secp();

    // The same payment index deterministically derives the same a_i.
    let key_a = alice.derive_authorization_key(1, secp).unwrap();
    let key_b = alice.derive_authorization_key(1, secp).unwrap();
    assert_eq!(
        key_a.public_key(),
        key_b.public_key(),
        "the same seed and index must derive the same key"
    );

    // Two payments that reuse payment_index 1 commit the same A_i, so the
    // same authorization key matches both receipt outputs. This documents the
    // key-reuse hazard: payment_index must be unique per payment.
    fund_payment(&mut alice, &bob.descriptor, &chain, &keychain, 1, 2, secp);
    fund_payment(&mut alice, &bob.descriptor, &chain, &keychain, 1, 2, secp);

    let hashes_a = alice.payments[0].receipt_output.receipt_key_hashes.unwrap();
    let hashes_b = alice.payments[1].receipt_output.receipt_key_hashes.unwrap();
    let reused_pub = key_a.public_key();
    assert!(
        hashes_a.matches_alice(reused_pub),
        "reused a_i must match the first receipt output"
    );
    assert!(
        hashes_b.matches_alice(reused_pub),
        "reused a_i must match the second receipt output"
    );
    assert_ne!(
        alice.payments[0].receipt_id, alice.payments[1].receipt_id,
        "reusing a_i must still produce distinct receipt outputs"
    );
}

// ─── Adversarial: a different wallet seed derives a different key ────────────

#[test]
fn adversarial_wrong_seed_derives_different_key() {
    let keychain = ExtKeychain::from_random_seed(false).unwrap();
    let secp = keychain.secp();

    let original = AliceWallet::new(keychain.clone());
    let mut other = AliceWallet::new(keychain.clone());
    other.seed = [0xB2; 32];

    let original_key = original.derive_authorization_key(1, secp).unwrap();
    let other_key = other.derive_authorization_key(1, secp).unwrap();

    assert_ne!(
        original_key.public_key(),
        other_key.public_key(),
        "different wallet seeds must derive different authorization keys"
    );
}
