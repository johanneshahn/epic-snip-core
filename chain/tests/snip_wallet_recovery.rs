// Copyright 2026 The Epic Cash Developers
//
// Research test: reusable, recoverable SNIP wallet library on local Usernet.
// Exercises deterministic seed recovery, persistence, duplicate-safe scanning,
// reorg reconciliation, and double-spend rejection.

mod chain_test_helper;

use std::path::{Path, PathBuf};

use crate::chain_test_helper::{
    clean_output_dir, init_chain, prepare_block, process_block, set_foundation_path_for_test,
};
use epic_core as core;
use epic_core::core::hash::Hashed;
use epic_core::core::receipt_claim::{ReceiptChainId, StealthReceiptDescriptor};
use epic_core::core::{Block, Input, OutputIdentifier, Transaction};
use epic_core::global::{self, ChainTypes};
use epic_core::pow;
use epic_keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use epic_snip_wallet::{
    ChainView, ChainViewError, Direction, PaymentStatus, ScanMode, SnipError, SnipWallet,
    ROLE_ALICE, ROLE_BOB,
};
use epic_util as util;
use util::secp::key::SecretKey;

// ─── Chain adapter ───────────────────────────────────────────────────────────

struct TestChain<'a> {
    chain: &'a epic_chain::Chain,
}

impl<'a> ChainView for TestChain<'a> {
    fn tip_height(&self) -> u64 {
        self.chain.head_header().unwrap().height
    }

    fn block_at_height(&self, height: u64) -> Option<Block> {
        let hash = self
            .chain
            .header_pmmr()
            .read()
            .get_header_hash_by_height(height)
            .ok()?;
        let header = self.chain.get_block_header(&hash).ok()?;
        self.chain.get_block(&header.hash()).ok()
    }

    fn block_hash_at_height(&self, height: u64) -> Option<String> {
        let hash = self
            .chain
            .header_pmmr()
            .read()
            .get_header_hash_by_height(height)
            .ok()?;
        Some(util::to_hex(hash.as_bytes().to_vec()))
    }

    fn is_unspent(&self, id: &OutputIdentifier) -> Result<(), ChainViewError> {
        match self.chain.is_unspent(id) {
            Ok(_) => Ok(()),
            Err(e) => {
                let message = format!("{}", e).to_lowercase();
                if message.contains("not found") || message.contains("already spent") {
                    Err(ChainViewError::NotFound)
                } else {
                    Err(ChainViewError::Other(message))
                }
            }
        }
    }
}

// ─── Chain and wallet helpers ────────────────────────────────────────────────

fn keychain(seed: u8) -> ExtKeychain {
    ExtKeychain::from_seed(&[seed; 32], false).unwrap()
}

fn setup_chain(chain_dir: &str, miner: &ExtKeychain) -> epic_chain::Chain {
    util::init_test_logger();
    clean_output_dir(chain_dir);
    set_foundation_path_for_test("foundation_floonet.json");
    global::set_mining_mode(ChainTypes::AutomatedTesting);
    let genesis = pow::mine_genesis_block().unwrap();
    let chain = init_chain(chain_dir, genesis);
    for n in 1..=4 {
        let previous = chain.head_header().unwrap();
        let block = prepare_block(miner, &previous, &chain, n, vec![], 1);
        process_block(&chain, &block);
    }
    chain
}

fn matured_coinbase_input(
    chain: &epic_chain::Chain,
    miner: &ExtKeychain,
) -> (Input, u64, SecretKey) {
    let prev = chain.head_header().unwrap();
    let height = prev.height + 1;
    let block = prepare_block(miner, &prev, chain, 1, vec![], 1);
    process_block(chain, &block);
    for _ in 0..3 {
        let p = chain.head_header().unwrap();
        let b = prepare_block(miner, &p, chain, 1, vec![], 1);
        process_block(chain, &b);
    }
    let value = core::consensus::reward_at_height(height);
    let id = ExtKeychainPath::new(1, height as u32, 0, 0, 0).to_identifier();
    let blind = miner
        .derive_key(value, &id, &SwitchCommitmentType::Regular)
        .unwrap();
    let commit = miner
        .commit(value, &id, &SwitchCommitmentType::Regular)
        .unwrap();
    (
        Input::new(core::core::OutputFeatures::Coinbase, commit),
        value,
        blind,
    )
}

fn mine_block_with_txs(
    chain: &epic_chain::Chain,
    miner: &ExtKeychain,
    txs: Vec<&Transaction>,
    branch: u8,
) -> u64 {
    let previous = chain.head_header().unwrap();
    let height = previous.height + 1;
    let block = prepare_block(miner, &previous, chain, height % 7 + 1, txs, branch);
    process_block(chain, &block);
    height
}

fn try_mine_block_with_txs(
    chain: &epic_chain::Chain,
    miner: &ExtKeychain,
    txs: Vec<&Transaction>,
    branch: u8,
) -> Result<u64, String> {
    for tx in &txs {
        chain.validate_tx(tx).map_err(|e| format!("{}", e))?;
    }
    Ok(mine_block_with_txs(chain, miner, txs, branch))
}

fn wallet_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

fn open_wallet(seed: u8, path: impl Into<PathBuf>) -> SnipWallet {
    SnipWallet::open(keychain(seed), path).unwrap()
}

fn receipt_chain_id() -> ReceiptChainId {
    let guard = global::CHAIN_TYPE.read();
    ReceiptChainId::from_chain_type(&guard)
}

fn fund_payment(
    chain: &epic_chain::Chain,
    miner: &ExtKeychain,
    alice: &mut SnipWallet,
    descriptor: &StealthReceiptDescriptor,
    fee: u64,
) -> epic_snip_wallet::CreatedPayment {
    let (input, value, blind) = matured_coinbase_input(chain, miner);
    let created = alice
        .create_payment(descriptor, input, value, &blind, fee)
        .unwrap();
    mine_block_with_txs(chain, miner, vec![&created.funding_tx], 1);
    created
}

fn incoming_records(wallet: &SnipWallet) -> Vec<&epic_snip_wallet::PaymentRecord> {
    wallet
        .store()
        .records()
        .filter(|record| record.direction == Direction::Incoming)
        .collect()
}

fn outgoing_records(wallet: &SnipWallet) -> Vec<&epic_snip_wallet::PaymentRecord> {
    wallet
        .store()
        .records()
        .filter(|record| record.direction == Direction::Outgoing)
        .collect()
}

// ─── Descriptor stability ────────────────────────────────────────────────────

#[test]
fn bob_descriptor_stable_across_restart_and_seed_restore() {
    let dir = tempfile::tempdir().unwrap();
    let first = open_wallet(0xB0, wallet_path(dir.path(), "first.json"));
    let descriptor = first.create_descriptor().unwrap();
    drop(first);

    let restarted = open_wallet(0xB0, wallet_path(dir.path(), "first.json"));
    assert_eq!(restarted.create_descriptor().unwrap().scan_public_key, descriptor.scan_public_key);
    assert_eq!(
        restarted.create_descriptor().unwrap().receipt_spend_public_key,
        descriptor.receipt_spend_public_key
    );

    let restored = open_wallet(0xB0, wallet_path(dir.path(), "restored.json"));
    assert_eq!(
        restored.create_descriptor().unwrap().scan_public_key,
        descriptor.scan_public_key
    );

    let wrong = open_wallet(0xB1, wallet_path(dir.path(), "wrong.json"));
    assert_ne!(
        wrong.create_descriptor().unwrap().scan_public_key,
        descriptor.scan_public_key
    );
}

// ─── Bob: seed restoration, discovery, and claim ─────────────────────────────

#[test]
fn bob_discovers_three_payments_after_seed_restore() {
    let dir = tempfile::tempdir().unwrap();
    let alice_kc = keychain(0xA1);
    let chain = setup_chain(".snip_wallet_recovery_bob_scan", &alice_kc);
    let view = TestChain { chain: &chain };

    let bob = open_wallet(0xB0, wallet_path(dir.path(), "bob_original.json"));
    let descriptor = bob.create_descriptor().unwrap();
    drop(bob);

    let mut alice = open_wallet(0xA1, wallet_path(dir.path(), "alice.json"));
    for _ in 0..3 {
        fund_payment(&chain, &alice_kc, &mut alice, &descriptor, 2);
    }

    let mut restored = open_wallet(0xB0, wallet_path(dir.path(), "bob_restored.json"));
    let report = restored.restore_wallet_state(&view, None).unwrap();
    assert_eq!(report.incoming_found, 3);
    assert_eq!(report.outgoing_found, 0);
    assert!(!report.descriptor_required);

    let records = incoming_records(&restored);
    assert_eq!(records.len(), 3);
    for record in &records {
        assert!(record.amount > 0);
        assert!(record.amount_known);
        assert!(record.reclaimable);
        assert_eq!(record.status, PaymentStatus::Confirmed);
        assert!(record.confirmation_height.is_some());
    }

    // Duplicate scan protection: a second pass finds no new records.
    let second = restored.scan_incoming(&view, 0, view.tip_height()).unwrap();
    assert_eq!(second.new_records, 0);
    assert!(second.duplicates >= 3);
    assert_eq!(incoming_records(&restored).len(), 3);
}

#[test]
fn bob_claims_unspent_receipt_after_restore() {
    let dir = tempfile::tempdir().unwrap();
    let alice_kc = keychain(0xA1);
    let chain = setup_chain(".snip_wallet_recovery_bob_claim", &alice_kc);
    let view = TestChain { chain: &chain };

    let bob = open_wallet(0xB0, wallet_path(dir.path(), "bob_original.json"));
    let descriptor = bob.create_descriptor().unwrap();
    drop(bob);

    let mut alice = open_wallet(0xA1, wallet_path(dir.path(), "alice.json"));
    fund_payment(&chain, &alice_kc, &mut alice, &descriptor, 2);

    let mut restored = open_wallet(0xB0, wallet_path(dir.path(), "bob_restored.json"));
    restored.restore_wallet_state(&view, None).unwrap();
    let records = incoming_records(&restored);
    assert_eq!(records.len(), 1);
    let record = records[0].clone();
    assert_eq!(record.status, PaymentStatus::Confirmed);

    let destination = restored.destination_blind(ROLE_BOB, 0).unwrap();
    let claim = restored
        .build_bob_claim(&record.payment_id, &destination, 2)
        .unwrap();
    mine_block_with_txs(&chain, &alice_kc, vec![&claim], 1);

    assert!(chain.is_unspent(&record.identifier().unwrap()).is_err());
    let refresh = restored.refresh_payment_states(&view).unwrap();
    assert_eq!(refresh.spent, 1);
    let after = restored
        .store()
        .get(&format!("incoming:{}", record.payment_id))
        .unwrap();
    assert_eq!(after.status, PaymentStatus::Spent);
}

// ─── Alice: persistence, restart reclaim, seed-only recovery ─────────────────

fn setup_alice_payments(
    chain_dir: &str,
    count: usize,
    alice_store: &Path,
) -> (epic_chain::Chain, ExtKeychain, StealthReceiptDescriptor, SnipWallet) {
    let alice_kc = keychain(0xA1);
    let chain = setup_chain(chain_dir, &alice_kc);
    let bob_kc = keychain(0xB0);
    let descriptor = epic_snip_wallet::bob_secrets(&bob_kc)
        .unwrap()
        .descriptor(bob_kc.secp())
        .unwrap();
    let mut alice = open_wallet(0xA1, alice_store);
    for _ in 0..count {
        fund_payment(&chain, &alice_kc, &mut alice, &descriptor, 2);
    }
    (chain, alice_kc, descriptor, alice)
}

#[test]
fn alice_payment_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("alice.json");
    let (_chain, _alice_kc, _descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_alice_persist", 2, &store);
    let before: Vec<(String, u32, u64)> = outgoing_records(&alice)
        .iter()
        .map(|record| {
            (
                record.payment_id.clone(),
                record.payment_index.unwrap(),
                record.amount,
            )
        })
        .collect();
    assert_eq!(before.len(), 2);
    drop(alice);

    let restarted = open_wallet(0xA1, &store);
    let after: Vec<(String, u32, u64)> = outgoing_records(&restarted)
        .iter()
        .map(|record| {
            (
                record.payment_id.clone(),
                record.payment_index.unwrap(),
                record.amount,
            )
        })
        .collect();
    assert_eq!(before, after);
    assert_eq!(restarted.store().state().next_payment_index, 2);
}

#[test]
fn alice_reclaim_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("alice.json");
    let (chain, alice_kc, _descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_alice_reclaim", 1, &store);
    let view = TestChain { chain: &chain };
    let record = outgoing_records(&alice)[0].clone();
    drop(alice);

    let restarted = open_wallet(0xA1, &store);
    let destination = restarted
        .destination_blind(ROLE_ALICE, record.payment_index.unwrap())
        .unwrap();
    let reclaim = restarted
        .build_alice_reclaim(
            &record.payment_id,
            None,
            &destination,
            2,
            receipt_chain_id(),
        )
        .unwrap();
    mine_block_with_txs(&chain, &alice_kc, vec![&reclaim], 1);

    assert!(chain.is_unspent(&record.identifier().unwrap()).is_err());
    let mut restarted = restarted;
    let refresh = restarted.refresh_payment_states(&view).unwrap();
    assert_eq!(refresh.spent, 1);
}

#[test]
fn alice_seed_only_recovery_with_empty_db() {
    let dir = tempfile::tempdir().unwrap();
    let original_store = dir.path().join("alice_original.json");
    let (chain, alice_kc, descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_alice_seed", 3, &original_store);
    let view = TestChain { chain: &chain };
    let mut original_indices: Vec<u32> = outgoing_records(&alice)
        .iter()
        .map(|record| record.payment_index.unwrap())
        .collect();
    original_indices.sort_unstable();
    drop(alice);

    let empty_store = dir.path().join("alice_restored.json");
    assert!(!empty_store.exists());
    let mut restored = open_wallet(0xA1, &empty_store);
    let report = restored
        .restore_wallet_state(&view, Some(&descriptor))
        .unwrap();
    assert_eq!(report.outgoing_found, 3);
    assert!(!report.descriptor_required);
    assert!(report.next_payment_index >= 3);

    let records = outgoing_records(&restored);
    assert_eq!(records.len(), 3);
    let mut recovered_indices: Vec<u32> = records
        .iter()
        .map(|record| record.payment_index.unwrap())
        .collect();
    recovered_indices.sort_unstable();
    assert_eq!(recovered_indices, original_indices);
    for record in &records {
        assert!(record.amount_known);
        assert!(record.reclaimable);
        assert!(record.amount > 0);
    }

    let record = records[0].clone();
    let destination = restored
        .destination_blind(ROLE_ALICE, record.payment_index.unwrap())
        .unwrap();
    let reclaim = restored
        .build_alice_reclaim(
            &record.payment_id,
            Some(&descriptor),
            &destination,
            2,
            receipt_chain_id(),
        )
        .unwrap();
    mine_block_with_txs(&chain, &alice_kc, vec![&reclaim], 1);
    assert!(chain.is_unspent(&record.identifier().unwrap()).is_err());
}

#[test]
fn alice_seed_restore_with_public_backup() {
    let dir = tempfile::tempdir().unwrap();
    let original_store = dir.path().join("alice_original.json");
    let (chain, alice_kc, descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_alice_backup", 2, &original_store);
    let view = TestChain { chain: &chain };
    let watermark = alice.store().state().next_payment_index;
    assert_eq!(watermark, 2);
    drop(alice);

    // Public backup: descriptor and index watermark only, no private keys.
    let backup_store = dir.path().join("alice_backup.json");
    let mut restored = open_wallet(0xA1, &backup_store);
    restored.register_descriptor(&descriptor).unwrap();
    restored
        .store_mut()
        .bump_next_payment_index(watermark)
        .unwrap();
    let report = restored
        .restore_wallet_state(&view, Some(&descriptor))
        .unwrap();
    assert_eq!(report.outgoing_found, 2);
    assert!(report.next_payment_index >= watermark);

    let record = outgoing_records(&restored)[0].clone();
    let destination = restored
        .destination_blind(ROLE_ALICE, record.payment_index.unwrap())
        .unwrap();
    let reclaim = restored
        .build_alice_reclaim(
            &record.payment_id,
            None,
            &destination,
            2,
            receipt_chain_id(),
        )
        .unwrap();
    mine_block_with_txs(&chain, &alice_kc, vec![&reclaim], 1);
    assert!(chain.is_unspent(&record.identifier().unwrap()).is_err());
}

#[test]
fn alice_seed_only_without_descriptor_limitation() {
    let dir = tempfile::tempdir().unwrap();
    let original_store = dir.path().join("alice_original.json");
    let (chain, _alice_kc, _descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_alice_limitation", 3, &original_store);
    let view = TestChain { chain: &chain };
    drop(alice);

    let empty_store = dir.path().join("alice_restored.json");
    let mut restored = open_wallet(0xA1, &empty_store);
    let report = restored.restore_wallet_state(&view, None).unwrap();
    assert_eq!(report.outgoing_found, 3);
    assert!(report.descriptor_required);

    let records = outgoing_records(&restored);
    assert_eq!(records.len(), 3);
    for record in &records {
        assert!(!record.amount_known);
        assert!(!record.reclaimable);
        assert!(record.descriptor_id.is_none());
    }

    let record = records[0].clone();
    let destination = restored
        .destination_blind(ROLE_ALICE, record.payment_index.unwrap())
        .unwrap();
    let error = restored
        .build_alice_reclaim(
            &record.payment_id,
            None,
            &destination,
            2,
            receipt_chain_id(),
        )
        .unwrap_err();
    assert!(matches!(error, SnipError::DescriptorRequired));
}

// ─── Wrong seed, key reuse, duplicate scans ──────────────────────────────────

#[test]
fn privacy_audit_descriptor_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let alice_kc = keychain(0xA1);
    let chain = setup_chain(".snip_wallet_recovery_privacy_audit", &alice_kc);
    let view = TestChain { chain: &chain };

    // Two different Bobs with different descriptors.
    let bob_a_kc = keychain(0xB0);
    let bob_b_kc = keychain(0xB1);
    let desc_a = epic_snip_wallet::bob_secrets(&bob_a_kc)
        .unwrap()
        .descriptor(bob_a_kc.secp())
        .unwrap();
    let desc_b = epic_snip_wallet::bob_secrets(&bob_b_kc)
        .unwrap()
        .descriptor(bob_b_kc.secp())
        .unwrap();

    // Alice creates 3 Receipts to Bob A and 3 to Bob B.
    let mut alice = open_wallet(0xA1, dir.path().join("alice.json"));
    for _ in 0..3 {
        fund_payment(&chain, &alice_kc, &mut alice, &desc_a, 2);
    }
    for _ in 0..3 {
        fund_payment(&chain, &alice_kc, &mut alice, &desc_b, 2);
    }

    // Collect public Receipt output fields from the chain.
    let mut receipt_fields: Vec<(String, String, String, String)> = Vec::new();
    for height in 0..=view.tip_height() {
        if let Some(block) = view.block_at_height(height) {
            for output in block.outputs() {
                if output.features.is_receipt() {
                    let commit = epic_util::to_hex(output.commit.0.to_vec());
                    let hint = output
                        .receipt_stealth_hint
                        .map(|h| epic_util::to_hex(h.ephemeral_public_key.to_vec()))
                        .unwrap_or_default();
                    let bob_hash = output
                        .receipt_key_hashes
                        .map(|h| epic_util::to_hex(h.bob.to_vec()))
                        .unwrap_or_default();
                    let alice_hash = output
                        .receipt_key_hashes
                        .map(|h| epic_util::to_hex(h.alice.to_vec()))
                        .unwrap_or_default();
                    receipt_fields.push((commit, hint, bob_hash, alice_hash));
                }
            }
        }
    }

    // Verify: no two Receipts share the same hint (ephemeral key).
    let mut hints: Vec<&String> = receipt_fields.iter().map(|r| &r.1).collect();
    hints.sort();
    for i in 1..hints.len() {
        assert_ne!(hints[i - 1], hints[i], "duplicate hint found");
    }

    // Verify: no two Receipts share the same bob hash.
    let mut bob_hashes: Vec<&String> = receipt_fields.iter().map(|r| &r.2).collect();
    bob_hashes.sort();
    for i in 1..bob_hashes.len() {
        assert_ne!(bob_hashes[i - 1], bob_hashes[i], "duplicate bob hash found");
    }

    // Verify: no two Receipts share the same commit.
    let mut commits: Vec<&String> = receipt_fields.iter().map(|r| &r.0).collect();
    commits.sort();
    for i in 1..commits.len() {
        assert_ne!(commits[i - 1], commits[i], "duplicate commit found");
    }

    // Verify: total count is 6 (3 to A + 3 to B).
    assert_eq!(receipt_fields.len(), 6);

    // Bob A claims 2 Receipts, Bob B claims 1.
    let view = TestChain { chain: &chain };
    let mut bob_a = open_wallet(0xB0, dir.path().join("bob_a.json"));
    bob_a.register_descriptor(&desc_a).unwrap();
    bob_a.scan_incoming(&view, 0, view.tip_height()).unwrap();
    assert_eq!(incoming_records(&bob_a).len(), 3);

    let mut bob_b = open_wallet(0xB1, dir.path().join("bob_b.json"));
    bob_b.register_descriptor(&desc_b).unwrap();
    bob_b.scan_incoming(&view, 0, view.tip_height()).unwrap();
    assert_eq!(incoming_records(&bob_b).len(), 3);

    // Claim by Bob A.
    let rec_a0 = incoming_records(&bob_a)[0].clone();
    let dest_a = bob_a.destination_blind(ROLE_BOB, 0).unwrap();
    let claim_a0 = bob_a
        .build_bob_claim(&rec_a0.payment_id, &dest_a, 2)
        .unwrap();
    mine_block_with_txs(&chain, &alice_kc, vec![&claim_a0], 1);

    // Claim by Bob B.
    let rec_b0 = incoming_records(&bob_b)[0].clone();
    let dest_b = bob_b.destination_blind(ROLE_BOB, 0).unwrap();
    let claim_b0 = bob_b
        .build_bob_claim(&rec_b0.payment_id, &dest_b, 2)
        .unwrap();
    mine_block_with_txs(&chain, &alice_kc, vec![&claim_b0], 1);

    // Now verify: after claims, the BobClaim public keys are all distinct.
    let mut claim_pubkeys: Vec<String> = Vec::new();
    for height in 0..=view.tip_height() {
        if let Some(block) = view.block_at_height(height) {
            // Access kernels through the block's transactions.
            // We check the block's transaction kernels.
            for kernel in block.kernels() {
                if let Some(claim) = &kernel.receipt_claim {
                    let secp = epic_util::secp::Secp256k1::with_caps(epic_util::secp::ContextFlag::Commit);
                    claim_pubkeys.push(epic_util::to_hex(
                        claim.receipt_public_key.serialize_vec(&secp, true).to_vec(),
                    ));
                }
            }
        }
    }
    // Verify all claim pubkeys are distinct.
    let mut sorted_pk = claim_pubkeys.clone();
    sorted_pk.sort();
    for i in 1..sorted_pk.len() {
        assert_ne!(sorted_pk[i - 1], sorted_pk[i], "duplicate claim pubkey found");
    }
    // We should have 2 claims.
    assert_eq!(claim_pubkeys.len(), 2);
}

#[test]
fn adapter_smoke_test() {
    let dir = tempfile::tempdir().unwrap();
    let alice_kc = keychain(0xA1);
    let chain = setup_chain(".snip_wallet_recovery_adapter", &alice_kc);
    let view = epic_chain::snip::SnipChainView { chain: &chain };

    let mut wallet = open_wallet(0xA1, dir.path().join("wallet.json"));
    let descriptor = wallet.create_descriptor().unwrap();
    fund_payment(&chain, &alice_kc, &mut wallet, &descriptor, 1);

    let mut restored = open_wallet(0xA1, dir.path().join("restored.json"));
    let report = restored
        .restore_wallet_state(&view, Some(&descriptor))
        .unwrap();
    assert_eq!(report.outgoing_found, 1);
    assert_eq!(report.incoming_found, 1);
}

#[test]
fn wrong_seed_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("alice.json");
    let (chain, _alice_kc, descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_wrong_seed", 2, &store);
    let view = TestChain { chain: &chain };
    drop(alice);

    let mut wrong_bob = open_wallet(0xB1, dir.path().join("wrong_bob.json"));
    let report = wrong_bob
        .scan_incoming(&view, 0, view.tip_height())
        .unwrap();
    assert_eq!(report.incoming, 0);
    assert_eq!(incoming_records(&wrong_bob).len(), 0);

    let mut wrong_alice = open_wallet(0xA2, dir.path().join("wrong_alice.json"));
    let report = wrong_alice
        .scan_outgoing(&view, &descriptor, 0, view.tip_height(), 100)
        .unwrap();
    assert_eq!(report.outgoing, 0);
    assert_eq!(outgoing_records(&wrong_alice).len(), 0);
}

#[test]
fn no_key_reuse_across_payments_or_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("alice.json");
    let (chain, alice_kc, descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_key_reuse", 2, &store);
    drop(alice);

    let mut restarted = open_wallet(0xA1, &store);
    assert_eq!(restarted.store().state().next_payment_index, 2);
    for _ in 0..2 {
        fund_payment(&chain, &alice_kc, &mut restarted, &descriptor, 2);
    }
    assert_eq!(restarted.store().state().next_payment_index, 4);

    let mut indices: Vec<u32> = outgoing_records(&restarted)
        .iter()
        .map(|record| record.payment_index.unwrap())
        .collect();
    indices.sort_unstable();
    assert_eq!(indices, vec![0, 1, 2, 3]);

    let mut authorization_keys = Vec::new();
    let mut ephemeral_keys = Vec::new();
    let mut destination_keys = Vec::new();
    for index in 0..4 {
        authorization_keys.push(
            restarted
                .alice_authorization_key(index)
                .unwrap()
                .secret_key()
                .0,
        );
        ephemeral_keys.push(restarted.alice_ephemeral_secret(index).unwrap().0);
        destination_keys.push(
            restarted
                .destination_blind(ROLE_ALICE, index)
                .unwrap()
                .0,
        );
    }
    assert_eq!(
        authorization_keys
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        ephemeral_keys
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        destination_keys
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
}

#[test]
fn scan_receipts_dispatcher_finds_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let alice_kc = keychain(0xA1);
    let chain = setup_chain(".snip_wallet_recovery_dispatcher", &alice_kc);
    let view = TestChain { chain: &chain };

    let mut sender = open_wallet(0xA1, dir.path().join("sender.json"));
    let descriptor = sender.create_descriptor().unwrap();
    fund_payment(&chain, &alice_kc, &mut sender, &descriptor, 2);

    // A fresh wallet with the same seed restores both directions from chain.
    let mut restored = open_wallet(0xA1, dir.path().join("restored.json"));
    let report = restored
        .scan_receipts(
            &view,
            0,
            view.tip_height(),
            ScanMode::Both,
            Some(&descriptor),
            100,
        )
        .unwrap();
    assert_eq!(report.incoming, 1);
    assert_eq!(report.outgoing, 1);
    assert_eq!(incoming_records(&restored).len(), 1);
    assert_eq!(outgoing_records(&restored).len(), 1);
}

#[test]
fn duplicate_scan_protection() {
    let dir = tempfile::tempdir().unwrap();
    let bob = open_wallet(0xB0, dir.path().join("bob.json"));
    let descriptor = bob.create_descriptor().unwrap();
    drop(bob);

    let alice_kc = keychain(0xA1);
    let chain = setup_chain(".snip_wallet_recovery_duplicate_scan", &alice_kc);
    let view = TestChain { chain: &chain };
    let mut alice = open_wallet(0xA1, dir.path().join("alice.json"));
    for _ in 0..3 {
        fund_payment(&chain, &alice_kc, &mut alice, &descriptor, 2);
    }

    let mut bob = open_wallet(0xB0, dir.path().join("bob_scan.json"));
    let first = bob.scan_incoming(&view, 0, view.tip_height()).unwrap();
    assert_eq!(first.new_records, 3);
    let height = incoming_records(&bob)[0].confirmation_height.unwrap();

    let second = bob.scan_incoming(&view, height, height).unwrap();
    assert_eq!(second.new_records, 0);
    assert!(second.duplicates >= 1);
    let third = bob.scan_incoming(&view, 0, view.tip_height()).unwrap();
    assert_eq!(third.new_records, 0);
    assert!(third.duplicates >= 3);
    assert_eq!(incoming_records(&bob).len(), 3);
}

// ─── Double spend and reorg ──────────────────────────────────────────────────

#[test]
fn double_spend_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("alice.json");
    let (chain, alice_kc, descriptor, alice) =
        setup_alice_payments(".snip_wallet_recovery_double_spend", 1, &store);
    let view = TestChain { chain: &chain };
    let alice_record = outgoing_records(&alice)[0].clone();

    let mut bob = open_wallet(0xB0, dir.path().join("bob.json"));
    bob.scan_incoming(&view, 0, view.tip_height()).unwrap();
    let bob_record = incoming_records(&bob)[0].clone();

    let bob_destination = bob.destination_blind(ROLE_BOB, 0).unwrap();
    let alice_destination = alice
        .destination_blind(ROLE_ALICE, alice_record.payment_index.unwrap())
        .unwrap();
    let bob_claim = bob
        .build_bob_claim(&bob_record.payment_id, &bob_destination, 2)
        .unwrap();
    let alice_reclaim = alice
        .build_alice_reclaim(
            &alice_record.payment_id,
            Some(&descriptor),
            &alice_destination,
            2,
            receipt_chain_id(),
        )
        .unwrap();

    mine_block_with_txs(&chain, &alice_kc, vec![&bob_claim], 1);

    let result = try_mine_block_with_txs(&chain, &alice_kc, vec![&alice_reclaim], 2);
    let error = result.expect_err("Alice reclaim must be rejected after Bob's claim");
    let lower = error.to_lowercase();
    assert!(
        lower.contains("not found") || lower.contains("already spent"),
        "unexpected rejection: {}",
        error
    );

    let second_destination = bob.destination_blind(ROLE_BOB, 1).unwrap();
    let second_bob = bob
        .build_bob_claim(&bob_record.payment_id, &second_destination, 2)
        .unwrap();
    let result = try_mine_block_with_txs(&chain, &alice_kc, vec![&second_bob], 2);
    let error = result.expect_err("a second Bob claim must be rejected");
    let lower = error.to_lowercase();
    assert!(
        lower.contains("not found") || lower.contains("already spent"),
        "unexpected rejection: {}",
        error
    );
}

#[test]
fn payment_state_updates_after_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let alice_kc = keychain(0xA1);
    let chain = setup_chain(".snip_wallet_recovery_reorg", &alice_kc);
    let bob_kc = keychain(0xB0);
    let descriptor = epic_snip_wallet::bob_secrets(&bob_kc)
        .unwrap()
        .descriptor(bob_kc.secp())
        .unwrap();
    let mut alice = open_wallet(0xA1, dir.path().join("alice.json"));
    let created = fund_payment(&chain, &alice_kc, &mut alice, &descriptor, 2);
    let funding_height = chain.head_header().unwrap().height;

    let view = TestChain { chain: &chain };
    let mut bob = open_wallet(0xB0, dir.path().join("bob.json"));
    bob.scan_incoming(&view, 0, view.tip_height()).unwrap();
    let record = incoming_records(&bob)[0].clone();
    assert_eq!(record.confirmation_height, Some(funding_height));
    assert_eq!(record.status, PaymentStatus::Confirmed);

    let head = chain.head_header().unwrap();
    let reorg_difficulty: u64 = head
        .total_difficulty()
        .num
        .iter()
        .map(|(_, &i)| i)
        .sum();
    let fork_head = chain.get_header_by_height(funding_height - 1).unwrap();
    let reorg_block = prepare_block(
        &alice_kc,
        &fork_head,
        &chain,
        reorg_difficulty,
        vec![],
        2,
    );
    let reorg_hash = reorg_block.hash();
    process_block(&chain, &reorg_block);
    assert_eq!(chain.head_header().unwrap().hash(), reorg_hash);
    assert_eq!(chain.head_header().unwrap().height, funding_height);
    assert!(chain.is_unspent(&record.identifier().unwrap()).is_err());

    let refresh = bob.refresh_payment_states(&view).unwrap();
    assert!(refresh.reorg_detected);
    assert_eq!(refresh.orphaned, 1);
    let orphaned = bob
        .store()
        .get(&format!("incoming:{}", record.payment_id))
        .unwrap();
    assert_eq!(orphaned.status, PaymentStatus::Orphaned);

    let new_head = chain.head_header().unwrap();
    let reinclude = prepare_block(
        &alice_kc,
        &new_head,
        &chain,
        1,
        vec![&created.funding_tx],
        1,
    );
    process_block(&chain, &reinclude);
    assert_eq!(chain.head_header().unwrap().height, funding_height + 1);

    bob.scan_incoming(&view, 0, view.tip_height()).unwrap();
    let confirmed = bob
        .store()
        .get(&format!("incoming:{}", record.payment_id))
        .unwrap();
    assert_eq!(confirmed.status, PaymentStatus::Confirmed);
    assert_eq!(confirmed.confirmation_height, Some(funding_height + 1));
    let refresh = bob.refresh_payment_states(&view).unwrap();
    assert_eq!(refresh.confirmed, 1);
}
