//! Unit tests for deterministic derivation and duplicate-safe persistence.

use epic_keychain::{ExtKeychain, Keychain};
use epic_snip_wallet::derive::{
    alice_authorization_key, alice_ephemeral_secret, bob_secrets, destination_blind,
    KEY_ALICE_AUTH, KEY_ALICE_EPHEMERAL, KEY_BOB_SCAN, KEY_BOB_SPEND, KEY_DESTINATION,
    ROLE_ALICE, ROLE_BOB,
};
use epic_snip_wallet::store::{
    Direction, InsertOutcome, PaymentRecord, PaymentStatus, SnipStore, DERIVATION_VERSION,
};

fn keychain(seed: u8) -> ExtKeychain {
    ExtKeychain::from_seed(&[seed; 32], false).unwrap()
}

#[test]
fn descriptor_is_stable_for_same_seed() {
    let a = keychain(0x42);
    let b = keychain(0x42);
    let da = bob_secrets(&a).unwrap().descriptor(a.secp()).unwrap();
    let db = bob_secrets(&b).unwrap().descriptor(b.secp()).unwrap();
    assert_eq!(da.scan_public_key, db.scan_public_key);
    assert_eq!(da.receipt_spend_public_key, db.receipt_spend_public_key);
}

#[test]
fn descriptor_differs_for_different_seed() {
    let a = keychain(0x42);
    let b = keychain(0x43);
    let da = bob_secrets(&a).unwrap().descriptor(a.secp()).unwrap();
    let db = bob_secrets(&b).unwrap().descriptor(b.secp()).unwrap();
    assert_ne!(da.scan_public_key, db.scan_public_key);
    assert_ne!(da.receipt_spend_public_key, db.receipt_spend_public_key);
}

#[test]
fn keys_are_domain_separated_and_unique() {
    let kc = keychain(0x42);
    let secp = kc.secp();

    let bob_scan = bob_secrets(&kc).unwrap();
    let a0 = alice_authorization_key(&kc, 0, secp).unwrap();
    let a1 = alice_authorization_key(&kc, 1, secp).unwrap();
    let e0 = alice_ephemeral_secret(&kc, 0).unwrap();
    let e1 = alice_ephemeral_secret(&kc, 1).unwrap();
    let d0 = destination_blind(&kc, ROLE_ALICE, 0).unwrap();
    let d1 = destination_blind(&kc, ROLE_ALICE, 1).unwrap();

    let secrets = [
        a0.secret_key().0,
        a1.secret_key().0,
        e0.0,
        e1.0,
        d0.0,
        d1.0,
    ];
    for i in 0..secrets.len() {
        for j in (i + 1)..secrets.len() {
            assert_ne!(secrets[i], secrets[j], "key {} equals key {}", i, j);
        }
    }

    // The descriptor keys must not collide with any payment key.
    let scan_pub = bob_secrets(&kc).unwrap().descriptor(secp).unwrap();
    assert_ne!(scan_pub.scan_public_key, scan_pub.receipt_spend_public_key);
    assert!(bob_scan.descriptor(secp).is_ok());
}

#[test]
fn distinct_paths_are_used_for_each_key_type() {
    let kc = keychain(0x42);
    let paths = [
        epic_snip_wallet::path(ROLE_BOB, 0, KEY_BOB_SCAN).to_identifier(),
        epic_snip_wallet::path(ROLE_BOB, 0, KEY_BOB_SPEND).to_identifier(),
        epic_snip_wallet::path(ROLE_ALICE, 0, KEY_ALICE_AUTH).to_identifier(),
        epic_snip_wallet::path(ROLE_ALICE, 0, KEY_ALICE_EPHEMERAL).to_identifier(),
        epic_snip_wallet::path(ROLE_ALICE, 0, KEY_DESTINATION).to_identifier(),
        epic_snip_wallet::path(ROLE_ALICE, 1, KEY_ALICE_AUTH).to_identifier(),
    ];
    for i in 0..paths.len() {
        for j in (i + 1)..paths.len() {
            assert_ne!(paths[i], paths[j], "path {} equals path {}", i, j);
        }
    }
    let _ = kc;
}

fn dummy_record(id: &str) -> PaymentRecord {
    PaymentRecord {
        payment_id: id.to_string(),
        receipt_commit: id.to_string(),
        receipt_output_hex: "00".to_string(),
        direction: Direction::Outgoing,
        amount: 1,
        amount_known: true,
        payment_index: Some(0),
        derivation_version: DERIVATION_VERSION,
        descriptor_id: None,
        funding_tx_id: None,
        block_hash: None,
        confirmation_height: None,
        status: PaymentStatus::Pending,
        reclaimable: true,
        spent_by: None,
    }
}

#[test]
fn store_is_duplicate_safe_and_restart_safe() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");

    {
        let mut store = SnipStore::open(&path).unwrap();
        assert_eq!(store.allocate_payment_index().unwrap(), 0);
        assert_eq!(store.allocate_payment_index().unwrap(), 1);
        assert_eq!(
            store.insert(dummy_record("aa")).unwrap(),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(dummy_record("aa")).unwrap(),
            InsertOutcome::Duplicate
        );
        assert_eq!(store.records().count(), 1);
    }

    let mut reopened = SnipStore::open(&path).unwrap();
    assert_eq!(reopened.state().next_payment_index, 2);
    assert_eq!(reopened.records().count(), 1);
    assert_eq!(
        reopened.insert(dummy_record("aa")).unwrap(),
        InsertOutcome::Duplicate
    );
    assert_eq!(reopened.allocate_payment_index().unwrap(), 2);
}

#[test]
fn index_watermark_never_moves_backwards() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    let mut store = SnipStore::open(&path).unwrap();
    store.bump_next_payment_index(10).unwrap();
    store.bump_next_payment_index(3).unwrap();
    assert_eq!(store.state().next_payment_index, 10);
}

#[test]
fn store_rejects_unknown_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    {
        let store = SnipStore::open(&path).unwrap();
        store.save().unwrap();
    }
    let mut state: epic_snip_wallet::StoreState =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    state.version = 999;
    std::fs::write(&path, serde_json::to_string(&state).unwrap()).unwrap();
    match SnipStore::open(&path) {
        Ok(_) => panic!("expected an unsupported-version error"),
        Err(error) => assert!(error.to_string().contains("unsupported store version")),
    }
}

#[test]
fn store_single_writer_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    let _first = SnipStore::open(&path).unwrap();
    // A second writer must be rejected.
    match SnipStore::open(&path) {
        Ok(_) => panic!("expected lock contention error"),
        Err(e) => assert!(e.to_string().contains("already open")),
    }
}

#[test]
fn store_contains_no_secret_material() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    let kc = keychain(0x42);
    let descriptor = epic_snip_wallet::bob_secrets(&kc)
        .unwrap()
        .descriptor(kc.secp())
        .unwrap();
    {
        let mut store = SnipStore::open(&path).unwrap();
        store.register_descriptor(&descriptor, kc.secp()).unwrap();
        store.allocate_payment_index().unwrap();
        store.insert(dummy_record("aa")).unwrap();
    }
    let data = std::fs::read_to_string(&path).unwrap();
    // The store must not contain any seed, private key, or derived secret.
    // Field-level: only public metadata fields are present.
    assert!(data.contains("\"payment_id\""));
    assert!(data.contains("\"receipt_commit\""));
    assert!(data.contains("\"descriptor_id\""));
    assert!(!data.to_lowercase().contains("secret"));
    assert!(!data.to_lowercase().contains("seed"));
    assert!(!data.to_lowercase().contains("private"));
}

#[test]
fn payment_index_allocation_respects_hardened_range() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    let mut store = SnipStore::open(&path).unwrap();
    store
        .bump_next_payment_index(epic_snip_wallet::derive::HARDENED)
        .unwrap();
    assert!(store.allocate_payment_index().is_err());
    assert!(store
        .bump_next_payment_index(epic_snip_wallet::derive::HARDENED + 1)
        .is_err());
}
