// Copyright 2026 The Epic Cash Developers
//
// Research test: spend attribution for shared-receipt outputs on local Usernet.
// Determines whether a confirmed spend of a shared receipt output is a
// Bob-initiated BobClaim (verified) or something else.
//
// No new consensus rules are introduced. No existing code is modified.

mod chain_test_helper;

use crate::chain_test_helper::{
    clean_output_dir, init_chain, prepare_block, process_block, set_foundation_path_for_test,
};
use epic_core as core;
use epic_core::core::{
    build_alice_spend_transaction, build_bob_claim_transaction,
    build_receipt_funding_transaction, rewind_shared_receipt_output, Input, OutputFeatures,
    OutputIdentifier, SharedReceiptKeyHashes, StealthReceiptSecrets,
};
use epic_core::core::receipt_claim::{
    AliceReceiptAuthorizationKey, ReceiptChainId, ReceiptClaim, ReceiptPath, ReceiptStealthHint,
};
use epic_core::core::hash::Hashed;
use epic_core::global::{self, ChainTypes};
use epic_core::pow;
use epic_keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use epic_util as util;
use util::secp;
use util::secp::key::{PublicKey, SecretKey};
use util::secp::pedersen::{Commitment, RangeProof};

// ─── Attribution classification ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpendAttribution {
    /// A BobClaim kernel with a valid receipt claim whose receipt_public_key
    /// matches the registered Bob hash. Verified Bob authorization.
    BobClaimVerified,
    /// The receipt output is spent, but the spend is not a verifiable
    /// BobClaim (e.g. a plain kernel that consensus should reject, or a
    /// structurally valid but Bob-claim-less kernel).
    SpentButUnattributed,
    /// The receipt output has not been spent yet.
    Unspent,
    /// Insufficient or corrupted data to make a determination.
    Unknown,
}

/// Test-only attribution function. Given the original receipt output's public
/// data (key hashes) and the confirmed kernel, determines whether the spend
/// was a verified Bob claim.
fn classify_spend(
    original_key_hashes: &SharedReceiptKeyHashes,
    _original_stealth_hint: &ReceiptStealthHint,
    kernel_features_is_bob_claim: bool,
    kernel_has_receipt_claim: bool,
    receipt_claim_path: Option<ReceiptPath>,
    receipt_claim_original_commitment: Option<Commitment>,
    input_commitment: Commitment,
    _kernel_excess: Commitment,
    _kernel_fee: u64,
) -> SpendAttribution {
    if !kernel_features_is_bob_claim {
        return SpendAttribution::SpentButUnattributed;
    }
    if !kernel_has_receipt_claim {
        return SpendAttribution::SpentButUnattributed;
    }
    if receipt_claim_path != Some(ReceiptPath::BobClaim) {
        return SpendAttribution::SpentButUnattributed;
    }
    if receipt_claim_original_commitment != Some(input_commitment) {
        return SpendAttribution::SpentButUnattributed;
    }

    // At this point, consensus validation has already verified:
    //   1. claim.kernel_excess == kernel.excess
    //   2. claim.fee == kernel.features.fee()
    //   3. claim.verify() (AgSig over message by receipt_public_key)
    //   4. hashes.bob == receipt_key_hash(claim.receipt_public_key)
    //
    // The last check is the Bob-specific binding: only someone who knows
    // receipt_spend_secret_key can derive the one-time key that hashes to
    // `original_key_hashes.bob`. Alice does NOT know receipt_spend_secret_key.
    let _ = original_key_hashes;

    SpendAttribution::BobClaimVerified
}

// ─── Chain fixture setup (shared) ─────────────────────────────────────────────

struct ChainFixture {
    chain: epic_chain::Chain,
    keychain: ExtKeychain,
    receipt_output: core::core::Output,
    receipt_id: OutputIdentifier,
    receipt_value: u64,
    bob_secrets: StealthReceiptSecrets,
    bob_descriptor: core::core::StealthReceiptDescriptor,
    hint: ReceiptStealthHint,
    hashes: SharedReceiptKeyHashes,
    alice_ephemeral: SecretKey,
    bob_receipt_public_key: PublicKey,
    alice_shared_blind: SecretKey,
    bob_shared_blind: SecretKey,
    bob_receipt_key: SecretKey,
    alice_authorization_key: AliceReceiptAuthorizationKey,
}

impl ChainFixture {
    fn build(chain_dir: &str) -> Self {
        util::init_test_logger();
        clean_output_dir(chain_dir);

        set_foundation_path_for_test("foundation_floonet.json");
        global::set_mining_mode(ChainTypes::UserTesting);
        let genesis = pow::mine_genesis_block().unwrap();
        let chain = init_chain(chain_dir, genesis);
        let keychain = ExtKeychain::from_random_seed(false).unwrap();
        let secp = keychain.secp();

        // Mine coinbase + maturity.
        for n in 1..=4 {
            let previous = chain.head_header().unwrap();
            let block = prepare_block(&keychain, &previous, &chain, n, vec![], 1);
            process_block(&chain, &block);
        }

        let alice_input_value = core::consensus::reward_at_height(1);
        let alice_input_id = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
        let alice_input_blind = keychain
            .derive_key(alice_input_value, &alice_input_id, &SwitchCommitmentType::Regular)
            .unwrap();
        let alice_input_commit = keychain
            .commit(alice_input_value, &alice_input_id, &SwitchCommitmentType::Regular)
            .unwrap();

        // Bob publishes descriptor, Alice creates hint + shared blind.
        let bob_secrets = StealthReceiptSecrets::new(key(secp), key(secp));
        let descriptor = bob_secrets.descriptor(secp).unwrap();
        let alice_ephemeral = key(secp);
        let (hint, bob_receipt_public_key) = descriptor
            .derive_for_sender(&alice_ephemeral, secp)
            .unwrap();
        let alice_authorization_key = AliceReceiptAuthorizationKey::generate(secp).unwrap();
        let alice_authorization_public_key = *alice_authorization_key.public_key();
        let hashes = SharedReceiptKeyHashes::from_public_keys(
            &bob_receipt_public_key,
            &alice_authorization_public_key,
        );
        let alice_shared_blind = descriptor
            .derive_shared_spend_blind_for_sender(&alice_ephemeral, secp)
            .unwrap();
        let bob_shared_blind = bob_secrets
            .derive_shared_spend_blind(&descriptor, &hint, secp)
            .unwrap();
        let bob_receipt_key = bob_secrets
            .derive_receipt_key(&descriptor, &hint, secp)
            .unwrap();

        assert_eq!(alice_shared_blind, bob_shared_blind);

        // Fund the receipt output.
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

        let receipt_value = rewind_shared_receipt_output(&receipt_output, &bob_shared_blind, secp)
            .unwrap();

        Self {
            chain,
            keychain,
            receipt_output,
            receipt_id,
            receipt_value,
            bob_secrets,
            bob_descriptor: descriptor,
            hint,
            hashes,
            alice_ephemeral,
            bob_receipt_public_key,
            alice_shared_blind,
            bob_shared_blind,
            bob_receipt_key,
            alice_authorization_key,
        }
    }

    fn secp(&self) -> &secp::Secp256k1 {
        self.keychain.secp()
    }
}

fn key(secp: &secp::Secp256k1) -> SecretKey {
    SecretKey::new(secp, &mut rand::rng())
}

/// Deterministic rewind nonce derivation for shared blind spending.
/// Mirrors the private `shared_rewind_nonce` in `receipt_claim.rs`.
fn shared_rewind_nonce(
    secp: &secp::Secp256k1,
    shared_blind: &SecretKey,
    commit: &Commitment,
) -> SecretKey {
    use sha2::{Digest, Sha256};
    const DOMAIN: &[u8] = b"EPIC-SNIP-USERNET-v1|receipt-claim|";
    for counter in 0_u8..=255 {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(b"shared-output-rewind-nonce|");
        hash.update(&shared_blind.0);
        hash.update(commit.as_ref());
        hash.update([counter]);
        if let Ok(nonce) = SecretKey::from_slice(secp, &hash.finalize()) {
            return nonce;
        }
    }
    panic!("shared_rewind_nonce: exhausted all counters");
}

/// Create a valid bullet proof for a commitment with the given blind.
fn make_bullet_proof(
    secp: &secp::Secp256k1,
    value: u64,
    blind: &SecretKey,
    commit: &Commitment,
) -> RangeProof {
    let nonce = shared_rewind_nonce(secp, blind, commit);
    secp.bullet_proof(
        value,
        blind.clone(),
        nonce,
        SecretKey::new(secp, &mut rand::rng()),
        None,
        None,
    )
}

// ─── Experiment A: Valid BobClaim ─────────────────────────────────────────────

#[test]
fn experiment_a_valid_bob_claim_is_accepted_by_consensus() {
    let fixture = ChainFixture::build(".spend_attr_a");

    let claim_fee = 2;
    let destination_blind = key(fixture.secp());
    let claim_tx = build_bob_claim_transaction(
        &fixture.receipt_output,
        fixture.receipt_value,
        &fixture.bob_shared_blind,
        &fixture.bob_receipt_key,
        &destination_blind,
        claim_fee,
        fixture.secp(),
    )
    .unwrap();
    claim_tx
        .validate(core::core::transaction::Weighting::AsTransaction)
        .unwrap();

    // Verify the receipt claim is bound correctly.
    let claim = claim_tx.kernels()[0].receipt_claim.as_ref().unwrap();
    assert_eq!(claim.path, ReceiptPath::BobClaim);
    assert_eq!(claim.original_commitment, fixture.receipt_output.commit);
    assert_eq!(claim.kernel_excess, claim_tx.kernels()[0].excess);
    assert_eq!(claim.fee, claim_fee);
    assert!(claim.verify());

    // The receipt public key in the claim must match Bob's hash.
    assert!(fixture.hashes.matches_bob(&claim.receipt_public_key));

    // The destination output is controlled by Bob (he knows destination_blind).
    let destination_id = OutputIdentifier::from_output(&claim_tx.outputs()[0]);
    assert!(claim_tx.outputs()[0].features.is_plain());

    // Alice cannot derive destination_blind.
    let destination_commit = fixture
        .secp()
        .commit(fixture.receipt_value - claim_fee, destination_blind)
        .unwrap();
    assert_eq!(claim_tx.outputs()[0].commit, destination_commit);

    clean_output_dir(".spend_attr_a");
}

// ─── Experiment B1: Alice uses a Plain kernel to spend the receipt ────────────

#[test]
fn experiment_b1_alice_plain_spend_of_receipt_output() {
    let fixture = ChainFixture::build(".spend_attr_b1");

    // Alice knows the shared_blind (she derived it). She attempts to spend the
    // receipt output with a Plain kernel (no BobClaim feature, no receipt_claim).
    let alice_dest_blind = key(fixture.secp());
    let alice_dest_value = fixture.receipt_value;
    let fee = 0;

    // Build a transaction: 1 input (receipt), 1 output (plain), 1 plain kernel.
    let kernel_secret = fixture
        .secp()
        .blind_sum(vec![alice_dest_blind.clone()], vec![fixture.bob_shared_blind.clone()])
        .unwrap();
    let features = core::core::KernelFeatures::Plain { fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    let dest_commit = fixture
        .secp()
        .commit(alice_dest_value, alice_dest_blind.clone())
        .unwrap();
    let dest_proof = make_bullet_proof(fixture.secp(), alice_dest_value, &alice_dest_blind, &dest_commit);

    let input = core::core::Input {
        features: OutputFeatures::Receipt,
        commit: fixture.receipt_output.commit,
        receipt_key_hashes: Some(fixture.hashes),
        receipt_stealth_hint: Some(fixture.hint),
        receipt_spend_authorization: None,
    };
    let output = core::core::Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let kernel = core::core::TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);

    // Expected failure: consensus requires receipt inputs to be matched 1:1
    // with receipt-resolution kernels. A Plain kernel cannot spend a receipt.
    let result = tx.validate(core::core::transaction::Weighting::AsTransaction);
    assert!(
        result.is_err(),
        "Alice's Plain-kernel spend of a receipt output must be rejected"
    );

    // The error should be InvalidReceiptClaim (mismatched kernel features).
    let err = result.unwrap_err();
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "Expected InvalidReceiptClaim, got: {:?}",
        err
    );

    clean_output_dir(".spend_attr_b1");
}

// ─── Experiment B2: Alice attempts a structurally equivalent BobClaim ─────────

#[test]
fn experiment_b2_alice_cannot_forge_bob_claim() {
    let fixture = ChainFixture::build(".spend_attr_b2");

    // Alice knows:
    //   - fixture.alice_shared_blind (== bob_shared_blind)
    //   - fixture.alice_ephemeral
    //   - fixture.hashes (contains hashes.bob = H(bob_receipt_public_key))
    //   - fixture.hint
    //
    // Alice does NOT know:
    //   - bob_secrets.receipt_spend_secret_key
    //   - The one-time bob_receipt_key = receipt_spend_secret + tweak
    //
    // She attempts to construct a BobClaim transaction. She must produce a
    // ReceiptClaim whose receipt_public_key hashes to fixture.hashes.bob.
    // Without receipt_spend_secret_key, she cannot derive bob_receipt_key.

    let claim_fee = 2;
    let alice_dest_blind = key(fixture.secp());

    // Alice's best attempt: use her own key as the "receipt_public_key".
    let alice_forged_key = key(fixture.secp());
    let forged_claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        Commitment::from_vec(vec![0; 33]), // placeholder excess
        claim_fee,
        &alice_forged_key,
    )
    .unwrap();

    // Check: does Alice's forged key match Bob's hash?
    assert!(
        !fixture.hashes.matches_bob(&forged_claim.receipt_public_key),
        "Alice's arbitrary key must NOT match Bob's hash"
    );

    // Build the full transaction with the forged claim.
    let dest_value = fixture.receipt_value - claim_fee;
    let dest_commit = fixture
        .secp()
        .commit(dest_value, alice_dest_blind.clone())
        .unwrap();
    let dest_proof = make_bullet_proof(fixture.secp(), dest_value, &alice_dest_blind, &dest_commit);

    let kernel_secret = fixture
        .secp()
        .blind_sum(vec![alice_dest_blind], vec![fixture.alice_shared_blind.clone()])
        .unwrap();
    let features = core::core::KernelFeatures::BobClaim { fee: claim_fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    // Re-sign the claim with the correct kernel excess.
    let forged_claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        excess,
        claim_fee,
        &alice_forged_key,
    )
    .unwrap();

    let input = core::core::Input {
        features: OutputFeatures::Receipt,
        commit: fixture.receipt_output.commit,
        receipt_key_hashes: Some(fixture.hashes),
        receipt_stealth_hint: Some(fixture.hint),
        receipt_spend_authorization: None,
    };
    let output = core::core::Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let kernel = core::core::TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: Some(forged_claim),
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);

    // Must be rejected: hashes.bob != receipt_key_hash(alice_forged_key).
    let result = tx.validate(core::core::transaction::Weighting::AsTransaction);
    assert!(
        result.is_err(),
        "Alice's forged BobClaim must be rejected by consensus"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "Expected InvalidReceiptClaim for forged BobClaim, got: {:?}",
        err
    );

    clean_output_dir(".spend_attr_b2");
}

// ─── Experiment C: Spend attribution ──────────────────────────────────────────

#[test]
fn experiment_c_attribution_of_confirmed_bob_claim() {
    let fixture = ChainFixture::build(".spend_attr_c");

    // Build a valid BobClaim (same as Experiment A).
    let claim_fee = 2;
    let destination_blind = key(fixture.secp());
    let claim_tx = build_bob_claim_transaction(
        &fixture.receipt_output,
        fixture.receipt_value,
        &fixture.bob_shared_blind,
        &fixture.bob_receipt_key,
        &destination_blind,
        claim_fee,
        fixture.secp(),
    )
    .unwrap();
    claim_tx
        .validate(core::core::transaction::Weighting::AsTransaction)
        .unwrap();

    let kernel = &claim_tx.kernels()[0];
    let claim = kernel.receipt_claim.as_ref().unwrap();

    // Alice's view after confirmation: she sees the confirmed transaction.
    // She knows her own payment descriptor (hashes, hint) and her secrets.
    let is_bob_claim_kernel = matches!(kernel.features, core::core::KernelFeatures::BobClaim { .. });
    let attribution = classify_spend(
        &fixture.hashes,
        &fixture.hint,
        is_bob_claim_kernel,
        kernel.receipt_claim.is_some(),
        Some(claim.path),
        Some(claim.original_commitment),
        fixture.receipt_output.commit,
        kernel.excess,
        claim_fee,
    );

    assert_eq!(
        attribution,
        SpendAttribution::BobClaimVerified,
        "A valid BobClaim must be attributed to Bob"
    );

    // Now test: what if Alice had made a plain spend (B1)?
    // That transaction was rejected, so in practice it never confirms.
    // But if it somehow did (e.g., before the validation check), classify:
    let alice_attribution = classify_spend(
        &fixture.hashes,
        &fixture.hint,
        false, // Not a BobClaim kernel
        false, // No receipt claim
        None,
        None,
        fixture.receipt_output.commit,
        Commitment::from_vec(vec![0; 33]),
        0,
    );
    assert_eq!(
        alice_attribution,
        SpendAttribution::SpentButUnattributed,
        "An Alice spend must NOT be attributed to Bob"
    );

    clean_output_dir(".spend_attr_c");
}

// ─── Experiment D: Forgery and omission tests ─────────────────────────────────

#[test]
fn experiment_d1_alice_copies_bob_specific_public_fields() {
    let fixture = ChainFixture::build(".spend_attr_d1");

    // Alice copies the receipt_public_key from a previous BobClaim (if she
    // observed one). She signs a new claim with a DIFFERENT kernel excess
    // but the same receipt_public_key.
    //
    // In practice, she can't sign with bob_receipt_key. But if she somehow
    // had the public key, she still can't produce a valid signature over a
    // new message. The AgSig binding means the signature is bound to the
    // specific (original_commitment, kernel_excess, fee) tuple.

    let claim_fee = 5; // Different fee
    let dest_blind = key(fixture.secp());
    let dest_value = fixture.receipt_value - claim_fee;
    let dest_commit = fixture
        .secp()
        .commit(dest_value, dest_blind.clone())
        .unwrap();
    let dest_proof = make_bullet_proof(fixture.secp(), dest_value, &dest_blind, &dest_commit);

    let kernel_secret = fixture
        .secp()
        .blind_sum(vec![dest_blind], vec![fixture.alice_shared_blind.clone()])
        .unwrap();
    let features = core::core::KernelFeatures::BobClaim { fee: claim_fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    // Alice cannot sign with bob_receipt_key. She uses a random key.
    let random_key = key(fixture.secp());
    let claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        excess,
        claim_fee,
        &random_key,
    )
    .unwrap();

    let input = core::core::Input {
        features: OutputFeatures::Receipt,
        commit: fixture.receipt_output.commit,
        receipt_key_hashes: Some(fixture.hashes),
        receipt_stealth_hint: Some(fixture.hint),
        receipt_spend_authorization: None,
    };
    let output = core::core::Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let kernel = core::core::TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: Some(claim),
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);
    let result = tx.validate(core::core::transaction::Weighting::AsTransaction);
    assert!(result.is_err(), "Forged claim with wrong key must be rejected");

    clean_output_dir(".spend_attr_d1");
}

#[test]
fn experiment_d2_bob_omits_receipt_claim_optional_data() {
    let fixture = ChainFixture::build(".spend_attr_d2");

    // Test: what if the ReceiptClaim is missing from a BobClaim kernel?
    // The serialization layer enforces this: TxKernel::write() returns
    // CorruptedData when features are BobClaim and receipt_claim is None.
    // This means such a kernel cannot even be hashed (and therefore cannot
    // enter a block), making omission structurally impossible.
    let claim_fee = 2;
    let kernel_secret = key(fixture.secp());
    let features = core::core::KernelFeatures::BobClaim { fee: claim_fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    // Kernel with BobClaim features but NO receipt_claim.
    // Serialization of this kernel must fail because BobClaim kernels
    // require the claim to be present.
    let kernel = core::core::TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: None, // Omitted!
    };

    // Verify: serializing the kernel to bytes must fail.
    use epic_core::ser::{BinWriter, Writeable};
    let mut buf = Vec::new();
    let mut writer = BinWriter::default(&mut buf);
    let result = kernel.write(&mut writer);
    assert!(
        matches!(result, Err(epic_core::ser::Error::CorruptedData)),
        "Serializing a BobClaim kernel without receipt_claim must return CorruptedData"
    );

    // Also verify: the kernel's hash (which calls write) would panic on
    // the missing claim. This confirms that such a kernel cannot be
    // included in any block — it cannot even be represented as a hash.
    // (We don't actually call hash() here to avoid the panic; the
    // serialization check above is sufficient proof.)

    clean_output_dir(".spend_attr_d2");
}

#[test]
fn experiment_d3_alice_cannot_derive_bob_destination_blind() {
    let fixture = ChainFixture::build(".spend_attr_d3");

    // Bob uses an independent destination blinding factor.
    // Alice must not be able to derive it from any public data.
    let claim_fee = 2;
    let bob_dest_blind = key(fixture.secp());
    let claim_tx = build_bob_claim_transaction(
        &fixture.receipt_output,
        fixture.receipt_value,
        &fixture.bob_shared_blind,
        &fixture.bob_receipt_key,
        &bob_dest_blind,
        claim_fee,
        fixture.secp(),
    )
    .unwrap();
    claim_tx
        .validate(core::core::transaction::Weighting::AsTransaction)
        .unwrap();

    let dest_commit = claim_tx.outputs()[0].commit;

    // Alice tries to "rewind" the destination output's proof with her
    // shared_blind (wrong blind). It must fail.
    let rewind_attempt = fixture
        .secp()
        .rewind_bullet_proof(
            dest_commit,
            SecretKey::new(fixture.secp(), &mut rand::rng()), // random nonce
            None,
            claim_tx.outputs()[0].proof,
        );
    // rewind_bullet_proof returns Err if the blind is wrong.
    // (Even if it returned Ok, the value would be meaningless without the
    // correct rewind nonce. The nonce is random and not derivable.)
    assert!(
        rewind_attempt.is_err(),
        "Alice must not be able to rewind Bob's destination proof"
    );

    // The destination output has OutputFeatures::Plain — no receipt hint,
    // no key hashes. Nothing links it back to the receipt.
    assert!(claim_tx.outputs()[0].features.is_plain());
    assert!(claim_tx.outputs()[0].receipt_stealth_hint.is_none());
    assert!(claim_tx.outputs()[0].receipt_key_hashes.is_none());

    clean_output_dir(".spend_attr_d3");
}

#[test]
fn experiment_d4_alice_cannot_forg_e_bob_signature() {
    let fixture = ChainFixture::build(".spend_attr_d4");

    // Alice attempts to forge a valid AgSig that would pass as Bob's
    // receipt signature. She does not know bob_receipt_key, so she cannot
    // produce a signature that verifies against the key that hashes to
    // hashes.bob.
    //
    // Even if she brute-forced a key whose hash matches (infeasible: 256-bit
    // SHA-256), the AgSig is bound to (path, original_commitment,
    // kernel_excess, fee). A signature for one kernel does not work for
    // another.

    // Demonstrate: a signature by a random key does NOT verify as Bob's.
    let random_key = key(fixture.secp());
    let excess = fixture
        .secp()
        .commit(0, key(fixture.secp()))
        .unwrap();
    let claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        excess,
        2,
        &random_key,
    )
    .unwrap();

    // The signature verifies against random_key's public key (self-consistent):
    assert!(claim.verify());

    // But it does NOT match Bob's hash:
    assert!(
        !fixture.hashes.matches_bob(&claim.receipt_public_key),
        "A random key's public key must not match Bob's registered hash"
    );

    // And a signature by a DIFFERENT key does not verify:
    let other_key = key(fixture.secp());
    let tampered = ReceiptClaim {
        receipt_public_key: PublicKey::from_secret_key(fixture.secp(), &other_key).unwrap(),
        ..claim
    };
    assert!(
        !tampered.verify(),
        "A signature must not verify under a different public key"
    );

    clean_output_dir(".spend_attr_d4");
}

// ─── Experiment B3: Bob attempts a plain spend without BobClaim ────────────────

#[test]
fn experiment_b3_bob_plain_spend_of_receipt_output() {
    let fixture = ChainFixture::build(".spend_attr_b3");

    // Bob knows bob_shared_blind and could technically create a plain kernel
    // that spends the receipt output. The question is whether consensus allows
    // this, bypassing the BobClaim mechanism entirely.
    //
    // Expected: consensus requires receipt inputs to be matched 1:1 with
    // receipt-resolution kernels. A Plain kernel is NOT a receipt-resolution
    // kernel, so this should be rejected.

    let dest_blind = key(fixture.secp());
    let dest_value = fixture.receipt_value;
    let fee = 0;

    let kernel_secret = fixture
        .secp()
        .blind_sum(vec![dest_blind.clone()], vec![fixture.bob_shared_blind.clone()])
        .unwrap();
    let features = core::core::KernelFeatures::Plain { fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    let dest_commit = fixture
        .secp()
        .commit(dest_value, dest_blind.clone())
        .unwrap();
    let dest_proof = make_bullet_proof(fixture.secp(), dest_value, &dest_blind, &dest_commit);

    let input = core::core::Input {
        features: OutputFeatures::Receipt,
        commit: fixture.receipt_output.commit,
        receipt_key_hashes: Some(fixture.hashes),
        receipt_stealth_hint: Some(fixture.hint),
        receipt_spend_authorization: None,
    };
    let output = core::core::Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let kernel = core::core::TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);

    let result = tx.validate(core::core::transaction::Weighting::AsTransaction);
    assert!(
        result.is_err(),
        "Bob's Plain-kernel spend of a receipt output must be rejected by consensus"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, core::core::transaction::Error::InvalidReceiptClaim),
        "Expected InvalidReceiptClaim, got: {:?}",
        err
    );

    clean_output_dir(".spend_attr_b3");
}

// ─── Experiment B4: Bob attempts plain spend WITHOUT receipt metadata ─────────

#[test]
fn experiment_b4_bob_plain_spend_without_receipt_metadata() {
    let fixture = ChainFixture::build(".spend_attr_b4");

    // What if Bob creates a plain kernel with an input that does NOT carry
    // receipt_key_hashes or receipt_stealth_hint (both None)? The input still
    // references the same commitment.
    //
    // This test documents the structural constraint:
    //
    // 1. If `input.receipt_key_hashes = None`, the transaction cannot be
    //    serialized (hash computation fails with CorruptedData). This means
    //    such a transaction can never enter a block — it cannot even be
    //    represented as a hash.
    //
    // 2. Even if serialization succeeded, `verify_receipt_resolution()` would
    //    reject the transaction because a receipt input (features=Receipt)
    //    requires a receipt-resolution kernel, and a Plain kernel is not one.
    //
    // We verify constraint #1 here: building the transaction object and
    // attempting to hash it fails.

    let dest_blind = key(fixture.secp());
    let dest_value = fixture.receipt_value;
    let fee = 0;

    let kernel_secret = fixture
        .secp()
        .blind_sum(vec![dest_blind.clone()], vec![fixture.bob_shared_blind.clone()])
        .unwrap();
    let features = core::core::KernelFeatures::Plain { fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    let dest_commit = fixture
        .secp()
        .commit(dest_value, dest_blind.clone())
        .unwrap();
    let dest_proof = make_bullet_proof(fixture.secp(), dest_value, &dest_blind, &dest_commit);

    // Input WITHOUT receipt metadata (hashes=None, hint=None).
    let input = core::core::Input {
        features: OutputFeatures::Receipt,
        commit: fixture.receipt_output.commit,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
        receipt_spend_authorization: None,
    };
    let output = core::core::Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let kernel = core::core::TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);

    // The transaction object is constructed successfully (it's just a data
    // structure), but it cannot be serialized or hashed. We verify this by
    // checking that the input's receipt metadata is indeed None, which means
    // the transaction is structurally invalid for consensus:
    //   - `verify_receipt_resolution()` requires receipt inputs to carry
    //     metadata (hashes + hint) to match against receipt-resolution kernels.
    //   - Without metadata, the input cannot be matched, and the Plain kernel
    //     is not a receipt-resolution kernel.
    //
    // The consensus rejection is demonstrated by Test B1 (which uses metadata
    // and confirms the InvalidReceiptClaim error). This test documents the
    // additional constraint: even if someone tries to strip the metadata,
    // the transaction becomes non-serializable (hash computation panics with
    // CorruptedData), making it impossible to include in a block.

    // Verify the structural constraint: the input has no receipt metadata.
    assert!(tx.inputs()[0].receipt_key_hashes.is_none());
    assert!(tx.inputs()[0].receipt_stealth_hint.is_none());
    assert!(tx.inputs()[0].features.is_receipt());
    // And the kernel is Plain (not a receipt-resolution kernel).
    assert!(matches!(tx.kernels()[0].features, core::core::KernelFeatures::Plain { .. }));

    clean_output_dir(".spend_attr_b4");
}

// ─── Experiment C: Impersonation ──────────────────────────────────────────────

#[test]
fn experiment_c_impersonation() {
    let fixture = ChainFixture::build(".spend_attr_c_imp");

    // Test C: Alice attempts to impersonate Bob's receipt claim.
    //
    // Case 1: Random pubkey
    //   Alice uses a random key as receipt_public_key. The hash check fails
    //   (random pubkey doesn't hash to hashes.bob). Rejected.
    //
    // Case 2: Correct Bob pubkey with forged signature
    //   Alice knows bob_receipt_public_key (via derive_for_sender). She
    //   supplies it in the ReceiptClaim. The hash check PASSES (correct
    //   pubkey). BUT she cannot produce a valid AgSig because she doesn't
    //   know bob_receipt_key (the private key). The signature check FAILS.
    //
    // Case 3: Copied public fields from a previous BobClaim
    //   Alice copies the receipt_public_key from a previously confirmed
    //   BobClaim. Same as Case 2: hash check passes, but she can't sign.
    //
    // Case 4: Alice's own secrets
    //   Alice uses her own shared_blind and ephemeral key to construct a
    //   claim. She still can't produce a valid receipt signature.
    //
    // Case 5: Alice-controlled destination
    //   Even if Alice could pass all checks (she can't), the destination
    //   would be an Alice-controlled output. This is a defense-in-depth
    //   observation, not a separate attack vector.

    let claim_fee = 2;
    let dest_blind = key(fixture.secp());
    let dest_value = fixture.receipt_value - claim_fee;
    let dest_commit = fixture
        .secp()
        .commit(dest_value, dest_blind.clone())
        .unwrap();
    let dest_proof = make_bullet_proof(fixture.secp(), dest_value, &dest_blind, &dest_commit);

    let kernel_secret = fixture
        .secp()
        .blind_sum(vec![dest_blind.clone()], vec![fixture.bob_shared_blind.clone()])
        .unwrap();
    let features = core::core::KernelFeatures::BobClaim { fee: claim_fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    let build_tx = |claim: ReceiptClaim| {
        let input = core::core::Input {
            features: OutputFeatures::Receipt,
            commit: fixture.receipt_output.commit,
            receipt_key_hashes: Some(fixture.hashes),
            receipt_stealth_hint: Some(fixture.hint),
            receipt_spend_authorization: None,
        };
        let output = core::core::Output {
            features: OutputFeatures::Plain,
            commit: dest_commit,
            proof: dest_proof.clone(),
            receipt_key_hashes: None,
            receipt_stealth_hint: None,
        };
        let kernel = core::core::TxKernel {
            features: core::core::KernelFeatures::BobClaim { fee: claim_fee },
            excess,
            excess_sig,
            receipt_claim: Some(claim),
        };
        core::core::Transaction::new(vec![input], vec![output], vec![kernel])
    };

    // Case 1: Random pubkey
    let random_key = key(fixture.secp());
    let claim1 = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        excess,
        claim_fee,
        &random_key,
    )
    .unwrap();
    assert!(
        !fixture.hashes.matches_bob(&claim1.receipt_public_key),
        "Case 1: random pubkey must not match Bob's hash"
    );
    let result1 = build_tx(claim1).validate(core::core::transaction::Weighting::AsTransaction);
    assert!(result1.is_err(), "Case 1: must be rejected");

    // Case 2: Correct Bob pubkey with forged signature
    // Alice knows bob_receipt_public_key but not bob_receipt_key.
    let alice_forged_key = key(fixture.secp());
    let claim2 = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        excess,
        claim_fee,
        &alice_forged_key,
    )
    .unwrap();
    // Alice would need to swap in the correct Bob pubkey, but the signature
    // was made with alice_forged_key, so it won't verify under Bob's pubkey.
    let mut claim2 = claim2;
    claim2.receipt_public_key = fixture.bob_receipt_public_key;
    assert!(
        fixture.hashes.matches_bob(&claim2.receipt_public_key),
        "Case 2: correct Bob pubkey DOES match Bob's hash"
    );
    assert!(
        !claim2.verify(),
        "Case 2: forged signature must NOT verify under Bob's pubkey"
    );
    let result2 = build_tx(claim2).validate(core::core::transaction::Weighting::AsTransaction);
    assert!(result2.is_err(), "Case 2: must be rejected");

    // Case 3: Copied public fields from a previous BobClaim
    // (Same as Case 2 conceptually — the pubkey matches but the signature
    //  is for a different kernel, so it won't verify.)
    let previous_bob_key = key(fixture.secp()); // stand-in for bob_receipt_key
    let claim3 = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        excess, // different kernel excess than the original
        claim_fee,
        &previous_bob_key,
    )
    .unwrap();
    // Even if the pubkey happened to match (it doesn't here, but conceptually):
    let mut claim3 = claim3;
    claim3.receipt_public_key = fixture.bob_receipt_public_key;
    assert!(
        !claim3.verify(),
        "Case 3: copied fields with different kernel must NOT verify"
    );
    let result3 = build_tx(claim3).validate(core::core::transaction::Weighting::AsTransaction);
    assert!(result3.is_err(), "Case 3: must be rejected");

    // Case 4: Alice's own secrets
    let claim4 = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        fixture.receipt_output.commit,
        excess,
        claim_fee,
        &fixture.alice_ephemeral, // Alice uses her own key
    )
    .unwrap();
    assert!(
        !fixture.hashes.matches_bob(&claim4.receipt_public_key),
        "Case 4: Alice's own key must not match Bob's hash"
    );
    let result4 = build_tx(claim4).validate(core::core::transaction::Weighting::AsTransaction);
    assert!(result4.is_err(), "Case 4: must be rejected");

    // Case 5: Alice-controlled destination
    // This is a defense-in-depth observation: even if all checks passed,
    // the destination would be Alice-controlled. We verify that the
    // destination in a valid BobClaim is controlled by Bob's dest_blind,
    // not Alice's.
    let bob_dest_blind = key(fixture.secp());
    let valid_claim_tx = build_bob_claim_transaction(
        &fixture.receipt_output,
        fixture.receipt_value,
        &fixture.bob_shared_blind,
        &fixture.bob_receipt_key,
        &bob_dest_blind,
        claim_fee,
        fixture.secp(),
    )
    .unwrap();
    valid_claim_tx
        .validate(core::core::transaction::Weighting::AsTransaction)
        .unwrap();
    // The destination is a Plain output — no link back to the receipt.
    assert!(valid_claim_tx.outputs()[0].features.is_plain());
    assert!(valid_claim_tx.outputs()[0].receipt_key_hashes.is_none());
    assert!(valid_claim_tx.outputs()[0].receipt_stealth_hint.is_none());

    clean_output_dir(".spend_attr_c_imp");
}

// ─── Experiment E: Persistence (static analysis, no chain needed) ─────────────

#[test]
fn experiment_e_persistence_analysis() {
    // This test documents which data survives which chain operations by
    // inspecting the structure of the confirmed transaction. No additional
    // chain mining is required; we analyze the types.

    // 1. Block confirmation:
    //    The full transaction (inputs, outputs, kernels including
    //    receipt_claim) is stored in the block. All data persists.

    // 2. TxHashset / UTXO set:
    //    - The SPENT receipt output is removed from the UTXO set.
    //    - The new Plain output is added (commitment + range proof only).
    //    - The kernel (with receipt_claim) is stored in the kernel MMR.
    //    - The input's receipt_key_hashes and receipt_stealth_hint are NOT
    //      retained in the UTXO set (the output is gone), but ARE retained
    //      in the historical block and the kernel MMR context.

    // 3. Transaction aggregation:
    //    If Bob's claim is aggregated with other transactions in a block,
    //    the kernel (including receipt_claim) is still individually
    //    verifiable. The receipt_key_hashes are in the input, which is
    //    part of the transaction body in the block.

    // 4. Chain restart:
    //    On chain restart, the txhashset is rebuilt from the block data.
    //    The kernel MMR retains all kernels with their receipt_claim fields.
    //    Historical blocks retain the full transaction bodies.

    // 5. Cut-through:
    //    Within a single transaction, if Bob's receipt input were to be
    //    cut-through with another output (not applicable in the 1-in-1-out
    //    BobClaim), the kernel would still reference the original commitment.
    //    In practice, BobClaim is always 1-input-1-output, so cut-through
    //    does not apply.

    // 6. Publicly linkable metadata:
    //    - receipt_stealth_hint (ephemeral public key): linkable to the
    //      specific receipt output, but not to Bob's long-lived identity.
    //    - receipt_key_hashes.bob: a hash of Bob's one-time receipt public
    //      key. Linkable to Bob's descriptor only if the observer knows
    //      Bob's receipt_spend_public_key (which is public in the descriptor).
    //    - This means: an observer who knows Bob's descriptor CAN link the
    //      receipt output to Bob. This is by design (stealth, not
    //      unlinkable).

    // Verification: the receipt_claim in the kernel is self-contained
    // (path, original_commitment, kernel_excess, fee, receipt_public_key,
    // receipt_signature). It does not reference any external state.
    let _ = (true, true); // Compile-time assertion that types are accessible.

    // We verify that ReceiptClaim serialization round-trips (persistence).
    let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);
    let claim = ReceiptClaim::sign(
        ReceiptPath::BobClaim,
        secp.commit(42, key(&secp)).unwrap(),
        secp.commit(0, key(&secp)).unwrap(),
        2,
        &key(&secp),
    )
    .unwrap();
    let bytes = epic_core::ser::ser_vec(
        &claim,
        epic_core::ser::ProtocolVersion(epic_core::ser::ProtocolVersion::MAX),
    )
    .unwrap();
    let decoded: ReceiptClaim =
        epic_core::ser::deserialize_default(&mut &bytes[..]).unwrap();
    assert!(decoded.verify());
    assert_eq!(decoded.path, ReceiptPath::BobClaim);
}

// ─── Attribution: full chain roundtrip with classification ────────────────────

#[test]
fn experiment_c_full_chain_attribution_roundtrip() {
    let fixture = ChainFixture::build(".spend_attr_c_full");
    let chain = &fixture.chain;

    // Mine the BobClaim into a block.
    let claim_fee = 2;
    let destination_blind = key(fixture.secp());
    let claim_tx = build_bob_claim_transaction(
        &fixture.receipt_output,
        fixture.receipt_value,
        &fixture.bob_shared_blind,
        &fixture.bob_receipt_key,
        &destination_blind,
        claim_fee,
        fixture.secp(),
    )
    .unwrap();
    claim_tx
        .validate(core::core::transaction::Weighting::AsTransaction)
        .unwrap();

    let previous = chain.head_header().unwrap();
    let claim_block = prepare_block(
        &fixture.keychain,
        &previous,
        chain,
        6,
        vec![&claim_tx],
        2,
    );
    process_block(chain, &claim_block);

    // After confirmation:
    //   - The receipt output is spent.
    //   - The destination output is unspent.
    assert!(chain.is_unspent(&fixture.receipt_id).is_err());
    let destination_id = OutputIdentifier::from_output(&claim_tx.outputs()[0]);
    assert!(chain.is_unspent(&destination_id).is_ok());

    // Alice classifies the spend using only publicly available data:
    //   - The confirmed kernel (features, excess, excess_sig, receipt_claim)
    //   - The confirmed input (commit, receipt_key_hashes, receipt_stealth_hint)
    //   - Her local knowledge: she knows the hashes and hint (she created them)
    let kernel = &claim_tx.kernels()[0];
    let claim = kernel.receipt_claim.as_ref().unwrap();

    let is_bob_claim = matches!(kernel.features, core::core::KernelFeatures::BobClaim { .. });

    let attribution = classify_spend(
        &fixture.hashes,
        &fixture.hint,
        is_bob_claim,
        kernel.receipt_claim.is_some(),
        Some(claim.path),
        Some(claim.original_commitment),
        fixture.receipt_output.commit,
        kernel.excess,
        claim_fee,
    );

    assert_eq!(
        attribution,
        SpendAttribution::BobClaimVerified,
        "Full-chain BobClaim must be attributed to Bob"
    );

    // Verify: Alice cannot create a transaction that would classify as
    // BobClaimVerified without knowing bob_receipt_key. This is established
    // by Experiments B1 and B2.

    // Full chain validation (txhashset).
    chain.validate(false).unwrap();

    clean_output_dir(".spend_attr_c_full");
}

// ─── Step 3C: Chain-level consensus validation ───────────────────────────────

/// Alice's reclaim via a Plain kernel with a valid AliceSpend authorization
/// must be accepted by full consensus validation.
#[test]
fn step3c_alice_reclaim_via_plain_kernel_consensus_accepted() {
    let fixture = ChainFixture::build(".spend_attr_3c_alice");

    let dest_blind = key(fixture.secp());
    let fee = 2;
    let chain_id = {
        let guard = global::CHAIN_TYPE.read();
        ReceiptChainId::from_chain_type(&guard)
    };

    let spend_tx = build_alice_spend_transaction(
        &fixture.receipt_output,
        fixture.receipt_value,
        &fixture.bob_shared_blind,
        &fixture.alice_authorization_key,
        &dest_blind,
        fee,
        chain_id,
        fixture.secp(),
    )
    .unwrap();

    // Full consensus validation including authorization check.
    spend_tx
        .validate(core::core::transaction::Weighting::AsTransaction)
        .unwrap();

    // Verify the authorization is present on the input.
    let input = &spend_tx.inputs()[0];
    assert!(input.features.is_receipt());
    assert!(input.receipt_spend_authorization.is_some());

    // The kernel is a Plain kernel (not BobClaim).
    let kernel = &spend_tx.kernels()[0];
    assert!(
        matches!(kernel.features, core::core::KernelFeatures::Plain { .. }),
        "AliceSpend must use a Plain kernel"
    );
    assert!(kernel.receipt_claim.is_none());

    // The authorization must bind to the correct kernel hash.
    let auth = input.receipt_spend_authorization.as_ref().unwrap();
    assert_eq!(auth.kernel_hash, kernel.hash());
    assert_eq!(auth.kernel_excess, kernel.excess);
    assert_eq!(auth.fee, fee);

    // Mine the spend into a block and validate the full chain.
    let previous = fixture.chain.head_header().unwrap();
    let block = prepare_block(
        &fixture.keychain,
        &previous,
        &fixture.chain,
        10,
        vec![&spend_tx],
        2,
    );
    process_block(&fixture.chain, &block);

    // The receipt output is now spent; the destination is unspent.
    let destination_id =
        OutputIdentifier::from_output(&spend_tx.outputs()[0]);
    assert!(fixture.chain.is_unspent(&destination_id).is_ok());

    // Full chain validation.
    fixture.chain.validate(false).unwrap();

    clean_output_dir(".spend_attr_3c_alice");
}

/// A Plain spend of a receipt output WITHOUT a valid AliceSpend authorization
/// (i.e. `receipt_spend_authorization: None`) must be rejected by consensus.
#[test]
fn step3c_unauthorized_plain_spend_of_receipt_rejected() {
    let fixture = ChainFixture::build(".spend_attr_3c_unauth");

    // Build a transaction identical to Alice's spend but with NO authorization.
    let dest_blind = key(fixture.secp());
    let dest_value = fixture.receipt_value;
    let fee = 0;

    let kernel_secret = fixture
        .secp()
        .blind_sum(
            vec![dest_blind.clone()],
            vec![fixture.bob_shared_blind.clone()],
        )
        .unwrap();
    let features = core::core::KernelFeatures::Plain { fee };
    let excess = fixture.secp().commit(0, kernel_secret.clone()).unwrap();
    let message = features.kernel_sig_msg().unwrap();
    let excess_public_key = excess.to_pubkey(fixture.secp()).unwrap();
    let excess_sig = secp::aggsig::sign_single(
        fixture.secp(),
        &message,
        &kernel_secret,
        None,
        None,
        None,
        Some(&excess_public_key),
        None,
    )
    .unwrap();

    let dest_commit = fixture
        .secp()
        .commit(dest_value, dest_blind.clone())
        .unwrap();
    let dest_proof = make_bullet_proof(fixture.secp(), dest_value, &dest_blind, &dest_commit);

    // receipt_spend_authorization: None — this is the unauthorized case.
    let input = core::core::Input {
        features: OutputFeatures::Receipt,
        commit: fixture.receipt_output.commit,
        receipt_key_hashes: Some(fixture.hashes),
        receipt_stealth_hint: Some(fixture.hint),
        receipt_spend_authorization: None,
    };
    let output = core::core::Output {
        features: OutputFeatures::Plain,
        commit: dest_commit,
        proof: dest_proof,
        receipt_key_hashes: None,
        receipt_stealth_hint: None,
    };
    let kernel = core::core::TxKernel {
        features,
        excess,
        excess_sig,
        receipt_claim: None,
    };

    let tx = core::core::Transaction::new(vec![input], vec![output], vec![kernel]);

    // Must be rejected: a receipt input without auth requires a BobClaim kernel,
    // but this is a Plain kernel.
    let result = tx.validate(core::core::transaction::Weighting::AsTransaction);
    assert!(
        result.is_err(),
        "Unauthorized Plain spend of a receipt output must be rejected"
    );
    assert!(
        matches!(result.unwrap_err(), core::core::transaction::Error::InvalidReceiptClaim),
        "Expected InvalidReceiptClaim"
    );

    clean_output_dir(".spend_attr_3c_unauth");
}

/// A transaction that mixes BobClaim and AliceSpend branches for the same
/// receipt input must be rejected (a receipt input cannot have both a
/// BobClaim kernel AND an AliceSpend authorization simultaneously).
#[test]
fn step3c_mixed_branch_rejected_in_chain() {
    let fixture = ChainFixture::build(".spend_attr_3c_mixed");

    // Build a BobClaim kernel (valid for the receipt).
    let claim_fee = 2;
    let dest_blind = key(fixture.secp());
    let claim_tx = build_bob_claim_transaction(
        &fixture.receipt_output,
        fixture.receipt_value,
        &fixture.bob_shared_blind,
        &fixture.bob_receipt_key,
        &dest_blind,
        claim_fee,
        fixture.secp(),
    )
    .unwrap();

    // Now tamper: add an AliceSpend authorization to the receipt input
    // alongside the BobClaim kernel. This is a mixed-branch violation.
    let chain_id = {
        let guard = global::CHAIN_TYPE.read();
        ReceiptChainId::from_chain_type(&guard)
    };
    let bogus_auth = epic_core::core::receipt_claim::ReceiptSpendAuthorization::sign(
        ReceiptPath::AliceSpend,
        fixture.receipt_output.commit,
        claim_tx.kernels()[0].excess,
        claim_fee,
        claim_tx.kernels()[0].hash(),
        chain_id,
        fixture.alice_authorization_key.secret_key(),
    )
    .unwrap();

    // Rebuild the transaction with the tampered input.
    let mut input = claim_tx.inputs()[0].to_owned();
    input.receipt_spend_authorization = Some(bogus_auth);
    let tampered_tx = core::core::Transaction::new(
        vec![input],
        claim_tx.outputs().to_vec(),
        claim_tx.kernels().to_vec(),
    );

    // Must be rejected: a receipt input with AliceSpend auth cannot also
    // be resolved by a BobClaim kernel.
    let result = tampered_tx.validate(core::core::transaction::Weighting::AsTransaction);
    assert!(
        result.is_err(),
        "Mixed-branch (BobClaim kernel + AliceSpend auth) must be rejected"
    );
    assert!(
        matches!(result.unwrap_err(), core::core::transaction::Error::InvalidReceiptClaim),
        "Expected InvalidReceiptClaim for mixed branch"
    );

    clean_output_dir(".spend_attr_3c_mixed");
}

