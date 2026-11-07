//! Local terminal demonstration of the experimental Stealth-Receipt flow.
//!
//! This is not a wallet or a Usernet block test. It constructs and validates a
//! local Core receipt-output-to-BobClaim transaction roundtrip.

use epic_core::core::{
    build_bob_claim_transaction, build_shared_receipt_output,
    rewind_shared_receipt_output, SharedReceiptKeyHashes, StealthReceiptSecrets,
};
use epic_core::core::transaction::Weighting;
use epic_core::global::{self, ChainTypes};
use util;
use util::secp;
use util::secp::key::{PublicKey, SecretKey};

fn key(secp: &secp::Secp256k1) -> SecretKey {
    SecretKey::new(secp, &mut rand::rng())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);

    // Bob performs this once and retains both private descriptor keys.
    let bob_secrets = StealthReceiptSecrets::new(key(&secp), key(&secp));
    let bob_descriptor = bob_secrets.descriptor(&secp)?;

    // Alice needs only the public descriptor and creates fresh entropy per payment.
    let alice_ephemeral = key(&secp);
    let (hint, bob_receipt_public_key) =
        bob_descriptor.derive_for_sender(&alice_ephemeral, &secp)?;
    let alice_authorization_public_key = PublicKey::from_secret_key(&secp, &key(&secp))?;
    let receipt_hashes = SharedReceiptKeyHashes::from_public_keys(
        &bob_receipt_public_key,
        &alice_authorization_public_key,
    );

    // Bob sees the public hint during a scan and independently recovers b_i.
    let bob_receipt_secret =
        bob_secrets.derive_receipt_key(&bob_descriptor, &hint, &secp)?;
    let bob_derived_public_key = PublicKey::from_secret_key(&secp, &bob_receipt_secret)?;
    assert_eq!(bob_receipt_public_key, bob_derived_public_key);

    // Independently derive the blind for the shared output. This is separate
    // from Bob's receipt authorization key and is never printed.
    let alice_shared_blind = bob_descriptor
        .derive_shared_spend_blind_for_sender(&alice_ephemeral, &secp)?;
    let bob_shared_blind = bob_secrets
        .derive_shared_spend_blind(&bob_descriptor, &hint, &secp)?;
    assert_eq!(alice_shared_blind, bob_shared_blind);
    let receipt_value = 42;
    let fee = 2;
    let receipt_output = build_shared_receipt_output(
        receipt_value,
        &alice_shared_blind,
        receipt_hashes,
        hint,
        &secp,
    )?;
    receipt_output.verify_proof()?;

    // Bob discovers the output, recovers its amount with the shared blind,
    // and builds a valid one-input, one-output claim transaction.
    let scanned_value = rewind_shared_receipt_output(&receipt_output, &bob_shared_blind, &secp)?;
    assert_eq!(scanned_value, receipt_value);
    let destination_blind = key(&secp);
    let claim_tx = build_bob_claim_transaction(
        &receipt_output,
        scanned_value,
        &bob_shared_blind,
        &bob_receipt_secret,
        &destination_blind,
        fee,
        &secp,
    )?;
    global::set_mining_mode(ChainTypes::UserTesting);
    let validation = claim_tx.validate(Weighting::AsTransaction);
    global::set_mining_mode(ChainTypes::Mainnet);
    validation?;

    println!("Epic SNIP experimental Stealth-Receipt demo");
    println!("  Hint R_i: {}", util::to_hex(hint.ephemeral_public_key.to_vec()));
    println!(
        "  Derived Bob receipt public key: {}",
        util::to_hex(bob_derived_public_key.serialize_vec(&secp, true).to_vec())
    );
    println!("  Bob key matches Alice's derived public key: yes");
    println!("  Shared output blind matches for Alice and Bob: yes");
    println!(
        "  Shared output commitment: {}",
        util::to_hex(receipt_output.commit.as_ref().to_vec())
    );
    println!("  Bob rewinds receipt amount: {scanned_value}");
    println!("  BobClaim transaction output amount: {}", scanned_value - fee);
    println!("  BobClaim transaction fully validates in Usernet mode: yes");
    println!();
    println!("This is a local Core transaction demo, not a wallet, block, or network test.");

    Ok(())
}
