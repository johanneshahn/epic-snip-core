//! Domain-separated deterministic key derivation for SNIP wallets.
//!
//! Layout:
//!
//! ```text
//! m / SNIP_PURPOSE' / ROLE' / INDEX' / KEY_TYPE'
//! ```
//!
//! All components are hardened. `SwitchCommitmentType::None` is used so the
//! derived scalar is independent of any amount and can be recovered from the
//! seed alone.

use epic_core::core::receipt_claim::{
    AliceReceiptAuthorizationKey, StealthReceiptSecrets,
};
use epic_keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use epic_util::secp;
use epic_util::secp::key::SecretKey;

use crate::{Result, SnipError};

/// Hardened-child bit used by Epic's `ExtKeychainPath`.
pub const HARDENED: u32 = 1 << 31;

/// Dedicated SNIP purpose: ASCII "SNIP", below the 31-bit hardened range.
pub const SNIP_PURPOSE: u32 = 0x534E_4950;

pub const ROLE_BOB: u32 = 0;
pub const ROLE_ALICE: u32 = 1;

pub const KEY_BOB_SCAN: u32 = 0;
pub const KEY_BOB_SPEND: u32 = 1;
pub const KEY_ALICE_AUTH: u32 = 2;
pub const KEY_ALICE_EPHEMERAL: u32 = 3;
pub const KEY_DESTINATION: u32 = 4;

/// Returns the hardened derivation path for one SNIP key.
pub fn path(role: u32, index: u32, key_type: u32) -> ExtKeychainPath {
    ExtKeychainPath::new(
        4,
        SNIP_PURPOSE | HARDENED,
        role | HARDENED,
        index | HARDENED,
        key_type | HARDENED,
    )
}

/// Derives one raw secret key from the wallet seed.
pub fn derive_secret(
    keychain: &ExtKeychain,
    role: u32,
    index: u32,
    key_type: u32,
) -> Result<SecretKey> {
    if role >= HARDENED || index >= HARDENED || key_type >= HARDENED {
        return Err(SnipError::Keychain(
            "derivation component is outside the hardened index range".into(),
        ));
    }
    let id = path(role, index, key_type).to_identifier();
    keychain
        .derive_key(0, &id, &SwitchCommitmentType::None)
        .map_err(|e| SnipError::Keychain(format!("derive_key: {:?}", e)))
}

/// Bob's deterministic scan and receipt-spend secrets.
pub fn bob_secrets(keychain: &ExtKeychain) -> Result<StealthReceiptSecrets> {
    let scan = derive_secret(keychain, ROLE_BOB, 0, KEY_BOB_SCAN)?;
    let spend = derive_secret(keychain, ROLE_BOB, 0, KEY_BOB_SPEND)?;
    Ok(StealthReceiptSecrets::new(scan, spend))
}

/// Alice's per-payment authorization key `a_i`.
pub fn alice_authorization_key(
    keychain: &ExtKeychain,
    payment_index: u32,
    secp: &secp::Secp256k1,
) -> Result<AliceReceiptAuthorizationKey> {
    let secret = derive_secret(keychain, ROLE_ALICE, payment_index, KEY_ALICE_AUTH)?;
    AliceReceiptAuthorizationKey::from_secret_key(secret, secp)
        .map_err(|e| SnipError::Core(format!("authorization key: {}", e)))
}

/// Alice's per-payment ephemeral secret `r_i`.
pub fn alice_ephemeral_secret(
    keychain: &ExtKeychain,
    payment_index: u32,
) -> Result<SecretKey> {
    derive_secret(keychain, ROLE_ALICE, payment_index, KEY_ALICE_EPHEMERAL)
}

/// A destination output blind for a claim or reclaim.
pub fn destination_blind(
    keychain: &ExtKeychain,
    role: u32,
    index: u32,
) -> Result<SecretKey> {
    derive_secret(keychain, role, index, KEY_DESTINATION)
}
