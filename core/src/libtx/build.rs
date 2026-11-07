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

//! Utility functions to build Epic transactions. Handles the blinding of
//! inputs and outputs, maintaining the sum of blinding factors, producing
//! the excess signature, etc.
//!
//! Each building function is a combinator that produces a function taking
//! a transaction a sum of blinding factors, to return another transaction
//! and sum. Combinators can then be chained and executed using the
//! _transaction_ function.
//!
//! Example:
//! build::transaction(
//!   KernelFeatures::Plain{ fee: 2 },
//!   vec![
//!     input_rand(75),
//!     output_rand(42),
//!     output_rand(32),
//!   ]
//! )

use crate::core::{
    Input, KernelFeatures, Output, OutputFeatures, ReceiptStealthHint,
    SharedReceiptKeyHashes, Transaction, TxKernel,
};
use crate::libtx::proof::{self, ProofBuild};
use crate::libtx::{aggsig, Error};
use keychain::{BlindSum, BlindingFactor, Identifier, Keychain, SwitchCommitmentType};

/// Context information available to transaction combinators.
pub struct Context<'a, K, B>
where
    K: Keychain,
    B: ProofBuild,
{
    /// The keychain used for key derivation
    pub keychain: &'a K,
    /// The bulletproof builder
    pub builder: &'a B,
}

/// Function type returned by the transaction combinators. Transforms a
/// (Transaction, BlindSum) tuple into another, given the provided context.
/// Will return an Err if seomthing went wrong at any point during transaction building.
pub type Append<K, B> = dyn for<'a> Fn(
    &'a mut Context<'_, K, B>,
    Result<(Transaction, BlindSum), Error>,
) -> Result<(Transaction, BlindSum), Error>;

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
fn build_input<K, B>(value: u64, features: OutputFeatures, key_id: Identifier) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    Box::new(
        move |build, acc| -> Result<(Transaction, BlindSum), Error> {
            if let Ok((tx, sum)) = acc {
                let commit =
                    build
                        .keychain
                        .commit(value, &key_id, &SwitchCommitmentType::Regular)?;
                // TODO: proper support for different switch commitment schemes
                let input = Input::new(features, commit);
                Ok((
                    tx.with_input(input),
                    sum.sub_key_id(key_id.to_value_path(value)),
                ))
            } else {
                acc
            }
        },
    )
}

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
pub fn input<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    debug!(
        "Building input (spending regular output): {}, {}",
        value, key_id
    );
    build_input(value, OutputFeatures::Plain, key_id)
}

/// Adds a coinbase input spending a coinbase output.
pub fn coinbase_input<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    debug!("Building input (spending coinbase): {}, {}", value, key_id);
    build_input(value, OutputFeatures::Coinbase, key_id)
}

/// Adds an output with the provided value and key identifier from the
/// keychain.
pub fn output<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    Box::new(
        move |build, acc| -> Result<(Transaction, BlindSum), Error> {
            let (tx, sum) = acc?;

            // TODO: proper support for different switch commitment schemes
            let switch = &SwitchCommitmentType::Regular;

            let commit = build.keychain.commit(value, &key_id, switch)?;

            debug!("Building output: {}, {:?}", value, commit);

            let rproof = proof::create(
                build.keychain,
                build.builder,
                value,
                &key_id,
                switch,
                commit,
                None,
            )?;

            Ok((
                tx.with_output(Output {
                    features: OutputFeatures::Plain,
                    commit,
                    proof: rproof,
                    receipt_key_hashes: None,
                    receipt_stealth_hint: None,
                }),
                sum.add_key_id(key_id.to_value_path(value)),
            ))
        },
    )
}

/// Adds an experimental Usernet receipt output.
///
/// The caller supplies the already-derived, one-time receipt key hashes and
/// stealth scan hint. The output proof is otherwise created by the normal
/// Epic proof builder. This helper does not make the receipt key the
/// Mimblewimble spend blind; a separate shared-blind construction is required
/// before a non-interactive Bob claim can build a complete spend transaction.
pub fn receipt_output<K, B>(
    value: u64,
    key_id: Identifier,
    receipt_key_hashes: SharedReceiptKeyHashes,
    receipt_stealth_hint: ReceiptStealthHint,
) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    Box::new(
        move |build, acc| -> Result<(Transaction, BlindSum), Error> {
            let (tx, sum) = acc?;
            let switch = &SwitchCommitmentType::Regular;
            let commit = build.keychain.commit(value, &key_id, switch)?;
            let rproof = proof::create(
                build.keychain,
                build.builder,
                value,
                &key_id,
                switch,
                commit,
                None,
            )?;
            Ok((
                tx.with_output(Output {
                    features: OutputFeatures::Receipt,
                    commit,
                    proof: rproof,
                    receipt_key_hashes: Some(receipt_key_hashes),
                    receipt_stealth_hint: Some(receipt_stealth_hint),
                }),
                sum.add_key_id(key_id.to_value_path(value)),
            ))
        },
    )
}

/// Adds a known excess value on the transaction being built. Usually used in
/// combination with the initial_tx function when a new transaction is built
/// by adding to a pre-existing one.
pub fn with_excess<K, B>(excess: BlindingFactor) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    Box::new(
        move |_build, acc| -> Result<(Transaction, BlindSum), Error> {
            acc.map(|(tx, sum)| (tx, sum.add_blinding_factor(excess.clone())))
        },
    )
}

/// Sets an initial transaction to add to when building a new transaction.
pub fn initial_tx<K, B>(tx: Transaction) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    Box::new(
        move |_build, acc| -> Result<(Transaction, BlindSum), Error> {
            acc.map(|(_, sum)| (tx.clone(), sum))
        },
    )
}

/// Takes an existing transaction and partially builds on it.
///
/// Example:
/// let (tx, sum) = build::transaction(tx, vec![input_rand(4), output_rand(1))], keychain)?;
///
pub fn partial_transaction<K, B>(
    tx: Transaction,
    elems: Vec<Box<Append<K, B>>>,
    keychain: &K,
    builder: &B,
) -> Result<(Transaction, BlindingFactor), Error>
where
    K: Keychain,
    B: ProofBuild,
{
    let mut ctx = Context { keychain, builder };
    let (tx, sum) = elems
        .iter()
        .fold(Ok((tx, BlindSum::new())), |acc, elem| elem(&mut ctx, acc))?;
    let blind_sum = ctx.keychain.blind_sum(&sum)?;
    Ok((tx, blind_sum))
}

/// Builds a complete transaction.
pub fn transaction<K, B>(
    features: KernelFeatures,
    elems: Vec<Box<Append<K, B>>>,
    keychain: &K,
    builder: &B,
) -> Result<Transaction, Error>
where
    K: Keychain,
    B: ProofBuild,
{
    let mut ctx = Context { keychain, builder };
    let (mut tx, sum) = elems
        .iter()
        .fold(Ok((Transaction::empty(), BlindSum::new())), |acc, elem| {
            elem(&mut ctx, acc)
        })?;
    let blind_sum = ctx.keychain.blind_sum(&sum)?;

    // Split the key so we can generate an offset for the tx.
    let split = blind_sum.split(&keychain.secp())?;
    let k1 = split.blind_1;
    let k2 = split.blind_2;

    let mut kern = TxKernel::with_features(features);

    // Construct the message to be signed.
    let msg = kern.msg_to_sign()?;

    // Generate kernel excess and excess_sig using the split key k1.
    let skey = k1.secret_key(&keychain.secp())?;
    kern.excess = ctx.keychain.secp().commit(0, skey)?;
    let pubkey = &kern.excess.to_pubkey(&keychain.secp())?;
    kern.excess_sig = aggsig::sign_with_blinding(&keychain.secp(), &msg, &k1, Some(&pubkey))?;

    // Store the kernel offset (k2) on the tx.
    // Commitments will sum correctly when accounting for the offset.
    tx.offset = k2.clone();

    // Set the kernel on the tx.
    let tx = tx.replace_kernel(kern);

    Ok(tx)
}

// Just a simple test, most exhaustive tests in the core.
#[cfg(test)]
mod test {

    use super::*;
    use crate::core::{SharedReceiptKeyHashes, StealthReceiptSecrets};
    use crate::core::transaction::Weighting;
    use crate::libtx::ProofBuilder;
    use keychain::{ExtKeychain, ExtKeychainPath};

    #[test]
    fn blind_simple_tx() {
        let keychain = ExtKeychain::from_random_seed(false).unwrap();
        let builder = ProofBuilder::new(&keychain);
        let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
        let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
        let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

        let tx = transaction(
            KernelFeatures::Plain { fee: 2 },
            vec![input(10, key_id1), input(12, key_id2), output(20, key_id3)],
            &keychain,
            &builder,
        )
        .unwrap();

        tx.validate(Weighting::AsTransaction).unwrap();
    }

    #[test]
    fn receipt_output_preserves_stealth_metadata() {
        let keychain = ExtKeychain::from_random_seed(false).unwrap();
        let builder = ProofBuilder::new(&keychain);
        let input_key_id = ExtKeychainPath::new(1, 10, 0, 0, 0).to_identifier();
        let output_key_id = ExtKeychainPath::new(1, 11, 0, 0, 0).to_identifier();
        let secp = keychain.secp();
        let bob_secrets = StealthReceiptSecrets::new(
            util::secp::key::SecretKey::new(&secp, &mut rand::rng()),
            util::secp::key::SecretKey::new(&secp, &mut rand::rng()),
        );
        let descriptor = bob_secrets.descriptor(&secp).unwrap();
        let ephemeral = util::secp::key::SecretKey::new(&secp, &mut rand::rng());
        let (hint, bob_key) = descriptor.derive_for_sender(&ephemeral, &secp).unwrap();
        let alice_key = util::secp::key::SecretKey::new(&secp, &mut rand::rng());
        let alice_public_key =
            util::secp::key::PublicKey::from_secret_key(&secp, &alice_key).unwrap();
        let hashes = SharedReceiptKeyHashes::from_public_keys(&bob_key, &alice_public_key);

        let tx = transaction(
            KernelFeatures::Plain { fee: 2 },
            vec![input(10, input_key_id), receipt_output(8, output_key_id, hashes, hint)],
            &keychain,
            &builder,
        )
        .unwrap();
        let output = &tx.outputs()[0];
        assert_eq!(output.features, OutputFeatures::Receipt);
        assert_eq!(output.receipt_key_hashes, Some(hashes));
        assert_eq!(output.receipt_stealth_hint, Some(hint));
        assert!(hashes.matches_bob(&bob_key));
    }

    #[test]
    fn blind_simple_tx_with_offset() {
        let keychain = ExtKeychain::from_random_seed(false).unwrap();
        let builder = ProofBuilder::new(&keychain);
        let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
        let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
        let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

        let tx = transaction(
            KernelFeatures::Plain { fee: 2 },
            vec![input(10, key_id1), input(12, key_id2), output(20, key_id3)],
            &keychain,
            &builder,
        )
        .unwrap();

        tx.validate(Weighting::AsTransaction).unwrap();
    }

    #[test]
    fn blind_simpler_tx() {
        let keychain = ExtKeychain::from_random_seed(false).unwrap();
        let builder = ProofBuilder::new(&keychain);
        let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
        let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();

        let tx = transaction(
            KernelFeatures::Plain { fee: 4 },
            vec![input(6, key_id1), output(2, key_id2)],
            &keychain,
            &builder,
        )
        .unwrap();

        tx.validate(Weighting::AsTransaction).unwrap();
    }
}
