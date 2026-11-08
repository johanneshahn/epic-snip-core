// Copyright 2026 The Epic Cash Developers
//
// Real wallet adapter: bridges `epic_snip_wallet` to `epic_chain::Chain`
// without duplicating consensus or cryptographic logic. `epic_chain` stays
// chain-agnostic at the library level; this module is the single, reusable
// integration point for wallet code that needs a concrete `ChainView`.

use epic_core as core;
use epic_core::core::hash::Hashed;
use epic_snip_wallet::{ChainView, ChainViewError};
use epic_util as util;

use crate::Chain;

/// A concrete [`ChainView`] over an [`epic_chain::Chain`].
///
/// This is the adapter production wallet code should use instead of
/// re-implementing the trait per call site.
pub struct SnipChainView<'a> {
    pub chain: &'a Chain,
}

impl<'a> ChainView for SnipChainView<'a> {
    fn tip_height(&self) -> u64 {
        self.chain.head_header().unwrap().height
    }

    fn block_at_height(&self, height: u64) -> Option<core::core::Block> {
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

    fn is_unspent(&self, id: &core::core::OutputIdentifier) -> Result<(), ChainViewError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use epic_snip_wallet::SnipWallet;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn adapter_implements_chain_view() {
        // Smoke test: the adapter compiles and can be constructed.
        let _ = std::marker::PhantomData::<SnipChainView>;
    }
}