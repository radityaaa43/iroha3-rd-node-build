//! A pool's public history, read back from the chain.
//!
//! Sources (all public on every validator): the pool's origin commitments (the
//! `ActivatePrivateSettlementPoolV1` it was activated with, recorded by `pool-init`) and each
//! finalized bundle's receipt (`GET /v1/nexus/private-settlements/bundles/{id}/receipt`), whose
//! per-leg delta carries old/new root and epoch, nullifiers, output commitments and encrypted
//! outputs. The bundle-id index is ours (public, non-secret); the chain is the authority: every
//! delta must continue the previous root, and the rebuilt tree must reproduce each new root.

use std::collections::BTreeSet;

use eyre::{Result, ensure, eyre};
use iroha::data_model::{
    nexus::PrivateSettlementDeltaV1,
    privacy::{PrivacyCommitmentV1, PrivacyEncryptedOutputV1, PrivacyNullifierV1, PrivacyPoolIdV1, PrivacyRootV1},
};

use crate::tree::PoolTree;

pub struct OutputRow {
    pub commitment: PrivacyCommitmentV1,
    pub encrypted: PrivacyEncryptedOutputV1,
    pub bundle_id: String,
    pub height: u64,
}

pub struct PoolHistory {
    pub pool_id: PrivacyPoolIdV1,
    pub tree: PoolTree,
    pub epoch: u64,
    pub outputs: Vec<OutputRow>,
    pub nullifiers: BTreeSet<PrivacyNullifierV1>,
}

impl PoolHistory {
    /// Origin of a pool activated with `origin` (two commitments, any order) at epoch 1.
    pub fn new(pool_id: PrivacyPoolIdV1, origin: &[PrivacyCommitmentV1]) -> Result<Self> {
        let mut sorted = origin.to_vec();
        sorted.sort_unstable();
        let mut tree = PoolTree::new(pool_id)?;
        tree.append(&sorted)?;
        Ok(Self { pool_id, tree, epoch: 1, outputs: Vec::new(), nullifiers: BTreeSet::new() })
    }

    pub fn root(&self) -> PrivacyRootV1 {
        self.tree.root()
    }

    /// Apply one finalized leg of this pool, in ledger order. Rejects a delta that does not
    /// continue the current head or whose new root the rebuilt tree does not reproduce.
    pub fn apply(&mut self, delta: &PrivateSettlementDeltaV1, height: u64) -> Result<()> {
        ensure!(delta.pool_id == self.pool_id, "delta of another pool");
        ensure!(delta.old_epoch == self.epoch && delta.old_root == self.root(), "delta does not continue the pool head (epoch {})", self.epoch);
        ensure!(delta.output_commitments.len() == delta.encrypted_outputs.len(), "output shape");
        self.tree.append(&delta.output_commitments)?;
        ensure!(self.root() == delta.new_root, "rebuilt tree root differs from the finalized new root");
        self.epoch = delta.new_epoch;
        self.nullifiers.extend(delta.nullifiers.iter().copied());
        let bundle_id = hex::encode(delta.bundle_id.as_ref());
        for (commitment, encrypted) in delta.output_commitments.iter().zip(&delta.encrypted_outputs) {
            self.outputs.push(OutputRow { commitment: *commitment, encrypted: encrypted.clone(), bundle_id: bundle_id.clone(), height });
        }
        Ok(())
    }

    pub fn position(&self, commitment: PrivacyCommitmentV1) -> Result<usize> {
        self.tree.position(commitment).ok_or_else(|| eyre!("commitment not in pool"))
    }
}
