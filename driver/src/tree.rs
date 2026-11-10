//! A settlement pool's note tree, rebuilt client-side from its public commitments.
//!
//! Same tree the validators keep (iroha_core privacy_engines/proof_managed_accumulator.rs @
//! 071e281e): append-only, depth 32, SHA-256 with typed leaf/node/empty-leaf domains. Upstream
//! only exposes paths for a fresh two-note pool (`plan_atomic_private_settlement_bootstrap_v1`);
//! keeping every leaf here gives a Merkle path for any note, so a received note can be spent in
//! a later bundle of the same pool.

use eyre::{Result, ensure, eyre};
use iroha::data_model::privacy::{
    PrivacyCommitmentV1, PrivacyNamespaceScopeV1, PrivacyNamespaceV1,
    PrivacyPoolIdV1, PrivacyPoolProgramNamespaceV1, PrivacyProtocolIdV1, PrivacyRootV1,
};
use iroha_core::privacy_engines::atomic_private_settlement::atomic_private_settlement_program_id_v1;
use sha2::{Digest as _, Sha256};

pub const DEPTH: usize = 32;
pub type Path32 = [[u8; 32]; DEPTH];

const EMPTY_LEAF: &[u8] = b"iroha.privacy.proof-managed-note-tree.empty-leaf.v1";
const LEAF: &[u8] = b"iroha.privacy.proof-managed-note-tree.leaf.v1";
const NODE: &[u8] = b"iroha.privacy.proof-managed-note-tree.node.v1";

fn node(level: usize, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NODE);
    h.update([u8::try_from(level).expect("depth-32 level fits u8")]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of an empty subtree at each level 0..=DEPTH.
fn empty_roots() -> [[u8; 32]; DEPTH + 1] {
    let mut out = [[0; 32]; DEPTH + 1];
    out[0] = Sha256::digest(EMPTY_LEAF).into();
    for level in 0..DEPTH {
        out[level + 1] = node(level, &out[level], &out[level]);
    }
    out
}

#[derive(Clone)]
pub struct PoolTree {
    namespace_bytes: Vec<u8>,
    commitments: Vec<PrivacyCommitmentV1>,
    leaves: Vec<[u8; 32]>,
}

impl PoolTree {
    pub fn new(pool_id: PrivacyPoolIdV1) -> Result<Self> {
        let namespace = PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
                pool_id,
                program_id: atomic_private_settlement_program_id_v1()?,
            }),
        );
        Ok(Self { namespace_bytes: norito::to_bytes(&namespace)?, commitments: Vec::new(), leaves: Vec::new() })
    }

    /// Append in ledger order: the sorted origin pair, then each finalized leg's three outputs.
    pub fn append(&mut self, commitments: &[PrivacyCommitmentV1]) -> Result<()> {
        for c in commitments {
            ensure!(!c.is_zero(), "zero commitment");
            ensure!(!self.commitments.contains(c), "duplicate commitment");
            ensure!(self.leaves.len() < (1usize << DEPTH), "note tree is full");
            let mut h = Sha256::new();
            h.update(LEAF);
            h.update(u64::try_from(self.namespace_bytes.len())?.to_be_bytes());
            h.update(&self.namespace_bytes);
            h.update(c.as_bytes());
            self.leaves.push(h.finalize().into());
            self.commitments.push(*c);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn position(&self, commitment: PrivacyCommitmentV1) -> Option<usize> {
        self.commitments.iter().position(|c| *c == commitment)
    }

    pub fn root(&self) -> PrivacyRootV1 {
        PrivacyRootV1::new(self.walk(None).0)
    }

    /// Authentication path (sibling per level, leaf level first) for the leaf at `position`.
    pub fn path(&self, position: usize) -> Result<Path32> {
        ensure!(position < self.leaves.len(), "no leaf at position {position}");
        self.walk(Some(position)).1.ok_or_else(|| eyre!("path"))
    }

    // ponytail: rebuilds the tree from all leaves, O(n) per call; keep a frontier if pools reach 10^5 notes
    fn walk(&self, target: Option<usize>) -> ([u8; 32], Option<Path32>) {
        let empty = empty_roots();
        let mut level_nodes = self.leaves.clone();
        let mut position = target;
        let mut path = [[0u8; 32]; DEPTH];
        for level in 0..DEPTH {
            if let Some(p) = position {
                path[level] = level_nodes.get(p ^ 1).copied().unwrap_or(empty[level]);
                position = Some(p >> 1);
            }
            level_nodes = level_nodes
                .chunks(2)
                .map(|pair| node(level, &pair[0], pair.get(1).unwrap_or(&empty[level])))
                .collect();
        }
        let root = level_nodes.first().copied().unwrap_or(empty[DEPTH]);
        (root, target.map(|_| path))
    }
}

/// Root implied by a leaf's commitment, position and path (what the prover checks).
pub fn root_from_path(tree: &PoolTree, commitment: PrivacyCommitmentV1, mut position: usize, path: &Path32) -> Result<PrivacyRootV1> {
    let at = tree.position(commitment).ok_or_else(|| eyre!("unknown commitment"))?;
    let mut acc = tree.leaves[at];
    for (level, sibling) in path.iter().enumerate() {
        acc = if position & 1 == 0 { node(level, &acc, sibling) } else { node(level, sibling, &acc) };
        position >>= 1;
    }
    Ok(PrivacyRootV1::new(acc))
}

#[cfg(test)]
mod tests {
    use iroha_core::privacy_engines::atomic_private_settlement::plan_atomic_private_settlement_bootstrap_v1;

    use super::*;

    fn rnd() -> [u8; 32] {
        rand::random()
    }

    #[test]
    fn tree_matches_upstream_bootstrap_plan() {
        let pool_id = PrivacyPoolIdV1::new(rnd());
        let inputs = [PrivacyCommitmentV1::new(rnd()), PrivacyCommitmentV1::new(rnd())];
        let outputs = [PrivacyCommitmentV1::new(rnd()), PrivacyCommitmentV1::new(rnd()), PrivacyCommitmentV1::new(rnd())];
        let plan = plan_atomic_private_settlement_bootstrap_v1(pool_id, inputs, outputs, [rnd(), rnd()]).unwrap();

        let mut tree = PoolTree::new(pool_id).unwrap();
        tree.append(&plan.initial_commitments).unwrap();
        assert_eq!(tree.root(), plan.old_root);
        for c in inputs {
            let at = tree.position(c).unwrap();
            assert_eq!(root_from_path(&tree, c, at, &tree.path(at).unwrap()).unwrap(), plan.old_root);
        }
        tree.append(&outputs).unwrap();
        assert_eq!(tree.root(), plan.new_root);
        // a received output (leaf 2) gets a valid path in the successor tree
        let at = tree.position(outputs[0]).unwrap();
        assert_eq!(at, 2);
        assert_eq!(root_from_path(&tree, outputs[0], at, &tree.path(at).unwrap()).unwrap(), plan.new_root);
    }

    #[test]
    fn append_rejects_duplicates_and_zero() {
        let mut tree = PoolTree::new(PrivacyPoolIdV1::new(rnd())).unwrap();
        let c = PrivacyCommitmentV1::new(rnd());
        tree.append(&[c]).unwrap();
        assert!(tree.append(&[c]).is_err());
        assert!(tree.append(&[PrivacyCommitmentV1::new([0; 32])]).is_err());
    }
}
