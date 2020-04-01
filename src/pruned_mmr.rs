//! Trimmed MMR methods

use crate::{
    pruned_hashset::PrunedHashSet,
    Storage,
    GeneError,
    MerkleMountainRange,
    MutableMmr,
};
use mohan::hash::H256;
use std::convert::TryFrom;


pub type PrunedMmr = MerkleMountainRange<PrunedHashSet>;
pub type PrunedMutableMmr = MutableMmr<PrunedHashSet>;

/// Create a pruned Merkle Mountain Range from the provided MMR. Pruning entails throwing all the hashes of the
/// pruned MMR away, except for the current peaks. A new MMR instance is returned that allows you to continue
/// adding onto the MMR as before. Most functions of the pruned MMR will work as expected, but obviously, any
/// leaf hashes prior to the base point won't be available. `get_leaf_hash` will return `None` for those nodes, and
/// `validate` will throw an error.
pub fn prune_mmr<B>(mmr: &MerkleMountainRange<B>) -> Result<PrunedMmr, GeneError>
where
    B: Storage<Value = H256>,
{
    let backend = PrunedHashSet::try_from(mmr)?;

    Ok(MerkleMountainRange {
        hashes: backend
    })
}

/// A convenience function in the same vein as [prune_mmr], but applied to `MutableMmr` instances.
pub fn prune_mutable_mmr<B>(mmr: &MutableMmr<B>) -> Result<PrunedMutableMmr, GeneError>
where
    B: Storage<Value = H256>,
{
    let backend = PrunedHashSet::try_from(&mmr.mmr)?;
    Ok(MutableMmr {
        mmr: MerkleMountainRange::new(backend),
        deleted: mmr.deleted.clone(),
        size: mmr.size,
    })
}

/// `calculate_mmr_root`` takes an MMR instance and efficiently calculates the new MMR root by applying the given
/// additions to calculate a new MMR root without changing the original MMR.
///
/// This is done by creating a memory-backed sparse (pruned) copy of the original MMR, applying the changes and then
/// calculating a new root.
///
/// # Parameters
/// * `src`: A reference to the original MMR
/// * `additions`: A vector of leaf node hashes to append to the MMR
/// * `deletions`: A vector of leaf node _indices_ that will be marked as deleted.
///
/// # Returns
/// The new MMR root as a result of applying the given changes
pub fn calculate_pruned_mmr_root<B>(
    src: &MutableMmr<B>,
    additions: Vec<H256>,
    deletions: Vec<u32>,
) -> Result<H256, GeneError>
where
    B: Storage<Value = H256>,
{
    let mut pruned_mmr = prune_mutable_mmr(src)?;
    for hash in additions {
        pruned_mmr.push(&hash)?;
    }
    for index in deletions {
        pruned_mmr.delete(index);
    }

    Ok(pruned_mmr.get_merkle_root()?)
}

pub fn calculate_mmr_root<B>(
    src: &MerkleMountainRange<B>,
    additions: Vec<H256>,
) -> Result<H256, GeneError>
where
    B: Storage<Value = H256>,
{
    let mut mmr = prune_mmr(src)?;
    for hash in additions {
        mmr.push(&hash)?;
    }
    Ok(mmr.get_merkle_root()?)
}