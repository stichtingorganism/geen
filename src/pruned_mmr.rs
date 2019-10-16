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