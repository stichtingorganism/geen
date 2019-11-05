//! Trimmed MMR

use crate::{
    algos::find_peaks, 
    GeneError, 
    Storage, 
    MerkleMountainRange
};
use mohan::hash::{
    H256
};
use std::convert::TryFrom;

/// This is a specialised struct that represents a pruned hash set for Merkle Mountain Ranges.
///
/// The basic idea is that when adding a new hash, only the peaks to the left of the new node hierarchy are ever needed.
/// This means that if we don't care about the data earlier than a given leaf node index, n_0, (i.e. we still have the
/// hashes, but can't recalculate them from source), we _only need to store the local peaks for the MMR at that time_
/// and we can forget about the rest. There will never be a request for a hash other than those at the peaks for the
/// MMR with n_0 leaf nodes.
///
/// The awesome thing is that this struct can be dropped into [MerkleMountainRange] as a backend and it. just. works.
#[derive(Debug)]
pub struct PrunedHashSet {
    /// The size of the base MMR. Only peaks are available for indices less than this value
    base_offset: usize,
    /// The array of peak indices for an MMR of size `base_offset`
    peak_indices: Vec<usize>,
    /// The array of hashes at the MMR peaks
    peak_hashes: Vec<H256>,
    /// New hashes added subsequent to `base_offset`.
    hashes: Vec<H256>,
}

impl<B> TryFrom<&MerkleMountainRange<B>> for PrunedHashSet
where
    B: Storage<Value = H256>,
{
    type Error = GeneError;

    fn try_from(base_mmr: &MerkleMountainRange<B>) -> Result<Self, Self::Error> {
        let base_offset = base_mmr.len()?;
        let peak_indices = find_peaks(base_offset);
        let peak_hashes = peak_indices
            .iter()
            .map(|i| match base_mmr.get_node_hash(*i)? {
                Some(h) => Ok(h.clone()),
                None => Err(GeneError::HashNotFound(*i)),
            })
            .collect::<Result<_, _>>()?;

        Ok(PrunedHashSet {
            base_offset,
            peak_indices,
            peak_hashes,
            hashes: Vec::new(),
        })
    }
}

impl Storage for PrunedHashSet {
    type Error = GeneError;
    type Value = H256;

    #[inline(always)]
    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.base_offset + self.hashes.len())
    }

    fn push(&mut self, item: Self::Value) -> Result<usize, Self::Error> {
        self.hashes.push(item);
        Ok(self.len()? - 1)
    }

    fn get(&self, index: usize) -> Result<Option<Self::Value>, Self::Error> {
        // If the index is from before we started adding hashes, we can return the hash *if and only if* it is a peak
        if index < self.base_offset {
            return Ok(match self.peak_indices.binary_search(&index) {
                Ok(nth_peak) => Some(self.peak_hashes[nth_peak].clone()),
                Err(_) => None,
            });
        }
        Ok(self.hashes.get(index - self.base_offset)?)
    }

    fn get_or_panic(&self, index: usize) -> Self::Value {
        self.get(index)
            .unwrap()
            .expect("PrunedHashSet only tracks peaks before the offset")
            .clone()
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
         self.base_offset = 0;
         self.peak_indices.clear();
         self.peak_hashes.clear();
         self.hashes.clear();
         Ok(())
     }
}