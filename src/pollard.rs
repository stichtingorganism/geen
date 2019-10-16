//! Pollard: Hash based Accumulator for a UTXO set 

use crate::{
    storage::Storage,
    //algos::{ bintree_height, find_peaks, leaf_index, peak_map_height },
    GeneError,
};
use mohan::{
    hash::H256,
    varint::VarInt
};
use serde::{Deserialize, Serialize};


/// An implementation of a Dynamic Hash Accumulator. The Accumulator is forest of binary merkle Trees. 
/// Only the hashes of the roots are stored. Items and be added and deleted through item witnesses that 
/// are presented to this data structure. The data itself is stored by the owners who must maintain their
/// proofs so that they can delete the item from the Accumulator. In the main use case UTXO are stored in this
/// data structure and validating nodes only store the peaks of the tree and clients sent transactions
/// with the merkle proof (witness) that it exists in the set.
#[derive(Debug)]
pub struct Pollard<B>
where B: Storage
{   
    /// Current Item Count
    count: u64,
    /// Stores the leaves
    pub(crate) leaves: B,
    /// The array of hashes at the MMR peaks
    pub(crate) peaks: [Option<H256>; 64],

    /// The array of peak indices for an MMR of size `base_offset`
    peak_indices: Vec<usize>,
    // /// The array of hashes at the MMR peaks
    // peak_hashes: Vec<H256>,
    /// The depth that we are caching the tree
    cache: usize,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub struct IncusionProof {
    /// Absolute position of an item in the tree.
    position: VarInt,
}

impl<B> Pollard<B>
where
    B: Storage<Value = H256>,
{
    /// Create a new Merkle mountain range using the given backend for storage
    pub fn new(backend: B) -> Pollard<B> {
        Pollard {
            leaves: backend,
            peaks: [None; 64]
        }
    }

    /// Total number of items in the Pollard.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Returns true if the MMR contains no hashes
    pub fn is_empty(&self) -> Result<bool, GeneError> {
        Ok(self.count() == 0)
    }

    /// Push a new element into the MMR. Computes new related peaks at the same time if applicable.
    /// Returns the new length of the merkle mountain range (the number of all nodes, not just leaf nodes).
    pub fn insert(&mut self, hash: &H256) -> Result<(), GeneError> {
        if self.is_empty()? {
            return self.push_hash(hash.clone());
        }

        let mut pos = self.len()?;
        let (peak_map, height) = peak_map_height(pos);

        if height != 0 {
            return Err(GeneError::CorruptDataStructure);
        }

        self.push_hash(hash.clone())?;

        // hash with all immediately preceding peaks, as indicated by peak map
        let mut peak = 1;
        while (peak_map & peak) != 0 {
            let left_sibling = pos + 1 - 2 * peak;
            let left_hash = &self.hashes.get_or_panic(left_sibling);
            peak *= 2;
            pos += 1;

            let hash_count = self
                .hashes
                .len()
                .map_err(|e| GeneError::BackendError(e.to_string()))?;

            let last_hash = &self.hashes.get_or_panic(hash_count - 1);
            let new_hash = left_hash.hash_with(last_hash);

            self.push_hash(new_hash)?;
        }

        // Ok(pos)
        Ok(())
    }

    //insert_batch(&mut self, items: Vec<H256>)
    //delete(&mut self, proof: MerkleProof) -> Result<(), GeneError> {}
    //delete_batch()
    //verification

    fn push_hash(&mut self, hash: H256) -> Result<usize, GeneError> {
        self.leaves.push(hash).map_err(|e| {
            GeneError::BackendError(e.to_string())
        })
    }



}