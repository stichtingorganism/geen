//! M...M...R...

use mohan::hash::{
    H256,
    BlakeHasher
};
use crate::{
    Storage,
    algos::{ bintree_height, find_peaks, leaf_index, peak_map_height, n_leaves },
    GeneError,
};
use std::cmp::{
    max,
    min
};

/// An implementation of a Merkle Mountain Range (MMR). The MMR is append-only and immutable. Only the hashes are
/// stored in this data structure. The data itself can be stored anywhere as long as you can maintain a 1:1 mapping
/// of the hash of that data to the leaf nodes in the MMR.
#[derive(Debug)]
pub struct MerkleMountainRange<B>
where B: Storage
{
    pub(crate) hashes: B
}

impl<B> MerkleMountainRange<B>
where
    B: Storage<Value = H256>,
{
    /// Create a new Merkle mountain range using the given backend for storage
    pub fn new(backend: B) -> MerkleMountainRange<B> {
        MerkleMountainRange {
            hashes: backend
        }
    }

    /// Clears the MMR and restores its state from a set of leaf hashes.
    pub fn restore(&mut self, leaf_hashes: Vec<H256>) -> Result<(), GeneError> {
        self.hashes
            .clear()
            .map_err(|e| GeneError::BackendError(e.to_string()))?;
        for hash in leaf_hashes {
            self.push(&hash)?;
        }
        Ok(())
    }

    /// Return the number of nodes in the full Merkle Mountain range, excluding bagged hashes
    #[inline(always)]
    pub fn len(&self) -> Result<usize, GeneError> {
        self.hashes
            .len()
            .map_err(|e| GeneError::BackendError(e.to_string()))
    }

    /// Returns true if the MMR contains no hashes
    pub fn is_empty(&self) -> Result<bool, GeneError> {
        Ok(self.len()? == 0)
    }

    /// This function returns the hash of the node index provided indexed from 0
    pub fn get_node_hash(&self, node_index: usize) -> Result<Option<H256>, GeneError> {
        self.hashes
            .get(node_index)
            .map_err(|e| GeneError::BackendError(e.to_string()))
    }

    /// This function returns the hash of the leaf index provided, indexed from 0
    pub fn get_leaf_hash(&self, leaf_node_index: usize) -> Result<Option<H256>, GeneError> {
        self.get_node_hash(leaf_index(leaf_node_index))
    }

    /// Returns the number of leaf nodes in the MMR.
    pub fn get_leaf_count(&self) -> Result<usize, GeneError> {
        Ok(n_leaves(self.len()?))
    }

    /// Returns a set of leaf hashes from the MMR.
    pub fn get_leaf_hashes(&self, index: usize, count: usize) -> Result<Vec<H256>, GeneError> {
        let leaf_count = self.get_leaf_count()?;
        if index >= leaf_count {
            return Ok(Vec::new());
        }
        let count = max(1, count);
        let last_index = min(index + count - 1, leaf_count);
        let mut leaf_hashes = Vec::with_capacity((last_index - index + 1) as usize);
        for index in index..=last_index {
            if let Some(hash) = self.get_leaf_hash(index)? {
                leaf_hashes.push(hash);
            }
        }
        Ok(leaf_hashes)
    }

    /// This function will return the single merkle root of the MMR by simply hashing the peaks together.
    ///
    /// Note that this differs from the bagging strategy used in other MMR implementations, and saves you a few hashes
    pub fn get_merkle_root(&self) -> Result<H256, GeneError> {
        if self.is_empty()? {
            return Ok(MerkleMountainRange::<B>::null_hash());
        }
        Ok(self.hash_to_root()?.finalize())
    }

    pub(crate) fn hash_to_root(&self) -> Result<BlakeHasher, GeneError> {
        let hasher = BlakeHasher::new();

        let peaks = find_peaks(
            self.hashes
                .len()
                .map_err(|e| GeneError::BackendError(e.to_string()))?,
        );
        Ok(peaks
            .into_iter()
            .map(|i| self.hashes.get_or_panic(i))
            .fold(hasher, |hasher, h| hasher.chain(h.as_bytes()))
        )
    }

    /// Push a new element into the MMR. Computes new related peaks at the same time if applicable.
    /// Returns the new length of the merkle mountain range (the number of all nodes, not just leaf nodes).
    pub fn push(&mut self, hash: &H256) -> Result<usize, GeneError> {
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
        Ok(pos)
    }

    /// Walks the nodes in the MMR and revalidates all parent hashes
    pub fn validate(&self) -> Result<(), GeneError> {
        // iterate on all parent nodes
        for n in 0..self
            .len()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
        {
            let height = bintree_height(n);

            if height > 0 {
                let hash = self
                    .get_node_hash(n)?
                    .ok_or(GeneError::CorruptDataStructure)?;

                let left_pos = n - (1 << height);
                let right_pos = n - 1;

                let left_child_hash = self
                    .get_node_hash(left_pos)?
                    .ok_or(GeneError::CorruptDataStructure)?;

                let right_child_hash = self
                    .get_node_hash(right_pos)?
                    .ok_or(GeneError::CorruptDataStructure)?;

                // hash the two child nodes together with parent_pos and compare
                let hash_check = left_child_hash.hash_with(right_child_hash);

                if hash_check != hash {
                    return Err(GeneError::InvalidMerkleTree);
                }
            }
        }
        Ok(())
    }

    /// Search for a given hash in the leaf node array. This is a very slow function, being O(n). In general, it's
    /// better to cache the index of the hash when storing it rather than using this function, but it's here for
    /// completeness. The index that is returned is the index of the _leaf node_, and not the MMR node index.
    pub fn find_leaf_node(&self, hash: &H256) -> Result<Option<usize>, GeneError> {
        for i in 0..self
            .hashes
            .len()
            .map_err(|e| GeneError::BackendError(e.to_string()))?
        {
            if *hash == self.hashes.get_or_panic(i) {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    pub(crate) fn null_hash() -> H256 {
        H256::zero()
    }

    fn push_hash(&mut self, hash: H256) -> Result<usize, GeneError> {
        self.hashes.push(hash).map_err(|e| {
            GeneError::BackendError(e.to_string())
        })
    }
}

impl<B, B2> PartialEq<MerkleMountainRange<B2>> for MerkleMountainRange<B>
where
    B: Storage<Value = H256>,
    B2: Storage<Value = H256>,
{
    fn eq(&self, other: &MerkleMountainRange<B2>) -> bool {
        (self.get_merkle_root() == other.get_merkle_root())
    }
}

