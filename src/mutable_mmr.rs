//! A MMR varient that enables evolution

use crate::{
    Storage,
    algos::{leaf_index, n_leaves},
    GeneError,
    MerkleMountainRange,
    Bitmap,
    MutableMmrLeafNodes
};
use mohan::hash::{
    BlakeHasher,
    H256
};


/// Unlike a pure MMR, which is append-only, in `MutableMmr`, leaf nodes can be marked as deleted.
///
/// In `MutableMmr` a roaring bitmap tracks which data have been marked as deleted, and the merklish root is modified
/// to include the hash of the roaring bitmap.
///
/// The `MutableMmr` API maps nearly 1:1 to that of MerkleMountainRange so that you should be able to use it as a
/// drop-in replacement for the latter in most cases.
#[derive(Debug)]
pub struct MutableMmr<B>
where
    B: Storage<Value = H256>,
{
    pub(crate) mmr: MerkleMountainRange<B>,
    pub(crate) deleted: Bitmap,
    // The number of leaf nodes in the MutableMmr. Bitmap is limited to 4 billion elements, which is plenty.
    // [croaring::Treemap] is a 64bit alternative, but this would break things on 32bit systems. A good TODO would be
    // to select the bitmap backend using a feature flag
    pub(crate) size: u32,
}

impl<B> MutableMmr<B>
where
    B: Storage<Value = H256>,
{
    /// Create a new mutable MMR using the backend provided
    pub fn new(mmr_backend: B) -> MutableMmr<B> {
        let mmr = MerkleMountainRange::new(mmr_backend);
        MutableMmr {
            mmr,
            deleted: Bitmap::create(),
            size: 0,
        }
    }

    /// Reset the MutableMmr and restore the MMR state from the set of leaf_hashes and deleted nodes.
    pub fn restore(&mut self, state: MutableMmrLeafNodes) -> Result<(), GeneError> {
        self.mmr.restore(state.leaf_hashes)?;
        self.deleted = state.deleted;
        self.size = self.mmr.get_leaf_count()? as u32;
        Ok(())
    }

    /// Return the number of leaf nodes in the `MutableMmr` that have not been marked as deleted.
    ///
    /// NB: This is semantically different to `MerkleMountainRange::len()`. The latter returns the total number of
    /// nodes in the MMR, while this function returns the number of leaf nodes minus the number of nodes marked for
    /// deletion.
    #[inline(always)]
    pub fn len(&self) -> u32 {
        self.size - self.deleted.cardinality() as u32
    }

    /// Returns true if the the MMR contains no nodes, OR all nodes have been marked for deletion
    pub fn is_empty(&self) -> Result<bool, GeneError> {
        Ok(self.mmr.is_empty()? || self.deleted.cardinality() == self.size as u64)
    }

    /// This function returns the hash of the leaf index provided, indexed from 0. If the hash does not exist, or if it
    /// has been marked for deletion, `None` is returned.
    pub fn get_leaf_hash(&self, leaf_node_index: u32) -> Result<Option<H256>, GeneError> {
        if self.deleted.contains(leaf_node_index) {
            return Ok(None);
        }

        self.mmr.get_node_hash(leaf_index(leaf_node_index as usize))
    }

    /// Returns the hash of the leaf index provided, as well as its deletion status. The node has been marked for
    /// deletion if the boolean value is true.
    pub fn get_leaf_status(&self, leaf_node_index: u32) -> Result<(Option<H256>, bool), GeneError> {
        let hash = self.mmr.get_node_hash(leaf_index(leaf_node_index as usize))?;
        let deleted = self.deleted.contains(leaf_node_index);
        Ok((hash, deleted))
    }

    /// Returns the number of leave nodes in the MMR.
    pub fn get_leaf_count(&self) -> usize {
        self.size as usize
    }

    /// Returns a merkle(ish) root for this merkle set.
    ///
    /// The root is calculated by concatenating the MMR merkle root with the compressed serialisation of the bitmap
    /// and then hashing the result.
    pub fn get_merkle_root(&self) -> Result<H256, GeneError> {
        // Note that two MutableMmrs could both return true for `is_empty()`, but have different merkle roots by
        // virtue of the fact that the underlying MMRs could be different, but all elements are marked as deleted in
        // both sets.
        let mmr_root = self.mmr.get_merkle_root()?;
        let mut hasher = BlakeHasher::new();
        hasher.write(mmr_root.as_bytes());
        Ok(self.hash_deleted(hasher))
    }

    /// Returns only the MMR merkle root without the compressed serialisation of the bitmap
    pub fn get_mmr_only_root(&self) -> Result<H256, GeneError> {
        self.mmr.get_merkle_root()
    }

    /// See [MerkleMountainRange::find_node_index]
    pub fn find_node_index(&self, hash: &H256) -> Result<Option<usize>, GeneError> {
        self.mmr.find_node_index(hash)
    }

     /// See [MerkleMountainRange::find_leaf_index]
     pub fn find_leaf_index(&self, hash: &H256) -> Result<Option<usize>, GeneError> {
        self.mmr.find_leaf_index(hash)
    }

    /// Push a new element into the MMR. Computes new related peaks at the same time if applicable.
    /// Returns the new number of leaf nodes (regardless of deleted state) in the mutable MMR
    pub fn push(&mut self, hash: &H256) -> Result<usize, GeneError> {
        if self.size >= std::u32::MAX {
            return Err(GeneError::MaximumSizeReached);
        }
        
        let result = self.mmr.push(hash);
        if result.is_ok() {
            self.size += 1;
        }
        Ok(self.size as usize)
    }

    /// Mark a node for deletion and optionally compress the deletion bitmap. Don't call this function unless you're
    /// in a tight loop and want to eke out some extra performance by delaying the bitmap compression until after the
    /// batch deletion.
    ///
    /// Note that this function doesn't actually
    /// delete anything (the underlying MMR structure is immutable), but marks the leaf node as deleted. Once a leaf
    /// node has been marked for deletion:
    /// * `get_leaf_hash(n)` will return None,
    /// * `len()` will not count this node anymore
    ///
    /// # Parameters
    /// * `leaf_node_index`: The index of the leaf node to mark for deletion, zero-based.
    /// * `compress`: Indicates whether the roaring bitmap should be compressed after marking the node for deletion.
    /// **NB**: You should set this to true unless you are in a loop and deleting multiple nodes, and you **must** set
    /// this to true if you are about to call `get_merkle_root()`. If you don't, the merkle root will be incorrect.
    ///
    /// # Return
    /// The function returns true if a node was actually marked for deletion. If the index is out of bounds, or was
    /// already deleted, the function returns false.
    pub fn delete_and_compress(&mut self, leaf_node_index: u32, compress: bool) -> bool {
        if (leaf_node_index >= self.size) || self.deleted.contains(leaf_node_index) {
            return false;
        }
        self.deleted.add(leaf_node_index);
        // The serialization is different in compressed vs. uncompressed form, but the merkle root must be 100%
        // deterministic based on input, so just be consistent an use the compressed form all the time.
        if compress {
            self.compress();
        }
        true
    }

    /// Mark a node for completion, and compress the roaring bitmap. See [delete_and_compress] for details.
    pub fn delete(&mut self, leaf_node_index: u32) -> bool {
        self.delete_and_compress(leaf_node_index, true)
    }

    /// Compress the roaring bitmap mapping deleted nodes. You never have to call this method unless you have been
    /// calling [delete_and_compress] with `compress` set to `false` ahead of a call to [get_merkle_root].
    pub fn compress(&mut self) -> bool {
        self.deleted.run_optimize()
    }

    /// Walks the nodes in the MMR and validates all parent hashes
    ///
    /// This just calls through to the underlying MMR's validate method. There's nothing we can do to check whether
    /// the roaring bitmap represents all the leaf nodes that we want to delete. Note: A struct that uses
    /// `MutableMmr` and links it to actual data should be able to do this though.
    pub fn validate(&self) -> Result<(), GeneError> {
        self.mmr.validate()
    }

    /// Hash the roaring bitmap of nodes that are marked for deletion
    fn hash_deleted(&self, mut hasher: BlakeHasher) -> H256 {
        let bitmap_ser = self.deleted.serialize();
        hasher.write(&bitmap_ser);
        hasher.finalize()
    }

    // Returns a bitmap with only the deleted nodes for the specified region in the MMR.
    fn get_sub_bitmap(&self, index: usize, count: usize) -> Result<Bitmap, GeneError> {
        let mut deleted = self.deleted.clone();
        if index > 0 {
            deleted.remove_range_closed(0..(index - 1) as u32)
        }
        let leaf_count = self.mmr.get_leaf_count()?;
        if leaf_count > 1 {
            let last_index = index + count - 1;
            if last_index < leaf_count - 1 {
                deleted.remove_range_closed((last_index + 1) as u32..leaf_count as u32);
            }
        }
        Ok(deleted)
    }

    /// Returns the state of the MMR that consists of the leaf hashes and the deleted nodes.
    pub fn to_leaf_nodes(&self, index: usize, count: usize) -> Result<MutableMmrLeafNodes, GeneError> {
        Ok(MutableMmrLeafNodes {
            leaf_hashes: self.mmr.get_leaf_hashes(index, count)?,
            deleted: self.get_sub_bitmap(index, count)?,
        })
    }

    /// Expose the MerkleMountainRange for verifying proofs
    pub fn mmr(&self) -> &MerkleMountainRange<B> {
        &self.mmr
    }

    /// Return a reference to the bitmap of deleted nodes
    pub fn deleted(&self) -> &Bitmap {
        &self.deleted
    }

    pub fn clear(&mut self) -> Result<(), GeneError> {
        self.mmr.clear()?;
        self.deleted = Bitmap::create();
        self.size = 0;
        Ok(())
    }
}

impl<B, B2> PartialEq<MutableMmr<B2>> for MutableMmr<B>
where
    B: Storage<Value = H256>,
    B2: Storage<Value = H256>,
{
    fn eq(&self, other: &MutableMmr<B2>) -> bool {
        self.get_merkle_root() == other.get_merkle_root()
    }
}

impl<B> From<MerkleMountainRange<B>> for MutableMmr<B>
where
    B: Storage<Value = H256>,
{
    fn from(mmr: MerkleMountainRange<B>) -> Self {
        let size = n_leaves(mmr.len().unwrap()) as u32; // TODO: fix unwrap
        MutableMmr {
            mmr,
            deleted: Bitmap::create(),
            size,
        }
    }
}