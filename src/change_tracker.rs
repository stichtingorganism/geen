//! Track Changes to a MMR, allows for rollback 


use std::{mem, ops::Deref};
use crate::{
    Storage,
    StorageExt,
    //algos::{ bintree_height, find_peaks, leaf_index, peak_map_height },
    GeneError,
    pruned_mmr::{prune_mutable_mmr, PrunedMutableMmr},
    MutableMmr,
    Bitmap
};
use mohan::hash::{
    H256
};

/// A struct that wraps an MMR to keep track of changes to the MMR over time. This enables one to roll
/// back changes to a point in history. Think of `MerkleChangeTracker` as 'git' for MMRs.
///
/// [MutableMMr] implements [std::ops::Deref], so that once you've wrapped the MMR, all the immutable methods are
/// available through the auto-dereferencing.
///
/// The basic philosophy of `MerkleChangeTracker` is as follows:
/// * Start with a 'base' MMR. For efficiency, you usually want to make this a [pruned_mmr::PrunedMmr], but it
/// doesn't have to be.
/// * We then maintain a change-list for every append and delete that is made on the MMR.
/// * You can `commit` the change-set at any time, which will create a new [MerkleCheckPoint] summarising the
/// changes, and the current change-set is reset.
/// * You can `rewind` to a previously committed checkpoint, p. This entails resetting the MMR to the base state and
/// then replaying every checkpoint in sequence until checkpoint p is reached. `rewind_to_start` and `replay` perform
/// similar functions.
/// * You can `reset` the ChangeTracker, which clears the current change-set and moves you back to the most recent
/// checkpoint ('HEAD')
#[derive(Debug)]
pub struct MerkleChangeTracker<BaseBackend, CpBackend>
where
    BaseBackend: Storage<Value = H256>,
{
    base: MutableMmr<BaseBackend>,
    mmr: PrunedMutableMmr,

    checkpoints: CpBackend,
    // The hashes added since the last commit
    current_additions: Vec<H256>,
    // The deletions since the last commit
    current_deletions: Bitmap,
}


impl<BaseBackend, CpBackend> MerkleChangeTracker<BaseBackend, CpBackend>
where
    BaseBackend: Storage<Value = H256>,
    CpBackend: Storage<Value = MerkleCheckPoint> + StorageExt<Value = MerkleCheckPoint>,
{
    /// Wrap an MMR inside a change tracker.
    ///
    /// # Parameters
    /// * `base`: The base, or anchor point of the change tracker. This represents the earliest point that you can
    ///   [MerkleChangeTracker::rewind] to.
    /// * `mmr`: An empty MMR instance that will be used to maintain the current state of the MMR.
    /// * `diffs`: The (usually empty) collection of diffs that will be used to store the MMR checkpoints.
    ///
    /// # Returns
    /// A new `MerkleChangeTracker` instance that is configured using the MMR and ChangeTracker instances provided.
    pub fn new(
        base: MutableMmr<BaseBackend>,
        diffs: CpBackend,
    ) -> Result<MerkleChangeTracker<BaseBackend, CpBackend>, GeneError>
    {
        let mmr = prune_mutable_mmr::<_>(&base)?;
        Ok(MerkleChangeTracker {
            base,
            mmr,
            checkpoints: diffs,
            current_additions: Vec::new(),
            current_deletions: Bitmap::create(),
        })
    }

    /// Return the number of Checkpoints this change tracker has recorded
    pub fn checkpoint_count(&self) -> Result<usize, GeneError> {
        self.checkpoints
            .len()
            .map_err(|e| GeneError::BackendError(e.to_string()))
    }

    /// Push the given hash into the MMR and update the current change-set
    pub fn push(&mut self, hash: &H256) -> Result<usize, GeneError> {
        let result = self.mmr.push(hash)?;
        self.current_additions.push(hash.clone());
        Ok(result)
    }

    /// Discards the current change-set and resets the MMR state to that of the last checkpoint
    pub fn reset(&mut self) -> Result<(), GeneError> {
        self.replay(self.checkpoint_count()?)
    }

    /// Mark a node for deletion and optionally compress the deletion bitmap. See [MutableMmr::delete_and_compress]
    /// for more details
    pub fn delete_and_compress(&mut self, leaf_node_index: u32, compress: bool) -> bool {
        let result = self.mmr.delete_and_compress(leaf_node_index, compress);

        if result {
            self.current_deletions.add(leaf_node_index)
        }
        result
    }

    /// Mark a node for completion, and compress the roaring bitmap. See [delete_and_compress] for details.
    pub fn delete(&mut self, leaf_node_index: u32) -> bool {
        self.delete_and_compress(leaf_node_index, true)
    }

    /// Compress the roaring bitmap mapping deleted nodes. You never have to call this method unless you have been
    /// calling [delete_and_compress] with `compress` set to `false` ahead of a call to [get_merkle_root].
    pub fn compress(&mut self) -> bool {
        self.mmr.compress()
    }

    /// Commit the change history since the last commit to a new [MerkleCheckPoint] and clear the current change set.
    pub fn commit(&mut self) -> Result<(), CpBackend::Error> {
        let mut hash_set = Vec::new();
        mem::swap(&mut hash_set, &mut self.current_additions);

        let mut deleted_set = Bitmap::create();
        mem::swap(&mut deleted_set, &mut self.current_deletions);

        let diff = MerkleCheckPoint::new(hash_set, deleted_set);
        self.checkpoints.push(diff)?;

        Ok(())
    }

    /// Rewind the MMR state by the given number of Checkpoints.
    ///
    /// Example:
    ///
    /// Assuming we start with an empty Mutable MMR, and apply the following:
    /// push(1), push(2), delete(1), *Checkpoint*  (1)
    /// push(3), push(4)             *Checkpoint*  (2)
    /// push(5), delete(4)           *Checkpoint*  (3)
    /// push(6)
    ///
    /// The state is now:
    /// ```text
    /// 1 2 3 4 5 6
    /// x     x
    /// ```
    ///
    /// After calling `rewind(1)`, The push of 6 wasn't check-pointed, so it will be discarded, and rewinding back one
    /// point to checkpoint 2 the state will be:
    /// ```text
    /// 1 2 3 4
    /// x
    /// ```
    ///
    /// Calling `rewind(1)` again will yield:
    /// ```text
    /// 1 2
    /// x
    /// ```
    pub fn rewind(&mut self, steps_back: usize) -> Result<(), GeneError> {
        self.replay(self.checkpoint_count()? - steps_back)
    }

    /// Rewinds the MMR back to the state of the base MMR; essentially discarding all the history accumulated to date.
    pub fn rewind_to_start(&mut self) -> Result<(), GeneError> {
        self.mmr = self.revert_mmr_to_base()?;
        Ok(())
    }

    // Common function for rewind_to_start and replay
    fn revert_mmr_to_base(&mut self) -> Result<PrunedMutableMmr, GeneError> {
        let mmr = prune_mutable_mmr::<_>(&self.base)?;
        self.current_deletions = Bitmap::create();
        self.current_additions = Vec::new();

        Ok(mmr)
    }

    /// Similar to [MerkleChangeTracker::rewind], `replay` moves the MMR state through checkpoints, but uses the base
    /// MMR as the starting point and steps forward through `num_checkpoints` checkpoints, rather than rewinding from
    /// the current state.
    pub fn replay(&mut self, num_checkpoints: usize) -> Result<(), GeneError> {
        let mut mmr = self.revert_mmr_to_base()?;
        self.checkpoints.truncate(num_checkpoints)?;
        let mut result = Ok(());

        self.checkpoints.for_each(|v| {
            if result.is_err() {
                return;
            }
            result = match v {
                Ok(cp) => cp.apply(&mut mmr),
                Err(e) => Err(e),
            };
        })?;

        mmr.compress();
        self.mmr = mmr;

        result
    }

    pub fn get_checkpoint(&self, index: usize) -> Result<MerkleCheckPoint, GeneError> {
        match self
            .checkpoints
            .get(index)
            .map_err(|e| GeneError::BackendError(e.to_string()))?
        {
            None => Err(GeneError::OutOfRange),
            Some(cp) => Ok(cp.clone()),
        }
    }
}

impl<BaseBackend, DiffBackend> Deref for MerkleChangeTracker<BaseBackend, DiffBackend>
where
    BaseBackend: Storage<Value = H256>,
{
    type Target = PrunedMutableMmr;

    fn deref(&self) -> &Self::Target {
        &self.mmr
    }
}

#[derive(Debug, Clone)]
pub struct MerkleCheckPoint {
    nodes_added: Vec<H256>,
    nodes_deleted: Bitmap,
}

impl MerkleCheckPoint {
    
    pub fn new(nodes_added: Vec<H256>, nodes_deleted: Bitmap) -> MerkleCheckPoint {
        MerkleCheckPoint {
            nodes_added,
            nodes_deleted,
        }
    }

    /// Apply this checkpoint to the MMR provided. Take care: The `deleted` set is not compressed after returning
    /// from here.
    fn apply<B2>(&self, mmr: &mut MutableMmr<B2>) -> Result<(), GeneError>
    where
        B2: Storage<Value = H256>,
    {
        for node in &self.nodes_added {
            mmr.push(node)?;
        }

        mmr.deleted.or_inplace(&self.nodes_deleted);
        Ok(())
    }

    /// Return a reference to the hashes of the nodes added in the checkpoint
    pub fn nodes_added(&self) -> &Vec<H256> {
        &self.nodes_added
    }

    /// Return a reference to the roaring bitmap of nodes that were deleted in this checkpoint
    pub fn nodes_deleted(&self) -> &Bitmap {
        &self.nodes_deleted
    }

    /// Break a checkpoint up into its constituent parts
    pub fn into_parts(self) -> (Vec<H256>, Bitmap) {
        (self.nodes_added, self.nodes_deleted)
    }
}

