//! Track Changes to a MMR, allows for rollback 


use std::{mem, ops::Deref, fmt};
use crate::{
    Storage,
    StorageExt,
    //algos::{ bintree_height, find_peaks, leaf_index, peak_map_height },
    GeneError,
    pruned_mmr::{prune_mutable_mmr, PrunedMutableMmr},
    MutableMmr,
    Bitmap,
    MutableMmrLeafNodes
};
use mohan::hash::{
    H256
};
use serde::{
    de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor},
    ser::{Serialize, SerializeStruct, Serializer},
};
use anyhow::Result;

/// Configuration for the MerkleChangeTracker.
#[derive(Debug, Clone, Copy)]
pub struct MerkleChangeTrackerConfig {
    /// The rewind_hist_len specifies the point in history upto where the MMR can be efficiently rewound before the
    /// base mmr needs to be reconstructed.
    pub rewind_hist_len: usize,
}

impl Default for MerkleChangeTrackerConfig {
    fn default() -> Self {
        Self { rewind_hist_len: 100 }
    }
}


/// The MMR cache is used to calculate Merkle and Merklish roots based on the state of the set of shared checkpoints. It
/// can efficiently create an updated cache state when small checkpoint rewinds were detected or the checkpoint state
/// has been expanded.
#[derive(Debug)]
pub struct MerkleChangeTracker<BaseBackend, CpBackend>
where
    BaseBackend: Storage<Value = H256>,
{
    // The last checkpoint index applied to the base MMR.
    base_cp_index: usize,
    // One more than the last checkpoint index applied to the current MMR.
    curr_cp_index: usize,
    // The base MMR is the anchor point of the mmr cache. A rewind can start at this state if the checkpoint tip is
    // beyond the base checkpoint index. It will have to rebuild the base MMR if the checkpoint tip index is less
    // than the base MMR index.
    base_mmr: MutableMmr<BaseBackend>,
    // The current mmr represents the latest mmr with all checkpoints applied.
    pub curr_mmr: PrunedMutableMmr,
    // Access to the checkpoint set.
    checkpoints: CpBackend,
    // Configuration for the MMR cache.
    config: MerkleChangeTrackerConfig
}


impl<BaseBackend, CpBackend> MerkleChangeTracker<BaseBackend, CpBackend>
where
    BaseBackend: Storage<Value = H256>,
    CpBackend: Storage<Value = MerkleCheckPoint> + StorageExt<Value = MerkleCheckPoint>,
{
    /// Creates a new MMR cache with access to the provided set of shared checkpoints.
    pub fn new(
        base_mmr: BaseBackend,
        checkpoints: CpBackend,
        config: MerkleChangeTrackerConfig,
    ) -> Result<MerkleChangeTracker<BaseBackend, CpBackend>, GeneError>
    {
        let base_mmr = MutableMmr::new(base_mmr);
        let curr_mmr = prune_mutable_mmr::<_>(&base_mmr)?;
        let mut mmr_cache = MerkleChangeTracker {
            base_cp_index: 0,
            curr_cp_index: 0,
            base_mmr,
            curr_mmr,
            checkpoints,
            config,
        };
        mmr_cache.reset()?;
        Ok(mmr_cache)
    }

    // Calculate the base checkpoint index based on the rewind history length and the number of checkpoints.
    fn calculate_base_cp_index(&mut self) -> Result<usize, GeneError> {
        let cp_count = self
            .checkpoints
            .len()
            .map_err(|e| GeneError::BackendError(e.to_string()))?;
        if cp_count > self.config.rewind_hist_len {
            return Ok(cp_count - self.config.rewind_hist_len);
        }
        Ok(0)
    }

    // Reconstruct the base MMR using the shared checkpoints. The base MMR contains the state from the the first
    // checkpoint to the checkpoint tip minus the minimum history length.
    fn create_base_mmr(&mut self) -> Result<(), GeneError> {
        self.base_mmr.clear()?;
        self.base_cp_index = self.calculate_base_cp_index()?;
        for cp_index in 0..=self.base_cp_index {
            if let Some(cp) = self
                .checkpoints
                .get(cp_index)
                .map_err(|e| GeneError::BackendError(e.to_string()))?
            {
                cp.apply(&mut self.base_mmr)?;
            }
        }
        Ok(())
    }

     // Reconstruct the current MMR from the next checkpoint after the base MMR to the last checkpoints.
     fn create_curr_mmr(&mut self) -> Result<(), GeneError> {
        self.curr_cp_index = self
            .checkpoints
            .len()
            .map_err(|e| GeneError::BackendError(e.to_string()))?;
        self.curr_mmr = prune_mutable_mmr::<_>(&self.base_mmr)?;
        for cp_index in self.base_cp_index + 1..self.curr_cp_index {
            if let Some(cp) = self
                .checkpoints
                .get(cp_index)
                .map_err(|e| GeneError::BackendError(e.to_string()))?
            {
                cp.apply(&mut self.curr_mmr)?;
            }
        }
        Ok(())
    }

    // An update to the checkpoints have been detected, update the base MMR to the correct position.
    fn update_base_mmr(&mut self) -> Result<(), GeneError> {
        let prev_cp_index = self.base_cp_index;
        self.base_cp_index = self.calculate_base_cp_index()?;
        if prev_cp_index < self.base_cp_index {
            for cp_index in prev_cp_index + 1..=self.base_cp_index {
                if let Some(cp) = self
                    .checkpoints
                    .get(cp_index)
                    .map_err(|e| GeneError::BackendError(e.to_string()))?
                {
                    cp.apply(&mut self.base_mmr)?;
                }
            }
        } else {
            self.create_base_mmr()?;
        }
        Ok(())
    }

     /// This function updates the state of the MMR cache based on the current state of the shared checkpoints.
     pub fn update(&mut self) -> Result<(), GeneError> {
        let cp_count = self
            .checkpoints
            .len()
            .map_err(|e| GeneError::BackendError(e.to_string()))?;
        if cp_count < self.base_cp_index {
            // Checkpoint before the base MMR index, this will require a full reconstruction of the cache.
            self.create_base_mmr()?;
            self.create_curr_mmr()?;
        } else if cp_count < self.curr_cp_index {
            // A short checkpoint reorg has occured, and requires the current MMR to be reconstructed.
            self.create_curr_mmr()?;
        } else if cp_count > self.curr_cp_index {
            // The cache has fallen behind and needs to update to the new checkpoint state.
            self.update_base_mmr()?;
            self.create_curr_mmr()?;
        }
        Ok(())
    }

    /// Reset the MmrCache and rebuild the base and current MMR state.
    pub fn reset(&mut self) -> Result<(), GeneError> {
        self.create_base_mmr()?;
        self.create_curr_mmr()
    }

    /// Returns the hash of the leaf index provided, as well as its deletion status. The node has been marked for
    /// deletion if the boolean value is true.
    pub fn fetch_mmr_node(&self, leaf_index: u32) -> Result<(Option<H256>, bool), GeneError> {
        let (base_hash, base_deleted) = self.base_mmr.get_leaf_status(leaf_index)?;
        let (curr_hash, curr_deleted) = self.curr_mmr.get_leaf_status(leaf_index)?;
        if let Some(base_hash) = base_hash {
            return Ok((Some(base_hash), base_deleted | curr_deleted));
        }
        Ok((curr_hash, base_deleted | curr_deleted))
    }


}

impl<BaseBackend, DiffBackend> Deref for MerkleChangeTracker<BaseBackend, DiffBackend>
where
    BaseBackend: Storage<Value = H256>,
{
    type Target = PrunedMutableMmr;

    fn deref(&self) -> &Self::Target {
        &self.curr_mmr
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
    
    /// Resets the current MerkleCheckpoint.
    pub fn clear(&mut self) {
        self.nodes_added.clear();
        self.nodes_deleted = Bitmap::create();
    }

    /// Add a hash to the set of nodes added.
    pub fn push_addition(&mut self, hash: H256) {
        self.nodes_added.push(hash);
    }

    /// Add a a deleted index to the set of deleted nodes.
    pub fn push_deletion(&mut self, leaf_index: u32) {
        self.nodes_deleted.add(leaf_index);
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

impl Serialize for MerkleCheckPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut state = serializer.serialize_struct("MerkleCheckPoint", 2)?;
        state.serialize_field("nodes_added", &self.nodes_added)?;
        state.serialize_field("nodes_deleted", &self.nodes_deleted.serialize())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MerkleCheckPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        enum Field {
            NodesAdded,
            NodesDeleted,
        };

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where D: Deserializer<'de> {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`nodes_added` or `nodes_deleted`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where E: de::Error {
                        match value {
                            "nodes_added" => Ok(Field::NodesAdded),
                            "nodes_deleted" => Ok(Field::NodesDeleted),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct MerkleCheckPointVisitor;

        impl<'de> Visitor<'de> for MerkleCheckPointVisitor {
            type Value = MerkleCheckPoint;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct MerkleCheckPoint")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<MerkleCheckPoint, V::Error>
            where V: SeqAccess<'de> {
                let nodes_added = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let nodes_deleted_buf: Vec<u8> =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let nodes_deleted: Bitmap = Bitmap::deserialize(&nodes_deleted_buf);
                Ok(MerkleCheckPoint::new(nodes_added, nodes_deleted))
            }

            fn visit_map<V>(self, mut map: V) -> Result<MerkleCheckPoint, V::Error>
            where V: MapAccess<'de> {
                let mut nodes_added = None;
                let mut nodes_deleted = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::NodesAdded => {
                            if nodes_added.is_some() {
                                return Err(de::Error::duplicate_field("nodes_added"));
                            }
                            nodes_added = Some(map.next_value()?);
                        },
                        Field::NodesDeleted => {
                            if nodes_deleted.is_some() {
                                return Err(de::Error::duplicate_field("nodes_deleted"));
                            }
                            let nodes_deleted_buf: Vec<u8> = map.next_value()?;
                            nodes_deleted = Some(Bitmap::deserialize(&nodes_deleted_buf));
                        },
                    }
                }
                let nodes_added = nodes_added.ok_or_else(|| de::Error::missing_field("nodes_added"))?;
                let nodes_deleted = nodes_deleted.ok_or_else(|| de::Error::missing_field("nodes_deleted"))?;
                Ok(MerkleCheckPoint::new(nodes_added, nodes_deleted))
            }
        }

        const FIELDS: &[&str] = &["nodes_added", "nodes_deleted"];
        deserializer.deserialize_struct("MerkleCheckPoint", FIELDS, MerkleCheckPointVisitor)
    }
}