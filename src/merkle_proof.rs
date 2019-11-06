//! Merkle Proofs

use mohan::{
    hash::{
        H256,
        BlakeHasher,
    },
    ser,
    VarInt
};
use std::fmt::{self, Display, Formatter};
use serde::{Deserialize, Serialize};
use crate::{
    MerkleMountainRange,
    Storage,
    GeneError,
    algos::{family, family_branch, find_peaks, is_leaf, is_left_sibling, leaf_index},
};



/// A Merkle proof that proves a particular element at a particular position exists in an MMR.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub struct MerkleProof {
    /// The size of the MMR at the time the proof was created.
    mmr_size: usize,
    /// The sibling path from the leaf up to the final sibling hashing to the local root.
    path: Vec<H256>,
    /// The set of MMR peaks, not including the local peak for the candidate node
    peaks: Vec<H256>,
}

impl Default for MerkleProof {
    fn default() -> MerkleProof {
        MerkleProof {
            mmr_size: 0,
            path: Vec::default(),
            peaks: Vec::default(),
        }
    }
}

impl MerkleProof {
    /// Build a Merkle Proof the given MMR at the given *leaf* position. This is usually the version you'll want to
    /// call, since you'll know the leaf index more often than the MMR index.
    ///
    /// For the difference between leaf node and MMR node indices, see the [mod level] documentation.
    ///
    /// See [MerkleProof::for_node] for more details on how the proof is constructed.
    pub fn for_leaf_node<B>(
        mmr: &MerkleMountainRange<B>,
        leaf_pos: usize,
    ) -> Result<MerkleProof, GeneError>
    where
        B: Storage<Value = H256>,
    {
        let pos = leaf_index(leaf_pos);
        MerkleProof::generate_proof(mmr, pos)
    }

    /// Build a Merkle proof for the candidate node at the given MMR index. If you want to build a proof using the
    /// leaf position, call [MerkleProof::for_leaf_node] instead. The given node position must be a leaf node,
    /// otherwise a `MerkleProofError::NonLeafNode` error will be returned.
    ///
    /// The proof for the MMR consists of two parts:
    /// a) A list of sibling node hashes starting from the candidate node and walking up the tree to the local root
    /// (i.e. the root of the binary tree that the candidate node lives in.
    /// b) A list of MMR peaks, excluding the local node hash.
    /// The final Merkle proof is constructed by hashing all the peaks together (this is slightly different to how
    /// other MMR implementations work).
    pub fn for_node<B>(mmr: &MerkleMountainRange<B>, pos: usize) -> Result<MerkleProof, GeneError>
    where
        B: Storage<Value = H256>,
    {
        // check this pos is actually a leaf in the MMR
        if !is_leaf(pos) {
            return Err(GeneError::NonLeafNode);
        }

        MerkleProof::generate_proof(mmr, pos)
    }

    fn generate_proof<B>(mmr: &MerkleMountainRange<B>, pos: usize) -> Result<MerkleProof, GeneError>
    where
        B: Storage<Value = H256>,
    {
        // check we actually have a hash in the MMR at this pos
        mmr.get_node_hash(pos)?.ok_or(GeneError::HashNotFound(pos))?;
        let mmr_size = mmr.len()?;
        let family_branch = family_branch(pos, mmr_size);

        // Construct a vector of sibling hashes from the candidate node's position to the local peak
        let path = family_branch
            .iter()
            .map(|(_, sibling)| {
                mmr.get_node_hash(*sibling)?
                    .map(|v| v.clone())
                    .ok_or(GeneError::HashNotFound(*sibling))
            })
            .collect::<Result<_, _>>()?;

        let peak_pos = match family_branch.last() {
            Some(&(parent, _)) => parent,
            None => pos,
        };

        // Get the peaks of the merkle trees, which are bagged together to form the root
        // For the proof, we must leave out the local root for the candidate node
        let peaks = find_peaks(mmr_size);
        let mut peak_hashes = Vec::with_capacity(peaks.len() - 1);

        for peak_index in peaks {
            if peak_index != peak_pos {
                let hash = mmr
                    .get_node_hash(peak_index)?
                    .ok_or(GeneError::HashNotFound(peak_index))?
                    .clone();
                peak_hashes.push(hash);
            }
        }

        Ok(MerkleProof {
            mmr_size,
            path,
            peaks: peak_hashes,
        })
    }

    pub fn verify_leaf(
        &self,
        root: &H256,
        hash: &H256,
        leaf_pos: usize,
    ) -> Result<(), GeneError>
    {
        let pos = leaf_index(leaf_pos);
        self.verify(root, hash, pos)
    }

    /// Verifies the Merkle proof against the provided root hash, element and position in the MMR.
    pub fn verify(&self, root: &H256, hash: &H256, pos: usize) -> Result<(), GeneError> {
        let mut proof = self.clone();
        // calculate the peaks once as these are based on overall MMR size (and will not change)
        let peaks = find_peaks(self.mmr_size);
        proof.verify_consume(root, hash, pos, &peaks)
    }

    /// Calculate a merkle root from the given hash, its peak position, and the peak hashes given with the proof
    /// Because of how the proofs are generated, the peak hashes given in the proof will always be an array one
    /// shorter then the canonical peak list for an MMR of a given size. e.g.: For an MMR of size 10:
    /// ```text
    ///       6
    ///    2     5    9
    ///   0 1   3 4  7 8
    /// ```
    /// The peak list is (6,9). But if we have an inclusion proof for say, 3, then we'll calculate 6 from the sibling
    /// data, therefore the proof only needs to provide 9.
    ///
    /// After running [verify_consume], we'll know the hash of 6 and it's position (the local root), and so we'll also
    /// know where to insert the hash in the peak list.
    fn check_root(&self, hash: &H256, pos: usize, peaks: &[usize]) -> Result<H256, GeneError> {
        // The peak hash list provided in the proof does not include the local peak determined from the candidate
        // node, so len(peak) must be len(self.peaks) + 1.
        if peaks.len() != self.peaks.len() + 1 {
            return Err(GeneError::IncorrectPeakMap);
        }

        let hasher = BlakeHasher::new();
        // We're going to hash the peaks together, but insert the provided hash in the correct position.
        let peak_hashes = self.peaks.iter();

        let (hasher, _) = peaks
            .iter()
            .fold((hasher, peak_hashes), |(hasher, mut peak_hashes), i| {
                if *i == pos {
                    (hasher.chain(hash.as_bytes()), peak_hashes)
                } else {
                    let hash = peak_hashes.next().unwrap();
                    (hasher.chain(hash.as_bytes()), peak_hashes)
                }
            });
            
        Ok(hasher.finalize())
    }

    /// Consumes the Merkle proof while verifying it.
    /// This method works by walking up the sibling path given in the proof. Since the only info we're given in the
    /// proof are the sibling hashes and the size of the MMR, there are a lot of bit-twiddling checks to determine
    /// where we are in the MMR.
    ///
    /// This algorithm works as follows:
    /// First we calculate the "local root" of the MMR by getting to the root of the full binary tree indicated by
    /// `pos` and `self.mmr_size`.
    /// This is done by popping a sibling hash off `self.path`, figuring out if it's on the left or right branch,
    /// calculating the parent hash, and then calling `verify_consume` again using the parent hash and position.
    /// Once `self.path` is empty, we have the local root and position, this data is used to hash all the peaks
    /// together in `check_root` to calculate the final merkle root.
    fn verify_consume(
        &mut self,
        root: &H256,
        hash: &H256,
        pos: usize,
        peaks: &[usize],
    ) -> Result<(), GeneError>
    {
        // If path is empty, we've got the hash of a local peak, so now we need to hash all the peaks together to
        // calculate the merkle root
        if self.path.is_empty() {
            let calculated_root = self.check_root(hash, pos, peaks)?;
            return if *root == calculated_root {
                Ok(())
            } else {
                Err(GeneError::RootMismatch)
            };
        }

        let sibling = self.path.remove(0); // FIXME Compare perf vs using a VecDeque
        let (parent_pos, sibling_pos) = family(pos);

        if parent_pos > self.mmr_size {
            return Err(GeneError::Unexpected);
        } else {
            let parent = if is_left_sibling(sibling_pos) {
                sibling.hash_with(hash)
            } else {
                hash.hash_with(sibling)
            };
            self.verify_consume(root, &parent, parent_pos, peaks)
        }
    }
}




impl Display for MerkleProof {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&format!("MMR Size: {}\n", self.mmr_size))?;
        f.write_str("Siblings:\n")?;
        self.path
            .iter()
            .enumerate()
            .fold(Ok(()), |_, (i, h)| f.write_str(&format!("{:3}: {}\n", i, h.to_hex())))?;
        f.write_str("Peaks:\n")?;
        self.peaks
            .iter()
            .enumerate()
            .fold(Ok(()), |_, (i, h)| f.write_str(&format!("{:3}: {}\n", i, h.to_hex())))?;
        Ok(())
    }
}


impl ser::Writeable for MerkleProof {
    fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        writer.write_u64(self.mmr_size as u64)?;
        let path_len = VarInt(self.path.len() as u64);
        path_len.write(writer);

        for i in 0..self.path.len() {
            self.path[i].write(writer);
        }

        let peaks_len = VarInt(self.peaks.len() as u64);
        peaks_len.write(writer);

        for i in 0..self.peaks.len() {
            self.peaks[i].write(writer);
        }

        Ok(())
    }
}

impl ser::Readable for MerkleProof {
    fn read(reader: &mut dyn ser::Reader) -> Result<MerkleProof, ser::Error> {
        let mmr_size = reader.read_u64()? as usize;
        let path_len = VarInt::read(reader)?;
        let mut path = Vec::new();
        for i in 0..path_len.as_u64() {
            let hash = H256::read(reader)?;
            path.push(hash);
        }

        let peaks_len = VarInt::read(reader)?;
        let mut peaks = Vec::new();
        for i in 0..peaks_len.as_u64() {
            let hash = H256::read(reader)?;
            peaks.push(hash);
        }

        Ok(MerkleProof { mmr_size, path, peaks })
    }
}