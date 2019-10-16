// Copyright 2019 Stichting Organism
// Copyright 2019 The Grin Developers
// Copyright 2019 The Tari Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Gene: Over the Mountains
//!  - MMR
//!  - Dynamic Accumulator
//!
//! # Merkle Mountain Ranges
//!
//! ## Introduction
//!
//! The Merkle mountain range was invented by Peter Todd more about them can be read at
//! [Open Timestamps](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md)
//! and the [Grin project](https://github.com/mimblewimble/grin/blob/master/doc/mmr.md).
//!
//! A Merkle mountain range(MMR) is a binary tree where each parent is the concatenated hash of its two
//! children. The leaves at the bottom of the MMR is the hashes of the data. The MMR allows easy to add and proof
//! of existence inside of the tree. MMR always tries to have the largest possible single binary tree, so in effect
//! it is possible to have more than one binary tree. Every time you have to get the merkle root (the single merkle
//! proof of the whole MMR) you have the bag the peaks of the individual trees, or mountain peaks.
//!
//! Lets take an example of how to construct one. Say you have the following MMR already made:
//! ```plaintext
//!       /\
//!      /  \
//!     /\  /\   /\
//!    /\/\/\/\ /\/\ /\
//! ```
//! From this we can see we have 3 trees or mountains. We have constructed the largest possible tree's we can.
//! If we want to calculate the merkle root we simply concatenate and then hash the three peaks.
//!
//! Lets continue the example, by adding a single object. Our MMR now looks as follows
//! ```plaintext
//!       /\
//!      /  \
//!     /\  /\   /\
//!    /\/\/\/\ /\/\ /\ /
//! ```
//! We now have 4 mountains. Calculating the root means hashing the concatenation of the (now) four peaks.
//!
//!  Lets continue thw example, by adding a single object. Our MMR now looks as follows
//! ```plaintext
//!           /\
//!          /  \
//!         /    \
//!        /      \
//!       /\      /\
//!      /  \    /  \
//!     /\  /\  /\  /\
//!    /\/\/\/\/\/\/\/\
//! ```
//! Now we only have a single binary tree, and the root is now the hash of the single peak's hash. This
//! process continues as you add more objects to the MMR.
//! ```plaintext
//!                 /\
//!                /  \
//!               /    \
//!              /      \
//!             /        \
//!            /          \
//!           /            \
//!          /\             \
//!         /\ \            /\
//!        /  \ \          /  \
//!       /\   \ \        /\   \
//!      /  \   \ \      /  \   \
//!     /\  /\  /\ \    /\  /\  /\
//!    /\/\/\/\/\/\/\  /\/\/\/\/\/\
//! ```
//! Due to the unique way the MMR is constructed we can easily represent the MMR as a linear list of the nodes. Lets
//! take the following MMR and number the nodes in the order we create them.
//! ```plaintext
//!         6
//!       /  \
//!      /    \
//!     2      5
//!    / \    / \
//!   0   1  3   4
//! ```
//! Looking above at the example of when you create the nodes, you will see the MMR nodes will have been created in the
//! order as they are named. This means we can easily represent them as a list:
//! Height:  0 | 0 | 1 | 0 | 0 | 1 | 2
//! Node:    0 | 1 | 2 | 3 | 4 | 5 | 6
//!
//! Because of the list nature of the MMR we can easily navigate around the MMR using the following formulas:
//!
//! Jump to right sibling : $$ n + 2^{H+1} - 1 $$
//! Jump to left sibling : $$ n - 2^{H+1} - 1 $$
//! peak of binary tree : $$ 2^{ H+1 } - 2 $$
//! left down : $$ n - 2^H $$
//! right down: $$ n-1 $$
//!
//! ## Node numbering
//!
//! There can be some confusion about how nodes are numbered in an MMR. The following conventions are used in this
//! crate:
//!
//! * _All_ indices are numbered starting from zero.
//! * MMR nodes refer to all the nodes in the Merkle Mountain Range and are ordered in the canonical mmr ordering
//! described above.
//! * Leaf nodes are numbered counting from zero and increment by one each time a leaf is added.
//!
//! To illustrate, consider this MMR:
//!
//! //! ```plaintext
//!            14
//!          /     \
//!         /       \
//!        6        13          21          <-- MMR indices
//!      /  \      /  \        /  \
//!     /    \    /    \      /    \
//!     2    5    9    12    17    21
//!    / \  / \  / \  / \   / \   / \
//!    0 1  3 4  7 8 10 11 15 16 18 19 22
//!    ----------------------------------
//!    0 1  2 3  4 5  6  7  8  9 10 11 12  <-- Leaf node indices
//!    ----------------------------------
//! ```

#[cfg(target_pointer_width = "32")]
pub type Bitmap = croaring::Bitmap;
#[cfg(target_pointer_width = "64")]
pub type Bitmap = croaring::Bitmap;
// pub type Bitmap = croaring::TreeMap;


use failure::Fail;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum GeneError {
    /// This error occurs when we receive a proof that's outdated and cannot be auto-updated.
    #[fail(display = "Item proof is outdated and must be re-created against the new state")]
    OutdatedProof,

    /// This error occurs when the merkle proof is too short or too long, or does not lead to a node
    /// to which it should.
    #[fail(display = "Merkle proof is invalid")]
    InvalidProof,

    /// Merkle proof root hash does not match when attempting to verify.
    #[fail(display = "Merkle proof is invalid")]
    RootMismatch,

    /// You tried to construct or verify a Merkle proof using a non-leaf node as the inclusion candidate
    #[fail(display = "Merkle proof is invalid")]
    NonLeafNode,

    /// There was no hash in the merkle tree backend with the given position
    #[fail(display = "Merkle proof is invalid")]
    HashNotFound(usize),

    /// The list of peak hashes provided in the proof has an error
    #[fail(display = "Merkle proof is invalid")]
    IncorrectPeakMap,

    /// Unexpected
    #[fail(display = "Merkle proof is invalid")]
    Unexpected,

    /// A problem has been encountered with the backend
    #[fail(display = "Backend Error: {}", _0)]
    BackendError(String),

    /// The Merkle tree is not internally consistent. A parent hash isn't equal to the hash of its children
    #[fail(display = "Merkle is not internally consistent")]
    InvalidMerkleTree,

    /// The next position was not a leaf node as expected
    #[fail(display = "Merkle Tree Malformed")]
    CorruptDataStructure,

    /// The tree has reached its maximum size
    #[fail(display = "Tree has reached its maximum size")]
    MaximumSizeReached,

    /// A request was out of range
    #[fail(display = "A request was out of range")]
    OutOfRange,
}


/// A vector-based backend for [Gene]
mod storage;
pub use storage::{ Storage, StorageExt };

/// Hiker
pub mod algos; 

/// An immutable, append-only Merkle Mountain range (MMR) data structure
mod mmr;
pub use mmr::MerkleMountainRange;

/// A data structure for proving a hash inclusion in an MMR
mod merkle_proof;
pub use merkle_proof::MerkleProof;

/// An append-only Merkle Mountain range (MMR) data structure that allows deletion of existing leaf nodes.
mod mutable_mmr;
pub use mutable_mmr::MutableMmr;

/// A function for snapshotting and pruning a Merkle Mountain Range
pub mod pruned_hashset;
pub mod pruned_mmr;

/// A data structure that maintains a list of diffs on an MMR, enabling you to rewind to a previous state
mod change_tracker;
pub use change_tracker::{ 
    MerkleChangeTracker, 
    MerkleCheckPoint 
};

// /// Dynamic Accumulator
// mod pollard;


#[cfg(test)]
mod test_gene;