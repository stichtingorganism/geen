//! Gene Tests

use mohan::{
    hash::{
        blake256,
        H256,
        BlakeHasher
    },
};
use crate::{
    MerkleMountainRange,
    MerkleProof,
    GeneError,
    algos::{is_leaf, leaf_index},
    Bitmap,
    MutableMmr,
    pruned_mmr::{
        prune_mmr,
        calculate_pruned_mmr_root,
        calculate_mmr_root
    },
    MerkleChangeTracker,
    MerkleChangeTrackerConfig,
    MerkleCheckPoint,
    MemBackendVec,
    Storage,
    StorageExt
};


fn int_to_hash(n: usize) -> H256 { blake256(&n.to_le_bytes()) }

pub fn combine_hashes(hashes: &Vec<H256>) -> H256 {
    let hasher = BlakeHasher::new();
    hashes
        .iter()
        .fold(hasher, |hasher, h| hasher.chain(h.as_bytes()))
        .finalize()
}


pub fn create_mmr(size: usize) -> MerkleMountainRange<Vec<H256>> {
    let mut mmr = MerkleMountainRange::<_>::new(Vec::default());
    for i in 0..size {
        let hash = int_to_hash(i);
        assert!(mmr.push(&hash).is_ok());
    }
    mmr
}

pub fn create_mutable_mmr(size: usize) -> MutableMmr<Vec<H256>> {
    let mut mmr = MutableMmr::<_>::new(Vec::default());
    for i in 0..size {
        let hash = int_to_hash(i);
        assert!(mmr.push(&hash).is_ok());
    }
    mmr
}

fn hash_with_bitmap(hash: &H256, bitmap: &mut Bitmap) -> H256 {
    bitmap.run_optimize();
    let hasher = BlakeHasher::new();
    hasher.chain(hash.as_bytes()).chain(&bitmap.serialize()).finalize()
}

//
//  MMR
//

/// MMRs with no elements should provide sane defaults. The merkle root must be the hash of an empty string, b"".
#[test]
fn zero_length_mmr() {
    let mmr = MerkleMountainRange::<_>::new(Vec::default());
    assert_eq!(mmr.len(), Ok(0));
    assert_eq!(mmr.is_empty(), Ok(true));
    let empty_hash = H256::zero();
    assert_eq!(mmr.get_merkle_root(), Ok(empty_hash));
}

/// Successively build up an MMR and check that the roots, heights and indices are all correct.
#[test]
fn build_mmr() {
    let mut mmr = MerkleMountainRange::<_>::new(Vec::default());
    // Add a single item
    let h0 = int_to_hash(0);

    assert!(mmr.push(&h0).is_ok());
    // The root of a single hash is the hash of that hash
    assert_eq!(mmr.len(), Ok(1));
    assert_eq!(mmr.get_merkle_root(), Ok(combine_hashes(&vec![h0])));
    // Two leaf item items:
    //    2
    //  0   1
    let h1 = int_to_hash(1);
    assert!(mmr.push(&h1).is_ok());
    let h_2 = combine_hashes(&vec![h0, h1]);
    assert_eq!(mmr.get_merkle_root(), Ok(combine_hashes(&vec![h_2])));
    assert_eq!(mmr.len(), Ok(3));
    // Three leaf item items:
    //    2
    //  0   1  3
    let h3 = int_to_hash(3);
    assert!(mmr.push(&h3).is_ok());
    // The root is a bagged root
    let root = combine_hashes(&vec![h_2, h3]);
    assert_eq!(mmr.get_merkle_root(), Ok(root));
    assert_eq!(mmr.len(), Ok(4));
    // Four leaf items:
    //        6
    //    2      5
    //  0   1  3   4
    let h4 = int_to_hash(4);
    assert!(mmr.push(&h4).is_ok());
    let h_5 = combine_hashes(&&vec![h3, h4]);
    let h_6 = combine_hashes(&vec![h_2, h_5]);
    assert_eq!(mmr.get_merkle_root(), Ok(combine_hashes(&vec![h_6])));
    assert_eq!(mmr.len(), Ok(7));
    // Five leaf items:
    //        6
    //    2      5
    //  0   1  3   4  7
    let h7 = int_to_hash(7);
    assert!(mmr.push(&h7).is_ok());
    let root = combine_hashes(&vec![h_6, h7]);
    assert_eq!(mmr.get_merkle_root(), Ok(root));
    assert_eq!(mmr.len(), Ok(8));
    // Six leaf item items:
    //        6
    //    2      5      9
    //  0   1  3   4  7  8
    let h8 = int_to_hash(8);
    let h_9 = combine_hashes(&vec![h7, h8]);
    assert!(mmr.push(&h8).is_ok());
    let root = combine_hashes(&vec![h_6, h_9]);
    assert_eq!(mmr.get_merkle_root(), Ok(root));
    assert_eq!(mmr.len(), Ok(10));
}

#[test]
fn equality_check() {
    let mut ma = MerkleMountainRange::<_>::new(Vec::default());
    let mut mb = MerkleMountainRange::<_>::new(Vec::default());
    assert!(ma == mb);
    assert!(ma.push(&int_to_hash(1)).is_ok());
    assert!(ma != mb);
    assert!(mb.push(&int_to_hash(1)).is_ok());
    assert!(ma == mb);
    assert!(ma.push(&int_to_hash(2)).is_ok());
    assert!(mb.push(&int_to_hash(3)).is_ok());
    assert!(ma != mb);
}

#[test]
fn validate() {
    let mmr = create_mmr(65);
    assert!(mmr.validate().is_ok());
}

#[test]
fn restore_from_leaf_hashes() {
    let mut mmr = MerkleMountainRange::<_>::new(Vec::default());
    let leaf_hashes = mmr.get_leaf_hashes(0, 1).unwrap();
    assert_eq!(leaf_hashes.len(), 0);

    let h0 = int_to_hash(0);
    let h1 = int_to_hash(1);
    let h2 = int_to_hash(2);
    let h3 = int_to_hash(3);
    assert!(mmr.push(&h0).is_ok());
    assert!(mmr.push(&h1).is_ok());
    assert!(mmr.push(&h2).is_ok());
    assert!(mmr.push(&h3).is_ok());
    assert_eq!(mmr.len(), Ok(7));

    // Construct MMR state from multiple leaf hash queries.
    let leaf_count = mmr.get_leaf_count().unwrap();
    let mut leaf_hashes = mmr.get_leaf_hashes(0, 2).unwrap();
    leaf_hashes.append(&mut mmr.get_leaf_hashes(2, leaf_count - 2).unwrap());
    assert_eq!(leaf_hashes.len(), 4);
    assert_eq!(leaf_hashes[0], h0);
    assert_eq!(leaf_hashes[1], h1);
    assert_eq!(leaf_hashes[2], h2);
    assert_eq!(leaf_hashes[3], h3);

    assert!(mmr.push(&int_to_hash(4)).is_ok());
    assert!(mmr.push(&int_to_hash(5)).is_ok());
    assert_eq!(mmr.len(), Ok(10));

    assert!(mmr.restore(leaf_hashes).is_ok());
    assert_eq!(mmr.len(), Ok(7));
    assert_eq!(mmr.get_leaf_hash(0), Ok(Some(h0)));
    assert_eq!(mmr.get_leaf_hash(1), Ok(Some(h1)));
    assert_eq!(mmr.get_leaf_hash(2), Ok(Some(h2)));
    assert_eq!(mmr.get_leaf_hash(3), Ok(Some(h3)));
    assert_eq!(mmr.get_leaf_hash(4), Ok(None));
}

#[test]
fn restore_from_leaf_nodes() {
    let mut mmr = MutableMmr::<_>::new(Vec::default());
    for i in 0..12 {
        assert!(mmr.push(&int_to_hash(i)).is_ok());
    }
    assert!(mmr.delete_and_compress(2, true));
    assert!(mmr.delete_and_compress(4, true));
    assert!(mmr.delete_and_compress(5, true));

    // Request state of MMR with single call
    let leaf_count = mmr.get_leaf_count();
    let mmr_state1 = mmr.to_leaf_nodes(0, leaf_count).unwrap();

    // Request state of MMR with multiple calls
    let mut mmr_state2 = mmr.to_leaf_nodes(0, 3).unwrap();
    mmr_state2.combine(mmr.to_leaf_nodes(3, 3).unwrap());
    mmr_state2.combine(mmr.to_leaf_nodes(6, leaf_count - 6).unwrap());
    assert_eq!(mmr_state1, mmr_state2);

    // Change the state more before the restore
    let mmr_root = mmr.get_merkle_root();
    assert!(mmr.push(&int_to_hash(7)).is_ok());
    assert!(mmr.push(&int_to_hash(8)).is_ok());
    assert!(mmr.delete_and_compress(3, true));

    // Restore from compact state
    assert!(mmr.restore(mmr_state1.clone()).is_ok());
    assert_eq!(mmr.get_merkle_root(), mmr_root);
    let restored_mmr_state = mmr.to_leaf_nodes(0, mmr.get_leaf_count()).unwrap();
    assert_eq!(restored_mmr_state, mmr_state2);
}

//
// Merkle Proofs
//

#[test]
fn zero_size_mmr() {
    let mmr = create_mmr(0);
    match MerkleProof::for_node(&mmr, 0) {
        Err(GeneError::HashNotFound(i)) => assert_eq!(i, 0),
        _ => panic!("Incorrect zero-length merkle proof"),
    }
}

/// Thorough check of MerkleProof process for each position in various MMR sizes
#[test]
fn merkle_proof_small_mmrs() {
    for size in 1..32 {
        let mmr = create_mmr(size);
        let root = mmr.get_merkle_root().unwrap();
        let mut hash_value = 0usize;
        for pos in 0..mmr.len().unwrap() {
            if is_leaf(pos) {
                let hash = int_to_hash(hash_value);
                hash_value += 1;
                let proof = MerkleProof::for_node(&mmr, pos).unwrap();
                assert!(proof.verify(&root, &hash, pos).is_ok());
            } else {
                assert_eq!(MerkleProof::for_node(&mmr, pos), Err(GeneError::NonLeafNode));
            }
        }
    }
}

#[test]
fn med_mmr() {
    let size = 500;
    let mmr = create_mmr(size);
    let root = mmr.get_merkle_root().unwrap();
    let i = 499;
    let pos = leaf_index(i);
    let hash = int_to_hash(i);
    let proof = MerkleProof::for_node(&mmr, pos).unwrap();
    assert!(proof.verify(&root, &hash, pos).is_ok());
}

#[test]
fn a_big_proof() {
    let mmr = create_mmr(100_000);
    let leaf_pos = 28_543;
    let mmr_index = leaf_index(leaf_pos);
    let root = mmr.get_merkle_root().unwrap();
    let hash = int_to_hash(leaf_pos);
    let proof = MerkleProof::for_node(&mmr, mmr_index).unwrap();
    assert!(proof.verify(&root, &hash, mmr_index).is_ok())
}

#[test]
fn for_leaf_node() {
    let mmr = create_mmr(100);
    let root = mmr.get_merkle_root().unwrap();
    let leaf_pos = 28;
    let hash = int_to_hash(leaf_pos);
    let proof = MerkleProof::for_leaf_node(&mmr, leaf_pos).unwrap();
    assert!(proof.verify_leaf(&root, &hash, leaf_pos).is_ok())
}

//
// Mutable MMR
//

/// MMRs with no elements should provide sane defaults. The merkle root must be the hash of an empty string, b"".
#[test]
fn zero_length_mutable_mmr() {
    let mmr = MutableMmr::<_>::new(Vec::default());
    assert_eq!(mmr.len(), 0);
    assert_eq!(mmr.is_empty(), Ok(true));
    let empty_hash = H256::zero();
    assert_eq!(
        mmr.get_merkle_root(),
        Ok(hash_with_bitmap(&empty_hash, &mut Bitmap::create()))
    );
}

#[test]
// Note the hardcoded hashes are only valid when using Blake256 as the Hasher
fn delete() {
    let mut mmr = MutableMmr::<_>::new(Vec::default());
    assert_eq!(mmr.is_empty(), Ok(true));
    for i in 0..5 {
        assert!(mmr.push(&int_to_hash(i)).is_ok());
    }
    assert_eq!(mmr.len(), 5);
    let root = mmr.get_merkle_root().unwrap();
    assert_eq!(
        &root.to_hex(),
        "7b7ddec2af4f3d0b9b165750cf2ff15813e965d29ecd5318e0c8fea901ceaef4"
    );
    // Can't delete past bounds
    assert_eq!(mmr.delete_and_compress(5, true), false);
    assert_eq!(mmr.len(), 5);
    assert_eq!(mmr.is_empty(), Ok(false));
    assert_eq!(mmr.get_merkle_root(), Ok(root));
    // Delete some nodes
    assert!(mmr.push(&int_to_hash(5)).is_ok());
    assert!(mmr.delete_and_compress(0, false));
    assert!(mmr.delete_and_compress(2, false));
    assert!(mmr.delete_and_compress(4, true));
    let root = mmr.get_merkle_root().unwrap();
    assert_eq!(
        &root.to_hex(),
        "69e69ba0c6222f2d9caa68282de0ba7f1259a0fa2b8d84af68f907ef4ec05054"
    );
    assert_eq!(mmr.len(), 3);
    assert_eq!(mmr.is_empty(), Ok(false));
    // Can't delete that which has already been deleted
    assert!(!mmr.delete_and_compress(0, false));
    assert!(!mmr.delete_and_compress(2, false));
    assert!(!mmr.delete_and_compress(0, true));
    // .. or beyond bounds of MMR
    assert!(!mmr.delete_and_compress(99, true));
    assert_eq!(mmr.len(), 3);
    assert_eq!(mmr.is_empty(), Ok(false));
    // Merkle root should not have changed:
    assert_eq!(mmr.get_merkle_root(), Ok(root));
    assert!(mmr.delete_and_compress(1, false));
    assert!(mmr.delete_and_compress(5, false));
    assert!(mmr.delete(3));
    assert_eq!(mmr.len(), 0);
    assert_eq!(mmr.is_empty(), Ok(true));
    let root = mmr.get_merkle_root().unwrap();
    assert_eq!(
        &root.to_hex(),
        "2a540797d919e63cff8051e54ae13197315000bcfde53efd3f711bb3d24995bc"
    );
}

/// Successively build up an MMR and check that the roots, heights and indices are all correct.
#[test]
fn build_mutable_mmr() {
    // Check the mutable MMR against a standard MMR and a roaring bitmap. Create one with 5 leaf nodes *8 MMR nodes)
    let mmr_check = create_mmr(5);
    assert_eq!(mmr_check.len(), Ok(8));
    let mut bitmap = Bitmap::create();
    // Create a small mutable MMR
    let mut mmr = MutableMmr::<_>::new(Vec::default());
    for i in 0..5 {
        assert!(mmr.push(&int_to_hash(i)).is_ok());
    }
    // MutableMmr::len gives the size in terms of leaf nodes:
    assert_eq!(mmr.len(), 5);
    let mmr_root = mmr_check.get_merkle_root().unwrap();
    let root_check = hash_with_bitmap(&mmr_root, &mut bitmap);
    assert_eq!(mmr.get_merkle_root(), Ok(root_check));
    // Delete a node
    assert!(mmr.delete_and_compress(3, true));
    bitmap.add(3);
    let root_check = hash_with_bitmap(&mmr_root, &mut bitmap);
    assert_eq!(mmr.get_merkle_root(), Ok(root_check));
}

#[test]
fn equality_check_mutable() {
    let mut ma = MutableMmr::<_>::new(Vec::default());
    let mut mb = MutableMmr::<_>::new(Vec::default());
    assert!(ma == mb);
    assert!(ma.push(&int_to_hash(1)).is_ok());
    assert!(ma != mb);
    assert!(mb.push(&int_to_hash(1)).is_ok());
    assert!(ma == mb);
    assert!(ma.push(&int_to_hash(2)).is_ok());
    assert!(ma != mb);
    assert!(ma.delete(1));
    // Even though the two trees have the same apparent elements, they're still not equal, because we don't actually
    // delete anything
    assert!(ma != mb);
    // Add the same hash to mb and then delete it
    assert!(mb.push(&int_to_hash(2)).is_ok());
    assert!(mb.delete(1));
    // Now they're equal!
    assert!(ma == mb);
}



//
// Prunable MMR
//

#[test]
fn pruned_mmr_empty() {
    let mmr = create_mmr(0);
    let root = mmr.get_merkle_root();
    let pruned = prune_mmr(&mmr).expect("Could not create empty pruned MMR");
    assert_eq!(pruned.is_empty(), Ok(true));
    assert_eq!(pruned.get_merkle_root(), root);
}

#[test]
fn pruned_mmrs() {
    for size in &[6, 14, 63, 64, 65, 127] {
        let mmr = create_mmr(*size);
        let mmr2 = create_mmr(size + 2);

        let root = mmr.get_merkle_root();
        let mut pruned = prune_mmr(&mmr).expect("Could not create empty pruned MMR");
        assert_eq!(pruned.len(), mmr.len());
        assert_eq!(pruned.get_merkle_root(), root);
        // The pruned MMR works just like the normal one
        let new_hash = int_to_hash(*size);
        assert!(pruned.push(&new_hash).is_ok());
        assert!(pruned.push(&int_to_hash(*size + 1)).is_ok());
        assert_eq!(pruned.get_merkle_root(), mmr2.get_merkle_root());
        // But you can only get recent hashes
        assert_eq!(pruned.get_leaf_hash(*size / 2), Ok(None));
        assert_eq!(pruned.get_leaf_hash(*size), Ok(Some(new_hash)))
    }
}

use rand::{
    distributions::{Distribution, Uniform},
    Rng,
};

fn get_changes() -> (usize, Vec<H256>, Vec<u32>) {
    let mut rng = rand::thread_rng();
    let src_size: usize = rng.gen_range(25, 150);
    let addition_length = rng.gen_range(1, 100);
    let additions: Vec<H256> = Uniform::from(1..1000)
        .sample_iter(rng)
        .take(addition_length)
        .map(int_to_hash)
        .collect();
    let deletions: Vec<u32> = Uniform::from(0..src_size)
        .sample_iter(rng)
        .take(src_size / 5)
        .map(|v| v as u32)
        .collect();
    (src_size, additions, deletions)
}

/// Create a random-sized MMR. Add a random number of additions and deletions; and check the new root against the
/// result of `calculate_pruned_mmr_root`
#[test]
pub fn calculate_pruned_mmr_roots() {
    let (src_size, additions, deletions) = get_changes();
    let mut src = create_mutable_mmr(src_size);
    let src_root = src.get_merkle_root().expect("Did not get source root");
    let root =
        calculate_pruned_mmr_root(&src, additions.clone(), deletions.clone()).expect("Did not calculate new root");
    assert_ne!(src_root, root);
    // Double check
    additions.iter().for_each(|h| {
        src.push(h).unwrap();
    });
    deletions.iter().for_each(|i| {
        src.delete(*i);
    });
    let new_root = src.get_merkle_root().expect("Did not calculate new root");
    assert_eq!(root, new_root);
}

/// Create a random-sized MMR. Add a random number of additions; and check the new root against the
/// result of `calculate_mmr_root`
#[test]
pub fn calculate_mmr_roots() {
    let (src_size, additions, _) = get_changes();
    let mut src = create_mmr(src_size);
    let src_root = src.get_merkle_root().expect("Did not get source root");
    let root = calculate_mmr_root(&src, additions.clone()).expect("Did not calculate new root");
    assert_ne!(src_root, root);
    // Double check
    additions.iter().for_each(|h| {
        src.push(h).unwrap();
    });
    let new_root = src.get_merkle_root().expect("Did not calculate new root");
    assert_eq!(root, new_root);
}

//
// Change Tracker
//

// #[test]
// fn change_tracker() {
//     let mmr = MutableMmr::<_>::new(Vec::default());
//     let config = MerkleChangeTrackerConfig {
//         min_history_len: 15,
//         max_history_len: 20,
//     };

//     let mmr = MerkleChangeTracker::new(mmr, Vec::new(), config).unwrap();
//     assert_eq!(mmr.checkpoint_count(), Ok(0));
//     assert_eq!(mmr.is_empty(), Ok(true));
// }

// #[test]
// /// Test the same MMR structure as the test in mutable_mmr, but add in rewinding and restoring of state
// fn checkpoints() {
//     //----------- Construct and populate the initial MMR --------------------------
//     let base = MutableMmr::<_>::new(Vec::default());
//     let config = MerkleChangeTrackerConfig {
//         min_history_len: 15,
//         max_history_len: 20,
//     };
//     let mut mmr = MerkleChangeTracker::new(base, Vec::new(), config).unwrap();
//     for i in 0..5 {
//         assert!(mmr.push(&int_to_hash(i)).is_ok());
//     }
//     assert_eq!(mmr.len(), 5);
//     assert_eq!(mmr.checkpoint_count(), Ok(0));
//     //----------- Commit the history thus far  -----------------------------------
//     assert!(mmr.commit().is_ok());
//     assert_eq!(mmr.checkpoint_count(), Ok(1));
//     let root_at_1 = mmr.get_merkle_root().unwrap();
//     assert_eq!(
//         &root_at_1.to_hex(),
//         "7b7ddec2af4f3d0b9b165750cf2ff15813e965d29ecd5318e0c8fea901ceaef4"
//     );
//     //----------- Add a node and delete a few nodes  -----------------------------
//     assert!(mmr.push(&int_to_hash(5)).is_ok());
//     assert!(mmr.delete_and_compress(0, false));
//     assert!(mmr.delete_and_compress(2, false));
//     assert!(mmr.delete_and_compress(4, true));
//     //----------- Commit the history again, and check the expected sizes  --------
//     let root_at_2 = mmr.get_merkle_root().unwrap();
//     assert_eq!(
//         &root_at_2.to_hex(),
//         "69e69ba0c6222f2d9caa68282de0ba7f1259a0fa2b8d84af68f907ef4ec05054"
//     );
//     assert!(mmr.commit().is_ok());
//     assert_eq!(mmr.len(), 3);
//     assert_eq!(mmr.checkpoint_count(), Ok(2));
//     //----------- Generate another checkpoint, the MMR is now empty  --------
//     assert!(mmr.delete_and_compress(1, false));
//     assert!(mmr.delete_and_compress(5, false));
//     assert!(mmr.delete(3));
//     assert!(mmr.commit().is_ok());
//     assert_eq!(mmr.is_empty(), Ok(true));
//     assert_eq!(mmr.checkpoint_count(), Ok(3));
//     let root = mmr.get_merkle_root().unwrap();
//     assert_eq!(
//         &root.to_hex(),
//         "2a540797d919e63cff8051e54ae13197315000bcfde53efd3f711bb3d24995bc"
//     );
//     //----------- Create an empty checkpoint -------------------------------
//     assert!(mmr.commit().is_ok());
//     assert_eq!(mmr.checkpoint_count(), Ok(4));
//     assert_eq!(
//         &mmr.get_merkle_root().unwrap().to_hex(),
//         "2a540797d919e63cff8051e54ae13197315000bcfde53efd3f711bb3d24995bc"
//     );
//     //----------- Rewind the MMR two commits----------------------------------
//     assert!(mmr.rewind(2).is_ok());
//     assert_eq!(mmr.get_merkle_root().unwrap().to_hex(), root_at_2.to_hex());
//     //----------- Perform an empty commit ------------------------------------
//     assert!(mmr.commit().is_ok());
//     assert_eq!(mmr.len(), 3);
//     assert_eq!(mmr.checkpoint_count(), Ok(3));
// }

// #[test]
// fn reset_and_replay() {
//     // You don't have to use a Pruned MMR... any MMR implementation is fine
//     let base = MutableMmr::from(create_mmr(5));
//     let config = MerkleChangeTrackerConfig {
//         min_history_len: 15,
//         max_history_len: 20,
//     };
//     let mut mmr = MerkleChangeTracker::new(base, Vec::new(), config).unwrap();
//     let root = mmr.get_merkle_root();
//     // Add some new nodes etc
//     assert!(mmr.push(&int_to_hash(10)).is_ok());
//     assert!(mmr.push(&int_to_hash(11)).is_ok());
//     assert!(mmr.push(&int_to_hash(12)).is_ok());
//     assert!(mmr.delete(7));
//     // Reset - should be back to base state
//     assert!(mmr.reset().is_ok());
//     assert_eq!(mmr.get_merkle_root(), root);

//     // Change some more state
//     assert!(mmr.delete(1));
//     assert!(mmr.delete(3));
//     assert!(mmr.commit().is_ok()); //--- Checkpoint 0 ---
//     let root = mmr.get_merkle_root();

//     // Change a bunch more things
//     let hash_5 = int_to_hash(5);
//     assert!(mmr.push(&hash_5).is_ok());
//     assert!(mmr.commit().is_ok()); //--- Checkpoint 1 ---
//     assert!(mmr.push(&int_to_hash(6)).is_ok());
//     assert!(mmr.commit().is_ok()); //--- Checkpoint 2 ---

//     assert!(mmr.push(&int_to_hash(7)).is_ok());
//     assert!(mmr.commit().is_ok()); //--- Checkpoint 3 ---
//     assert!(mmr.delete(0));
//     assert!(mmr.delete(6));
//     assert!(mmr.commit().is_ok()); //--- Checkpoint 4 ---

//     // Get checkpoint 1
//     let cp = mmr.get_checkpoint(1).unwrap();
//     assert_eq!(cp.nodes_added(), &[hash_5]);
//     assert_eq!(*cp.nodes_deleted(), Bitmap::create());

//     // Get checkpoint 0
//     let cp = mmr.get_checkpoint(0).unwrap();
//     assert!(cp.nodes_added().is_empty());
//     let mut deleted = Bitmap::create();
//     deleted.add(1);
//     deleted.add(3);
//     assert_eq!(*cp.nodes_deleted(), deleted);

//     // Roll back to last time we save the root
//     assert!(mmr.replay(1).is_ok());
//     assert_eq!(mmr.len(), 3);

//     assert_eq!(mmr.get_merkle_root(), root);
// }


// #[test]
// fn serialize_and_deserialize_merklecheckpoint() {
//     let nodes_added = vec![int_to_hash(0), int_to_hash(1)];
//     let mut nodes_deleted = Bitmap::create();
//     nodes_deleted.add(1);
//     nodes_deleted.add(5);
//     let mcp = MerkleCheckPoint::new(nodes_added, nodes_deleted);

//     let ser_buf = bincode::serialize(&mcp).unwrap();
//     let des_mcp: MerkleCheckPoint = bincode::deserialize(&ser_buf).unwrap();
//     assert_eq!(mcp.into_parts(), des_mcp.into_parts());
// }

// #[test]
// fn update_of_base_mmr_with_history_bounds() {
//     let base = MutableMmr::<_>::new(Vec::default());
//     let config = MerkleChangeTrackerConfig {
//         min_history_len: 3,
//         max_history_len: 5,
//     };
//     let mut mmr = MerkleChangeTracker::new(base, Vec::new(), config).unwrap();
//     for i in 1..=5 {
//         assert!(mmr.push(&int_to_hash(i)).is_ok());
//         assert!(mmr.commit().is_ok());
//     }
//     let mmr_state = mmr.to_base_leaf_nodes(0, mmr.get_base_leaf_count()).unwrap();
//     assert_eq!(mmr_state.leaf_hashes.len(), 0);

//     assert!(mmr.push(&int_to_hash(6)).is_ok());
//     assert!(mmr.commit().is_ok());
//     let mmr_state = mmr.to_base_leaf_nodes(0, mmr.get_base_leaf_count()).unwrap();
//     assert_eq!(mmr_state.leaf_hashes.len(), 3);

//     for i in 7..=8 {
//         assert!(mmr.push(&int_to_hash(i)).is_ok());
//         assert!(mmr.commit().is_ok());
//     }
//     let mmr_state = mmr.to_base_leaf_nodes(0, mmr.get_base_leaf_count()).unwrap();
//     assert_eq!(mmr_state.leaf_hashes.len(), 3);

//     assert!(mmr.push(&int_to_hash(9)).is_ok());
//     assert!(mmr.commit().is_ok());
//     let mmr_state = mmr.to_base_leaf_nodes(0, mmr.get_base_leaf_count()).unwrap();
//     assert_eq!(mmr_state.leaf_hashes.len(), 6);
// }

#[test]
fn create_cache_update_and_rewind() {
    let config = MerkleChangeTrackerConfig { rewind_hist_len: 2 };
    let mut checkpoint_db = MemBackendVec::<MerkleCheckPoint>::new();
    let mut mmr_cache = MerkleChangeTracker::<_, _>::new(Vec::new(), checkpoint_db.clone(), config).unwrap();

    let h1 = int_to_hash(1);
    let h2 = int_to_hash(2);
    let h3 = int_to_hash(3);
    let h4 = int_to_hash(4);
    let h5 = int_to_hash(5);
    let h6 = int_to_hash(6);
    let h7 = int_to_hash(7);
    let h8 = int_to_hash(8);
    let ha = combine_hashes(&vec![h1, h2]);
    let hb = combine_hashes(&vec![h3, h4]);
    let hc = combine_hashes(&vec![h5, h6]);
    let hd = combine_hashes(&vec![h7, h8]);
    let hahb = combine_hashes(&vec![ha, hb]);
    let hchd = combine_hashes(&vec![hc, hd]);
    let cp1_mmr_only_root = combine_hashes(&vec![ha]);
    let cp2_mmr_only_root = combine_hashes(&vec![hahb]);
    let cp3_mmr_only_root = combine_hashes(&vec![hahb, hc]);
    let cp4_mmr_only_root = combine_hashes(&vec![combine_hashes(&vec![hahb, hchd])]);

    checkpoint_db
        .push(MerkleCheckPoint::new(vec![h1.clone(), h2.clone()], Bitmap::create()))
        .unwrap();
    assert!(mmr_cache.update().is_ok());
    assert_eq!(mmr_cache.get_mmr_only_root(), Ok(cp1_mmr_only_root.clone()));

    checkpoint_db
        .push(MerkleCheckPoint::new(vec![h3.clone(), h4.clone()], Bitmap::create()))
        .unwrap();
    assert!(mmr_cache.update().is_ok());
    assert_eq!(mmr_cache.get_mmr_only_root(), Ok(cp2_mmr_only_root.clone()));

    // Two checkpoint update
    checkpoint_db
        .push(MerkleCheckPoint::new(vec![h5.clone(), h6.clone()], Bitmap::create()))
        .unwrap();
    checkpoint_db
        .push(MerkleCheckPoint::new(vec![h7.clone(), h8.clone()], Bitmap::create()))
        .unwrap();
    assert!(mmr_cache.update().is_ok());
    assert_eq!(mmr_cache.get_mmr_only_root(), Ok(cp4_mmr_only_root.clone()));

    // No rewind
    checkpoint_db.truncate(4).unwrap();
    assert!(mmr_cache.update().is_ok());
    assert_eq!(mmr_cache.get_mmr_only_root(), Ok(cp4_mmr_only_root));

    // Only current MMR update
    checkpoint_db.truncate(3).unwrap();
    assert!(mmr_cache.update().is_ok());
    assert_eq!(mmr_cache.get_mmr_only_root(), Ok(cp3_mmr_only_root));

    // Full cache update
    checkpoint_db.truncate(1).unwrap();
    assert!(mmr_cache.update().is_ok());
    assert_eq!(mmr_cache.get_mmr_only_root(), Ok(cp1_mmr_only_root));
}

//
// MemBackendVec
//

#[test]
fn len_push_get_truncate_for_each_shift_clear() {
    let mut db_vec = MemBackendVec::<i32>::new();
    let mut mem_vec = vec![100, 200, 300, 400, 500, 600];
    assert_eq!(db_vec.len().unwrap(), 0);

    mem_vec.iter().for_each(|val| assert!(db_vec.push(val.clone()).is_ok()));
    assert_eq!(db_vec.len().unwrap(), mem_vec.len());

    mem_vec
        .iter()
        .enumerate()
        .for_each(|(i, val)| assert_eq!(db_vec.get(i).unwrap(), Some(val.clone())));
    assert_eq!(db_vec.get(mem_vec.len()).unwrap(), None);

    mem_vec.truncate(4);
    assert!(db_vec.truncate(4).is_ok());
    assert_eq!(db_vec.len().unwrap(), mem_vec.len());
    db_vec.for_each(|val| assert!(mem_vec.contains(&val.unwrap()))).unwrap();

    assert!(mem_vec.shift(2).is_ok());
    assert!(db_vec.shift(2).is_ok());
    assert_eq!(db_vec.len().unwrap(), 2);
    assert_eq!(db_vec.get(0).unwrap(), Some(300));
    assert_eq!(db_vec.get(1).unwrap(), Some(400));

    assert!(db_vec.clear().is_ok());
    assert_eq!(db_vec.len().unwrap(), 0);
}