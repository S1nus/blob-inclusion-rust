use celestia_types::nmt::NamespacedHashExt;
//use celestia_types::nmt::NamespacedHashExt;
use celestia_types::{Blob, nmt::Namespace, Commitment, ExtendedHeader};
//use rand::prelude::*;

//use sha2::{Sha256, Digest};

use std::fs::File;
//use std::io::prelude::*;
use celestia_types::hash::Hash;

mod row_inclusion;
//use row_inclusion::*;

use nmt_rs::{NamespacedHash, TmSha2Hasher};
use nmt_rs::simple_merkle::tree::MerkleTree;
use nmt_rs::simple_merkle::db::MemDb;
//use nmt_rs::simple_merkle::tree::MerkleHash;

#[tokio::main]
async fn main() {

    // Hardcoded values for the namespace and blob
    let namespace = Namespace::new_v0(&[1, 2, 3, 4, 5]).expect("Invalid namespace");
    let _commitment = Commitment([194, 162, 95, 38, 0, 61, 45, 149, 199, 177, 161, 111, 45, 244, 27, 227, 44, 248, 94, 113, 251, 63, 91, 16, 124, 90, 109, 182, 25, 145, 233, 196]);
    let _height = 1332908;

    // load Mocha-4 block #1332908 header from a file
    let header_bytes = std::fs::read("header.dat").unwrap();
    let dah = ExtendedHeader::decode_and_validate(&header_bytes).unwrap();
    let eds_row_roots = &dah.dah.row_roots();
    let eds_column_roots = &dah.dah.column_roots();
    let data_tree_leaves: Vec<_> = eds_row_roots.iter()
        .chain(eds_column_roots.iter())
        .map(|root| root.to_array())
        .collect();

    // try to get in and out of raw type
    let root_as_array = eds_row_roots[0].to_array();
    let root_recovered: NamespacedHash<29> = NamespacedHash::from_raw(&root_as_array).unwrap();
    assert_eq!(root_recovered, eds_row_roots[0]);

    // "Data root" is the merkle root of the EDS row and column roots
    let hasher = TmSha2Hasher {}; // Tendermint Sha2 hasher
    let mut tree: MerkleTree<MemDb<[u8; 32]>, TmSha2Hasher> = MerkleTree::with_hasher(hasher);
    for leaf in data_tree_leaves {
        tree.push_raw_leaf(&leaf);
    }
    // Ensure that the data root is the merkle root of the EDS row and column roots
    assert_eq!(dah.dah.hash(), Hash::Sha256(tree.root()));

    // extended data square (EDS) size
    let eds_size = eds_row_roots.len();
    // original data square (ODS) size
    let ods_size = eds_size/2;

    let blob_bytes = std::fs::read("blob.dat").unwrap();
    let mut blob = Blob::new(namespace, blob_bytes).unwrap();
    blob.index = Some(8);
    let blob_shares: Vec<[u8; 512]> = blob
        .to_shares()
        .expect("Failed to split blob to shares")
        .iter()
        .map(|share| share.data)
        .collect();

    let blob_index: usize = blob.index.unwrap().try_into().unwrap();
    let blob_size: usize = blob.data.len()/512;
    let first_row_index: usize = blob_index / ods_size;
    let last_row_index: usize = first_row_index + (blob_size / ods_size);
    println!("first row index: {} last row index: {}", first_row_index, last_row_index);

    // Since the row roots spanned by the blob are contiguous
    // their inclusion in the data root can be proved efficiently with a merkle range proof
    let rp = tree.build_range_proof(first_row_index..last_row_index+1);
    let blob_row_root_hashes: Vec<[u8; 32]> = tree.leaves()[first_row_index..last_row_index+1]
        .iter()
        .map(|leaf| leaf.hash().clone())
        .collect();
    match rp.verify_range(&tree.root(), &blob_row_root_hashes) {
        Ok(_) => println!("Range proof verified"),
        Err(_) => println!("Range proof verification failed"),
    }

    // load the blob proofs from file
    // One NMT range proof for each row of the square spanned by the blob
    // proves the blob's shares go into the respective row root
    let proofs_file = File::open("proofs.json").unwrap();
    let proofs: Vec<celestia_types::nmt::NamespaceProof> = serde_json::from_reader(proofs_file).unwrap();

    let mut start = 0;
    for i in 0..(last_row_index - first_row_index) {
        let proof = &proofs[i];
        let root = &eds_row_roots[first_row_index + i];
        let end = start + (proof.end_idx() as usize - proof.start_idx() as usize);
        let result = proof.verify_range(&root, &blob_shares[start..end], namespace.into());
        println!("row {} result: {}", i, result.is_ok());
        start = end;
    }
}