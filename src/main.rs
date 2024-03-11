use nmt_rs::simple_merkle::proof;
use nmt_rs::simple_merkle::tree::MerkleHash;
use nmt_rs::NamespaceMerkleHasher;
use tokio::main;

use celestia_rpc::{BlobClient, HeaderClient, Client};
use celestia_types::{Blob, nmt::Namespace, Commitment};
use celestia_types::blob::SubmitOptions;
use rand::prelude::*;
use nmt_rs::nmt_proof::NamespaceProof;
use celestia_types::nmt::{NamespacedHash, NamespacedHashExt, NamespacedSha2Hasher, NS_SIZE};
use celestia_types::nmt::namespace_proof::NmtNamespaceProof;

use std::collections::VecDeque;

#[tokio::main]
async fn main() {
    let token = std::env::var("CELESTIA_NODE_AUTH_TOKEN").expect("Token not provided");
    let client = Client::new("ws://localhost:26658", Some(&token))
        .await
        .expect("Failed creating rpc client");
    let network_head = client.header_network_head()
        .await
        .expect("could not get network head");

    let my_namespace = Namespace::new_v0(&[1, 2, 3, 4, 5]).expect("Invalid namespace");
    let commitment = Commitment([194, 162, 95, 38, 0, 61, 45, 149, 199, 177, 161, 111, 45, 244, 27, 227, 44, 248, 94, 113, 251, 63, 91, 16, 124, 90, 109, 182, 25, 145, 233, 196]);
    let height = 1332908;
    let dah = client.header_get_by_height(height)
        .await
        .expect("Failed getting header");
    let row_roots = dah.dah.row_roots;
    let blob = client.blob_get(height, my_namespace, commitment)
        .await
        .expect("Failed getting blob");
    let blob_size: usize = (blob.data.len()/512).try_into().unwrap(); // num shares
    println!("blob size: {}", blob_size);
    let square_size: usize = row_roots.len().try_into().unwrap();
    println!("Square size: {}", square_size);
    let blob_index: usize = blob.index.try_into().unwrap();
    let first_row_index =  blob_index / square_size;
    println!("First row index: {}", first_row_index);
    let last_row_index = first_row_index + (blob_size / square_size);
    println!("last row index: {}", last_row_index);
    let proofs: Vec<NmtNamespaceProof> = client.blob_get_proof(height, my_namespace, commitment)
        .await
        .expect("Failed getting proof")
        .iter()
        .map(|p| p.clone().into_inner())
        .collect();

    let hasher = NamespacedSha2Hasher::with_ignore_max_ns(true);

    /*let mut leaf_hashes: VecDeque<_> = blob.data.chunks(512)
        .map(|chunk| hasher.hash_leaf_with_namespace(chunk, my_namespace.into_inner()))
        .collect();*/
    let shares = blob.to_shares().expect("Failed to split blob to shares");
    let mut leaf_hashes: Vec<_> = shares.iter().map(|share| share.as_ref()).collect();

    // verify first row proof
    let first_row_leaves: Vec<&[u8]> = leaf_hashes.drain(..24).collect();
    let res = proofs[0].verify_range(&row_roots[first_row_index], &first_row_leaves, my_namespace.into_inner());
    if res.is_err() {
        panic!("Failed to verify first row");
    }

    // verify middle row proofs
    for i in 1..(proofs.len()-1) {
        let next_row_leaves: Vec<&[u8]> = leaf_hashes.drain(..32).collect();
        let res = proofs[i].verify_range(&row_roots[first_row_index+i], &next_row_leaves, my_namespace.into_inner());
        if res.is_err() {
            panic!("Failed to verify row {}",i);
        }
    }

    // verify last row proof
    let res = proofs[proofs.len()-1].verify_range(&row_roots[proofs.len()-1], &leaf_hashes, my_namespace.into_inner());
    if res.is_err() {
        panic!("Failed to verify last row");
    }
}

fn create_valid_ethereum_blob() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut buf = [0; 131072];
    rng.fill(&mut buf[..]);
    buf.to_vec()
}