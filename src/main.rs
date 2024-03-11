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

    let mut leaf_hashes: VecDeque<_> = blob.data.chunks(512)
        .map(|chunk| hasher.hash_leaf_with_namespace(chunk, my_namespace.into_inner()))
        .collect();

    for (i, p) in proofs.iter().map(|mut p| p).enumerate() {
        //p.verify_range(root, raw_leaves, leaf_namespace)
        let row_leaves: Vec<NamespacedHash>;

        let start_index = match i {
            0 => (blob_index%(square_size/2)) as usize,
            _ => 0
        } + i*(square_size/2);
        let end_index: usize;
        if i == proofs.len() - 1 {
            end_index = (square_size/2) - (blob_index + blob_size)%(square_size/2) as usize + i*(square_size/2);
        } else {
            end_index = (square_size/2) as usize + i*(square_size/2);
        }
        println!("start index: {} end index: {}", start_index, end_index);

        if let NamespaceProof::PresenceProof { proof, ignore_max_ns } = p {
            println!("{}", proof.range.len());
            println!("{}", end_index - start_index);
            let hashes: Vec<_> = leaf_hashes.drain(0..(end_index-start_index)).collect();
            let res = proof.verify_range_with_hasher(
                &row_roots[first_row_index as usize+ i as usize],
                &hashes,
                hasher.clone(),
            );
            if res.is_err() {
                //println!("Presence proof failed: {:?}", res);
                println!("Invalid :( {:?}", res);
            } else {
                println!("Valid!");
            }
        } else {
            println!("Absence proof");
        }
    }

    /*for p in proofs {
        //println!("Proof: {:?}", p.into_inner());
        let inner = p.into_inner();
        match inner {
            NamespaceProof::PresenceProof { proof, ignore_max_ns } => {
                //println!("Presence proof: {:?}", proof);
                println!("Presence proof");
                for s in proof.siblings {
                    println!("{:x?}", s.hash());
                }
            }
            NamespaceProof::AbsenceProof { proof, ignore_max_ns, leaf } => {
                //println!("Absence proof: {:?}", proof);
                println!("Absence proof");
            }

        }
    }*/

    // I'm gonna post a blob
    /*let random_blob = create_valid_ethereum_blob();
    let blob = Blob::new(my_namespace, random_blob)
        .expect("Failed to create a blob");
    println!("Blob commitment: {:?}", blob.commitment);
    let height = client.blob_submit(&[blob], SubmitOptions::default())
        .await
        .expect("Failed submitting the blob");
    println!("Height: {}", height);*/

}

fn create_valid_ethereum_blob() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut buf = [0; 131072];
    rng.fill(&mut buf[..]);
    buf.to_vec()
}