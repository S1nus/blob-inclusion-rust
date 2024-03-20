use celestia_types::nmt::NamespacedHashExt;
use celestia_types::{Blob, nmt::Namespace, Commitment, ExtendedHeader};
use rand::prelude::*;


use std::fs::File;
use std::io::prelude::*;
use celestia_types::hash::Hash;

mod row_inclusion;
use row_inclusion::*;

#[tokio::main]
async fn main() {
    /*let token = std::env::var("CELESTIA_NODE_AUTH_TOKEN").expect("Token not provided");
    let client = Client::new("ws://localhost:26658", Some(&token))
        .await
        .expect("Failed creating rpc client");
    let network_head = client.header_network_head()
        .await
        .expect("could not get network head");*/

    let my_namespace = Namespace::new_v0(&[1, 2, 3, 4, 5]).expect("Invalid namespace");
    let commitment = Commitment([194, 162, 95, 38, 0, 61, 45, 149, 199, 177, 161, 111, 45, 244, 27, 227, 44, 248, 94, 113, 251, 63, 91, 16, 124, 90, 109, 182, 25, 145, 233, 196]);
    let height = 1332908;

    // replacing the fetch with a file read
    /*let dah = client.header_get_by_height(height)
        .await
        .expect("Failed getting header");
    let header_bytes = dah.encode_vec().unwrap();
    let mut header_file = File::create("header.dat").unwrap();
    header_file.write_all(&header_bytes).unwrap();*/

    let header_bytes = std::fs::read("header.dat").unwrap();
    let dah = ExtendedHeader::decode_and_validate(&header_bytes).unwrap();

    let row_roots = &dah.dah.row_roots;

    let leaves: Vec<_> = dah.dah.row_roots.iter()
        .chain(dah.dah.column_roots.iter())
        .map(|root| Sha256::hash(&root.to_array()))
        .collect();
    let mut tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = Hash::Sha256(tree.root().unwrap());
    println!("root from header {:?}", dah.dah.hash());
    println!("root from tree {:?}", root);

    // replacing fetch with a file read
    /*let blob = client.blob_get(height, my_namespace, commitment)
        .await
        .expect("Failed getting blob");*/
    let blob_bytes = std::fs::read("blob.dat").unwrap();
    let mut blob = Blob::new(my_namespace, blob_bytes).unwrap();
    blob.index = 8;

    let blob_bytes = &blob.data;
    let mut file = File::create("blob.dat").unwrap();
    file.write_all(&blob_bytes).unwrap();
    let blob_size: usize = (blob.data.len()/512).try_into().unwrap(); // num shares
    println!("blob size: {}", blob_size);
    let square_size: usize = row_roots.len().try_into().unwrap();
    println!("Square size: {}", square_size);
    let blob_index: usize = blob.index.try_into().unwrap();
    let first_row_index =  blob_index / square_size;
    println!("First row index: {}", first_row_index);
    let last_row_index = first_row_index + (blob_size / square_size);
    println!("last row index: {}", last_row_index);

    let p0_bytes = bincode::serialize(&row_roots[first_row_index]).unwrap();
    let p0_from_bytes: celestia_types::nmt::NamespaceProof = bincode::deserialize(&p0_bytes).unwrap();

    /*let proofs: Vec<NmtNamespaceProof> = client.blob_get_proof(height, my_namespace, commitment)
        .await
        .expect("Failed getting proof")
        .iter()
        //.map(|p| p.clone().into_inner())
        .map(|p| NamespaceProof::from(p.clone()))
        .collect();*/

    /*let proofs: Vec<celestia_types::nmt::NamespaceProof> = client.blob_get_proof(height, my_namespace, commitment)
    .await
    .expect("Failed getting proof")
    .iter()
    .map(|p| celestia_types::nmt::NamespaceProof::from(p.clone()))
    .collect();

    let proofs_bytes = serde_json::to_string(&proofs).unwrap();
    let mut proofs_data_file = File::create("proofs.json").unwrap();
    proofs_data_file.write_all(proofs_bytes.as_bytes()).unwrap();*/
    let proofs_file = File::open("proofs.json").unwrap();
    let proofs: Vec<celestia_types::nmt::NamespaceProof> = serde_json::from_reader(proofs_file).unwrap();


    let shares = blob.to_shares().expect("Failed to split blob to shares");
    let mut leaf_hashes: Vec<_> = shares.iter().map(|share| share.as_ref()).collect();

    // verify first row proof
    let first_row_leaves: Vec<&[u8]> = leaf_hashes.drain(..((square_size/2) - (blob_index%(square_size/2)))).collect();
    let res = proofs[0].verify_range(&row_roots[first_row_index], &first_row_leaves, my_namespace.into_inner());
    if res.is_err() {
        panic!("Failed to verify first row");
    }

    // verify middle row proofs
    for i in 1..(proofs.len()-1) {
        let next_row_leaves: Vec<&[u8]> = leaf_hashes.drain(..(square_size/2)).collect();
        let res = proofs[i].verify_range(&row_roots[first_row_index+i], &next_row_leaves, my_namespace.into_inner());
        if res.is_err() {
            panic!("Failed to verify row {}",i);
        }
    }

    // verify last row proof
    let last_row_leaves = leaf_hashes;
    let res = proofs[proofs.len()-1].verify_range(&row_roots[proofs.len()-1], &last_row_leaves, my_namespace.into_inner());
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