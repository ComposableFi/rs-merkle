use hex;
use rs_merkle::{algorithms::Keccak256, MerkleProof, MerkleTree};
use std::convert::TryFrom;

// TODO:
// Remove main.rs before merge
// remove hex dependency before merge
// Add tests for keccak256
// NOTE: in order to run, cargo build, cargo run
fn main() {
    let leaf_values = ["4", "5", "6", "7"];

    let mut leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| Keccak256::hash(x.as_bytes()))
        .collect();
    leaves.sort();

    let mut merkle_tree: MerkleTree<Keccak256> = MerkleTree::new();

    merkle_tree.insert(leaves[0]);
    merkle_tree.commit();
    merkle_tree.insert(leaves[1]);
    merkle_tree.commit();
    merkle_tree.insert(leaves[2]);
    merkle_tree.commit();
    merkle_tree.insert(leaves[3]);
    merkle_tree.commit();

    let indices_to_prove = vec![2];
    let leaves_to_prove = leaves.get(2..3).ok_or("can't get leaves to prove").unwrap();
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree
        .root()
        .ok_or("couldn't get the merkle root")
        .unwrap();

    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();

    // Parse proof back on the client
    let proof = MerkleProof::<Keccak256>::try_from(proof_bytes).unwrap();
    assert!(proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len()
    ));

    println!("tree root hash: {:?}", merkle_tree.root_hex().unwrap());
    println!("leaf A hash: {:?}", hex::encode(&leaves[0]));
    println!("leaf B hash: {:?}", hex::encode(&leaves[1]));
    println!("leaf C hash: {:?}", hex::encode(&leaves[2]));
    println!("leaf D hash: {:?}", hex::encode(&leaves[3]));
    println!("proof hash array: {:?}", proof.proof_hashes_hex());
}

// ["0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6", "0x1219c99b22ee9acd905b8b7805a91b29ace6c3866372231fa7a965b580278968"]

// ["0xe455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d", "0x0a75e973627ce3946884aca0fce20dbc26e232bcdf2c75a5bef979fa47140360"]
