use rand::{distributions::Alphanumeric, Rng};
use rs_merkle::{
    algorithms::Keccak256, utils, utils::properties::TreeProperties, MerkleProof, MerkleTree,
};
use std::convert::TryFrom;
// TODO:
// Remove main.rs before merge
// NOTE: in order to run, cargo build, cargo run
fn main() {
    let tree_props = TreeProperties {
        sorted_pair_enabled: true,
    };
    //let leaf_values = ["a", "b", "c", "d", "e", "f", "g"];
    let leaf_values: Vec<String> = (0..1000)
        .map(|_| {
            let rng = rand::thread_rng();
            let random_string: String = rng
                .sample_iter(&Alphanumeric)
                .take(1000)
                .map(char::from)
                .collect();
            random_string
        })
        .collect();

    let leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| Keccak256::hash(x.as_bytes()))
        .collect();

    let merkle_tree = MerkleTree::<Keccak256>::from_leaves(&leaves, tree_props);

    let index_to_prove = 1;
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove").unwrap();
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
        leaves.len(),
        tree_props
    ));
    println!(
        "tree root hash: {:?}",
        format!("{}{}", "0x", merkle_tree.root_hex().unwrap())
    );

    println!(
        "leaf {} : {}",
        index_to_prove,
        format!(
            "{}{}",
            "0x",
            utils::collections::to_hex_string(&leaves[index_to_prove])
        )
    );

    let proof_to_print = proof
        .proof_hashes_hex()
        .iter()
        .map(|x| format!("{}{}", "0x", x.as_str()))
        .collect::<Vec<String>>();

    println!("proof hash array: {:?}", proof_to_print);
}
