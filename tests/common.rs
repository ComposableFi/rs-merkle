use rs_merkle::{utils::properties::TreeProperties, Hasher, MerkleTree};

pub struct TestData<T: Hasher> {
    pub leaf_values: Vec<String>,
    pub expected_root_hex: String,
    pub leaf_hashes: Vec<T::Hash>,
}

fn combine<T: Clone>(active: Vec<T>, rest: Vec<T>, mut combinations: Vec<Vec<T>>) -> Vec<Vec<T>> {
    return if rest.is_empty() {
        if active.is_empty() {
            combinations
        } else {
            combinations.push(active);
            combinations
        }
    } else {
        let mut next = active.clone();

        if let Some(first) = rest.get(0) {
            next.push(first.clone());
        }

        combinations = combine(next, rest.clone().drain(1..).collect(), combinations);
        combinations = combine(active, rest.clone().drain(1..).collect(), combinations);
        combinations
    };
}

/// Create all possible combinations of elements inside a vector without duplicates
pub fn combinations<T: Clone>(vec: Vec<T>) -> Vec<Vec<T>> {
    combine(Vec::new(), vec, Vec::new())
}

pub fn setup<T: Hasher>(leaf_values: &[&str], expected_root_hex: &str) -> TestData<T> {
    let leaf_hashes: Vec<T::Hash> = leaf_values.iter().map(|x| T::hash(x.as_bytes())).collect();

    TestData {
        leaf_values: leaf_values.iter().cloned().map(String::from).collect(),
        leaf_hashes,
        expected_root_hex: String::from(expected_root_hex),
    }
}

#[derive(Clone)]
pub struct ProofTestCases<T: Hasher> {
    pub merkle_tree: MerkleTree<T>,
    pub cases: Vec<MerkleProofTestCase<T>>,
}

#[derive(Clone)]
pub struct MerkleProofTestCase<T: Hasher> {
    pub leaf_indices_to_prove: Vec<usize>,
    pub leaf_hashes_to_prove: Vec<T::Hash>,
}

impl<T: Hasher> MerkleProofTestCase<T> {
    fn new(leaf_hashes_to_prove: Vec<T::Hash>, leaf_indices_to_prove: Vec<usize>) -> Self {
        Self {
            // title: format!("from a tree of {} elements for {} elements at positions {:?}", leaf_hashes.len(), leaf_indices_to_prove.len(), leaf_indices_to_prove),
            leaf_hashes_to_prove,
            leaf_indices_to_prove,
        }
    }
}

pub fn setup_proof_test_cases<T: Hasher>(
    tree_properties: TreeProperties,
) -> Vec<ProofTestCases<T>> {
    let max_case = [
        "a", "b", "c", "d", "e", "f", "g", "h", "k", "l", "m", "o", "p", "r", "s",
    ];

    max_case
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let tree_elements = max_case.get(0..index + 1).unwrap();

            let leaves: Vec<T::Hash> = tree_elements
                .iter()
                .map(|x| T::hash(x.as_bytes()))
                .collect();

            let tuples: Vec<(usize, T::Hash)> = leaves.iter().cloned().enumerate().collect();

            let possible_proof_elements_combinations = combinations(tuples);

            let cases: Vec<MerkleProofTestCase<T>> = possible_proof_elements_combinations
                .iter()
                .cloned()
                .map(|proof_elements| {
                    let (indices, leaves2): (Vec<usize>, Vec<T::Hash>) =
                        proof_elements.iter().cloned().unzip();
                    MerkleProofTestCase::new(leaves2, indices)
                })
                .collect();
            let merkle_tree = MerkleTree::<T>::from_leaves(&leaves, tree_properties);

            let case = ProofTestCases { merkle_tree, cases };
            case
        })
        .collect()
}
