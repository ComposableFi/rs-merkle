use super::{Keccak256 as KeccakAlgo, Sha256 as ShaAlgo};
use crate::{prelude::*, Hasher};

#[derive(Clone)]
pub struct HashAlgorithm {}

#[derive(Clone)]
pub enum HashType {
    Keccak256,
    Sha256,
}

impl Hasher for HashAlgorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8], hash_type: HashType) -> [u8; 32] {
        match hash_type {
            HashType::Keccak256 => KeccakAlgo::hash(data),
            HashType::Sha256 => ShaAlgo::hash(data),
        }
    }
}
