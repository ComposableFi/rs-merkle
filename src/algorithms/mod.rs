//! This module contains built-in implementations of the [`Hasher`]
//!
//! [`Hasher`]: crate::Hasher
mod hash_algorithm;
mod keccak256;
mod sha256;
pub use hash_algorithm::HashAlgorithm as Hash;
pub use hash_algorithm::HashType;
pub use keccak256::Keccak256Algorithm as Keccak256;
pub use sha256::Sha256Algorithm as Sha256;
