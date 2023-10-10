use std::mem;

use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};

/// This trait is taken from [`rs_merkle::Hasher`]
///
/// [`rs_merkle::Hasher`]: https://docs.rs/rs_merkle/latest/rs_merkle/trait.Hasher.html
pub trait Hasher: Clone {
    type Hash: Copy + PartialEq + Into<Vec<u8>> + TryFrom<Vec<u8>>;

    fn hash(buffer: &[u8]) -> Self::Hash;

    fn hash_size() -> usize {
        mem::size_of::<Self::Hash>()
    }

    /// If we don't have a right node in the tree, use the left node as the right one.
    fn hash_pair(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        let mut combined: Vec<u8> = (*left).into();

        let result = if let Some(right) = right {
            let mut right: Vec<u8> = (*right).into();
            combined.append(&mut right);
            Self::hash(&combined)
        } else {
            *left
        };

        result
    }
}

#[derive(Clone)]
pub struct Sha256Hasher {}

impl Hasher for Sha256Hasher {
    type Hash = [u8; 32];

    fn hash(buffer: &[u8]) -> Self::Hash {
        let mut hasher = Sha256::new();
        hasher.update(buffer);
        hasher.finalize_fixed().into()
    }
}
