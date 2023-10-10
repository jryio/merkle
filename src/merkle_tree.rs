use std::fmt::Debug;

use crate::hasher::{Hasher, Sha256Hasher};

// TODO: MerkleTree::root() -> T::Hash
// TODO: MerkleTree:proof()

#[derive(Debug)]
pub struct MerkleTree<T: Hasher> {
    /// Tree is a vector of Hashes defined as Hasher::Hash.
    ///
    /// A Hash has a size, can be turned into a [u8] slice (Into<Vec<u8>>), constructed from a [u8]
    tree: Vec<T::Hash>,
    /// Leaves are the number of data nodes used to initialize the Merkle Tree
    leaves: usize,
    /// Nodes are the total number of nodes in the Merkle Tree including the leaf nodes
    nodes: usize,
    /// Height is the height (or depth) of the binary tree given the initial number of leaves
    height: usize,
    /// Hash Size is the size of the output Hasher (T::hash_size())
    hash_size: usize,
}

impl<T: Hasher> MerkleTree<T>
where
    T::Hash: Debug,
{
    fn new() -> Self {
        Self {
            tree: Vec::new(),
            leaves: 0,
            nodes: 0,
            height: 0,
            hash_size: T::hash_size(),
        }
    }

    pub fn from_leaves<D: AsRef<[u8]>>(data: &[D]) -> Self {
        // Create a new Merkle Tree
        let mut merkle_tree = Self::new();

        // Hash the leaves
        let leaves = merkle_tree.hash_leaves(data);

        // Build tree
        let tree = merkle_tree.build_tree(&leaves);

        merkle_tree
    }

    fn hash_leaves<D: AsRef<[u8]>>(&self, data: &[D]) -> Vec<T::Hash> {
        data.iter().map(|x| T::hash(x.as_ref())).collect()
    }

    fn build_tree(&mut self, hashed: &[T::Hash]) {
        // Allocate enough space for all of the expected nodes in our tree
        self.calculate_height(hashed.len());
        self.calculate_nodes();
        self.tree = Vec::with_capacity(self.nodes);

        // Starting on the left of the Vec, insert out hashed leaf nodes
        self.tree.extend(hashed.iter());

        // Now build the inner-nodes (hashes of leaf nodes) all the way up to the root by pushing
        // the parents onto the Vec (on the right)
        self.build_parents(
            0,            /* start_index*/
            hashed.len(), /* level length */
        );
    }

    /// Case - Four Hashed Leave Nodes
    ///
    /// build_parents-1st    build_parents-2nd          build_parents-3rd
    /// [ L0, L1, L2, L3,    L4(L0+L1), L5(L2+L3),      L6(L4+L5)]
    ///   0   1   2   3      4          5               6
    ///   start_index = 0    start_index = 4            start_index = 6
    ///   length      = 4    length      = 2            length      = 0
    ///
    ///
    /// Case - Seven Hashed Leaf Nodes
    ///
    /// build_parents-1st               build_parents-2nd                       build_parents-3rd           build_parents-4th
    /// [ L0, L1, L2, L3, L4, L5, L6,   L7(L0+L1), L8(L2+L3), L9(L4+L5), L6,    L10(L7+L8), L11(L9+L6),     L12(L10+L11)]
    ///   0   1   2   3   4   5   6     7          8          9          10     11          12              13               = 14 nodes total
    ///   start_index = 0               start_index      = 7                    start_index      = 11       start_index      = 13
    ///   length      = 7               length = new_len = 4                    length = new_len = 2        length = new_len = 0
    ///   new_len     = 4               new_len          = 2                    new_len          = 1
    ///
    ///
    /// Case - Ten Hashed Leaf Nodes
    ///
    /// build_parents-1st
    /// [ L0, L1, L2, L3, L4, L5, L6, L7, L8, L9
    ///   0   1   2   3   4   5   6   7   8   9
    ///   start_index = 0
    ///   length      = 10
    ///   new_len     = 5
    fn build_parents(&mut self, start_index: usize, length: usize) {
        if length == 1 {
            return;
        }
        let mut new_len = length / 2;
        for i in 0..new_len {
            let left_index = start_index + (2 * i);
            let left = self.tree[left_index];
            // The right node will be the index immediately after the left one.
            // For an odd number of leaf nodes, the last node will not have a right.
            // In this case, hash_pair() will propogate the left node up the tree until
            // it eventually balances.
            let right_index = left_index + 1;
            let right = self.tree.get(right_index);
            // Compute the new parent and add to the tree
            // On the next recursion of this function,
            // these parent nodes should already be in the tree
            let parent = T::hash_pair(&left, right);
            self.tree.push(parent);
        }
        // If we had an odd number of nodes at this level,
        // push the remainder node to the end of the next levels
        if length % 2 == 1 {
            let index = start_index + length - 1;
            let last = self.tree[index];
            self.tree.push(last);
            // Update the next recursion to handle
            // the next level being 1 larger than expeted
            new_len += 1;
        }
        let new_start = start_index + (length);
        // Recurse to the next level
        self.build_parents(new_start, new_len)
    }

    fn calculate_height(&mut self, num_leaves: usize) {
        // Minimum possible height of the tree
        // More space in the vector will be allocated if necessary
        // floor(log_2(num_leaves + 1) + 1)
        self.height = match num_leaves {
            1 => 1,
            // n if n % 2 == 0 => ((num_leaves + 1).ilog2()) as usize,
            _ => (num_leaves as f32 + 1f32).log2().round() as usize,
        };
    }

    fn calculate_nodes(&mut self) {
        // Because a Merkle Tree is a binary tree, we can pre-compute the number of inner-nodes
        // (hashes) given the number of leaf nodes.
        //
        // This comes out to be:
        //      Total Nodes = 2^(H) - 1
        //
        // For a full balanced binary tree.
        self.nodes = 2usize.pow((self.height + 1) as u32) - 1;
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn nodes(&self) -> usize {
        self.tree.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::hasher::Sha256Hasher;

    use super::MerkleTree;

    #[test]
    fn test_basic_construction() {
        // Case - One Hashed Leaf Node
        let input = vec!["first"];
        let mktree = MerkleTree::<Sha256Hasher>::from_leaves(&input);
        assert_eq!(
            mktree.height(),
            1,
            "The height of the Merkle Tree with 1 leaf should be 1"
        );

        assert_eq!(
            mktree.tree.len(),
            1,
            "The number of total nodes of the Merkle Tree with 1 leaf (inclusive) should be 1"
        );

        // Case - Four Hashed Leaf Nodes
        let input = vec!["first", "second", "third", "fourth"];
        let mktree = MerkleTree::<Sha256Hasher>::from_leaves(&input);
        assert_eq!(
            mktree.height(),
            2,
            "The height of the Merkle Tree with 4 leaves should be 2"
        );

        assert_eq!(
            mktree.tree.len(),
            7,
            "The number of total nodes of the Merkle Tree with 4 leaves (inclusive) should be 7"
        );

        // Case - Seven Hashed Leaf Nodes
        let input = vec![
            "first", "second", "third", "fourth", "fifth", "sixth", "seventh",
        ];
        let mktree = MerkleTree::<Sha256Hasher>::from_leaves(&input);
        assert_eq!(
            mktree.height(),
            3,
            "The height of the Merkle Tree with 7 leaves should be 3"
        );

        assert_eq!(
            mktree.tree.len(),
            14,
            "The number of total nodes of the Merkle Tree with 7 leaves (inclusive) should be 14"
        );

        // Case - Eight Hashed Leaf Nodes
        let input = vec![
            "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eight",
        ];
        let mktree = MerkleTree::<Sha256Hasher>::from_leaves(&input);
        assert_eq!(
            mktree.height(),
            3,
            "The height of the Merkle Tree with 8 leaves should be 3"
        );

        assert_eq!(
            mktree.tree.len(),
            15,
            "The number of total nodes of the Merkle Tree with 8 leaves (inclusive) should be 15"
        );

        // Case - Ten Hashed Leaf Nodes
        let input = vec![
            "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eight", "ninth",
            "tenth",
        ];
        let mktree = MerkleTree::<Sha256Hasher>::from_leaves(&input);
        assert_eq!(
            mktree.height(),
            3,
            "The height of the Merkle Tree with 10 leaves should be 3"
        );

        assert_eq!(
            mktree.tree.len(),
            21,
            "The number of total nodes of the Merkle Tree with 10 leaves (inclusive) should be 21"
        );

        // Case - Eleven Hashed Leaf Nodes
        let input = vec![
            "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eight", "ninth",
            "tenth", "eleventh",
        ];
        let mktree = MerkleTree::<Sha256Hasher>::from_leaves(&input);
        assert_eq!(
            mktree.height(),
            4,
            "The height of the Merkle Tree with 11 leaves should be 4"
        );

        assert_eq!(
            mktree.tree.len(),
            23,
            "The number of total nodes of the Merkle Tree with 11 leaves (inclusive) should be 14"
        );
    }
}
