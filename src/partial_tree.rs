use crate::prelude::*;
use crate::{error::Error, utils, utils::properties::TreeProperties, Hasher};

type PartialTreeLayer<H> = Vec<(usize, H)>;

/// Partial tree represents a part of the original tree that is enough to calculate the root.
/// Used in to extract the root in a merkle proof, to apply diff to a tree or to merge
/// multiple trees into one.
///
/// It is a rare case when you need to use this struct on it's own. It's mostly used inside
/// [`MerkleTree`] and [`MerkleProof`]
///
/// [`MerkleTree`]: crate::MerkleTree
/// [`MerkleProof`]: crate::MerkleProof
#[derive(Clone)]
pub struct PartialTree<T: Hasher> {
    layers: Vec<Vec<(usize, T::Hash)>>,
}

impl<T: Hasher> Default for PartialTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Hasher> PartialTree<T> {
    /// Takes leaves (item hashes) as an argument and build a Merkle Tree from them.
    /// Since it's a partial tree, hashes must be accompanied by their index in the original tree.
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// This is a helper function to build a full tree from a full set of leaves without any
    /// helper indices
    pub fn from_leaves(leaves: &[T::Hash], tree_properties: TreeProperties) -> Result<Self, Error> {
        let leaf_tuples: Vec<(usize, T::Hash)> = leaves.iter().cloned().enumerate().collect();

        Self::build(
            vec![leaf_tuples],
            utils::indices::tree_depth(leaves.len()),
            tree_properties,
        )
    }

    pub fn build(
        partial_layers: Vec<Vec<(usize, T::Hash)>>,
        depth: usize,
        tree_properties: TreeProperties,
    ) -> Result<Self, Error> {
        let layers = Self::build_tree(partial_layers, depth, tree_properties)?;

        Ok(Self { layers })
    }

    fn sorted_concat_and_hash(
        left_node: Option<&T::Hash>,
        right_node: Option<&T::Hash>,
        current_layer: &mut Vec<(usize, T::Hash)>,
        parent_node_index: usize,
    ) -> Result<(), Error> {
        match left_node {
            // Populate `current_layer` back for the next iteration
            Some(left) => {
                let left_hex = utils::collections::to_hex_string(left);

                match right_node {
                    Some(right) => {
                        let right_hex = utils::collections::to_hex_string(right);
                        if right_hex < left_hex {
                            current_layer
                                .push((parent_node_index, T::concat_and_hash(right, left_node)))
                        } else {
                            current_layer
                                .push((parent_node_index, T::concat_and_hash(left, right_node)))
                        }
                    }
                    None => current_layer
                        .push((parent_node_index, T::concat_and_hash(left, right_node))),
                }
                Ok(())
            }
            None => return Err(Error::not_enough_helper_nodes()),
        }
    }

    fn unsorted_concat_and_hash(
        left_node: Option<&T::Hash>,
        right_node: Option<&T::Hash>,
        current_layer: &mut Vec<(usize, T::Hash)>,
        parent_node_index: usize,
    ) -> Result<(), Error> {
        match left_node {
            // Populate `current_layer` back for the next iteration
            Some(left) => {
                current_layer.push((parent_node_index, T::concat_and_hash(left, right_node)))
            }
            None => return Err(Error::not_enough_helper_nodes()),
        }
        Ok(())
    }

    /// This is a general algorithm for building a partial tree. It can be used to extract root
    /// from merkle proof, or if a complete set of leaves provided as a first argument and no
    /// helper indices given, will construct the whole tree.
    fn build_tree(
        mut partial_layers: Vec<Vec<(usize, T::Hash)>>,
        full_tree_depth: usize,
        tree_properties: TreeProperties,
    ) -> Result<Vec<PartialTreeLayer<T::Hash>>, Error> {
        let mut partial_tree: Vec<Vec<(usize, T::Hash)>> = Vec::new();
        let mut current_layer = Vec::new();

        // Reversing helper nodes, so we can remove one layer starting from 0 each iteration
        let mut reversed_layers: Vec<Vec<(usize, T::Hash)>> =
            partial_layers.drain(..).rev().collect();

        // This iterates to full_tree_depth and not to the partial_layers_len because when constructing
        // It is iterating to full_tree_depth instead of partial_layers.len to address the case
        // of applying changes to a tree when tree requires a resize, and partial layer len
        // in that case going to be lower that the resulting tree depth
        for _ in 0..full_tree_depth {
            // Appending helper nodes to the current known nodes
            if let Some(mut nodes) = reversed_layers.pop() {
                current_layer.append(&mut nodes);
            }

            current_layer.sort_by(|(a, _), (b, _)| a.cmp(b));

            // Adding partial layer to the tree
            partial_tree.push(current_layer.clone());

            // This empties `current` layer and prepares it to be reused for the next iteration
            let (indices, nodes): (Vec<usize>, Vec<T::Hash>) = current_layer.drain(..).unzip();
            let parent_layer_indices = utils::indices::parent_indices(&indices);

            for (i, parent_node_index) in parent_layer_indices.iter().enumerate() {
                let left_node = nodes.get(i * 2);
                let right_node = nodes.get(i * 2 + 1);

                if tree_properties.sorted_pair_enabled {
                    Self::sorted_concat_and_hash(
                        left_node,
                        right_node,
                        &mut current_layer,
                        *parent_node_index,
                    )?;
                } else {
                    Self::unsorted_concat_and_hash(
                        left_node,
                        right_node,
                        &mut current_layer,
                        *parent_node_index,
                    )?;
                }
            }
        }

        partial_tree.push(current_layer.clone());

        Ok(partial_tree)
    }

    /// Returns how many layers there is between leaves and the root
    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Return the root of the tree
    pub fn root(&self) -> Option<&T::Hash> {
        Some(&self.layers.last()?.first()?.1)
    }

    pub fn contains(&self, layer_index: usize, node_index: usize) -> bool {
        match self.layers().get(layer_index) {
            Some(layer) => layer.iter().any(|(index, _)| *index == node_index),
            None => false,
        }
    }

    /// Consumes other partial tree into itself, replacing any conflicting nodes with nodes from
    /// `other` in the process. Doesn't rehash the nodes, so the integrity of the result is
    /// not verified. It gives an advantage in speed, but should be used only if the integrity of
    /// the tree can't be broken, for example, it is used in the `.commit` method of the
    /// `MerkleTree`, since both partial trees are essentially constructed in place and there's
    /// no need to verify integrity of the result.
    pub fn merge_unverified(&mut self, other: Self) {
        // Figure out new tree depth after merge
        let depth_difference = other.layers().len() - self.layers().len();
        let combined_tree_size = if depth_difference > 0 {
            other.layers().len()
        } else {
            self.layers().len()
        };

        for layer_index in 0..combined_tree_size {
            let mut combined_layer: Vec<(usize, T::Hash)> = Vec::new();

            if let Some(self_layer) = self.layers().get(layer_index) {
                let mut filtered_layer: Vec<(usize, T::Hash)> = self_layer
                    .iter()
                    .filter(|(node_index, _)| !other.contains(layer_index, *node_index))
                    .cloned()
                    .collect();

                combined_layer.append(&mut filtered_layer);
            }

            if let Some(other_layer) = other.layers().get(layer_index) {
                let mut cloned_other_layer = other_layer.clone();
                combined_layer.append(&mut cloned_other_layer);
            }

            combined_layer.sort_by(|(a, _), (b, _)| a.cmp(b));
            // iterate through combined layer
            // combined_layer.iter().for_each(|(_, node)| {
            //     std::println!("layer {} {:?}", layer_index, node);
            // });
            // std::println!("layer {} - {:?}", layer_index, &combined_layer);
            self.upsert_layer(layer_index, combined_layer);
        }
    }

    /// Replace layer at a given index with a new layer. Used during tree merge
    fn upsert_layer(&mut self, layer_index: usize, mut new_layer: Vec<(usize, T::Hash)>) {
        match self.layers.get_mut(layer_index) {
            Some(layer) => {
                layer.clear();
                layer.append(new_layer.as_mut())
            }
            None => self.layers.push(new_layer),
        }
    }

    pub fn layer_nodes(&self) -> Vec<Vec<T::Hash>> {
        let hashes: Vec<Vec<T::Hash>> = self
            .layers()
            .iter()
            .map(|layer| layer.iter().cloned().map(|(_, hash)| hash).collect())
            .collect();

        hashes
    }

    /// Returns partial tree layers
    pub fn layers(&self) -> &[Vec<(usize, T::Hash)>] {
        &self.layers
    }

    /// Clears all elements in the ree
    pub fn clear(&mut self) {
        self.layers.clear();
    }
}
