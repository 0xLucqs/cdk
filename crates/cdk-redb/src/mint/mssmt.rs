//! Redb storage backend for Merkle Sum Sparse Tree
use std::any::Any;
use std::path::Path;
use std::sync::Arc;

use cdk_common::common::NamespaceableTreeStore;
use cdk_common::database;
use mssmt::{Branch, CompactLeaf, Db, EmptyTree, Leaf, Node, TreeError};
use redb::{Database, TableDefinition};
use sha2::Sha256;

use super::super::error::Error;

const TREE_SIZE: usize = 257;

// Define table names
const BRANCHES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mssmt_branches");
const LEAVES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mssmt_leaves");
const COMPACT_LEAVES_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("mssmt_compact_leaves");
const ROOTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mssmt_roots");

/// Redb storage backend for Merkle Sum Sparse Tree
#[derive(Debug, Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    namespace: String,
    empty_tree: Arc<[Node<32, Sha256>; TREE_SIZE]>,
}

impl RedbStore {
    /// Create a new Redb store with the given path and namespace
    pub fn new(path: &Path) -> Result<Self, Error> {
        let db = Database::create(path)?;
        let db = Arc::new(db);
        let empty_tree = EmptyTree::<32, Sha256>::empty_tree();
        let store = Self {
            db,
            namespace: "default".to_string(),
            empty_tree,
        };
        store.migrate()?;
        Ok(store)
    }

    /// Run database migrations
    pub fn migrate(&self) -> Result<(), Error> {
        let write_txn = self.db.begin_write()?;
        let _ = write_txn.open_table(BRANCHES_TABLE)?;
        let _ = write_txn.open_table(LEAVES_TABLE)?;
        let _ = write_txn.open_table(COMPACT_LEAVES_TABLE)?;
        let _ = write_txn.open_table(ROOTS_TABLE)?;
        write_txn.commit()?;
        Ok(())
    }

    fn get_leaf(&self, key: &[u8; 32]) -> Option<Leaf<32, Sha256>> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(LEAVES_TABLE).ok()?;
        let red_key = [self.namespace.as_bytes(), key].concat();
        let data = table.get(red_key.as_slice()).ok()??;
        let (sum, value) = Self::deserialize_leaf(data.value());
        Some(Leaf::new(value, sum))
    }

    fn get_compact_leaf(&self, key: &[u8; 32]) -> Option<CompactLeaf<32, Sha256>> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(COMPACT_LEAVES_TABLE).ok()?;
        let red_key = [self.namespace.as_bytes(), key].concat();
        let data = table.get(red_key.as_slice()).ok()??;
        let (leaf_key, sum, value) = Self::deserialize_compact_leaf(data.value());
        Some(unsafe { CompactLeaf::new_with_hash(*key, Leaf::new(value, sum), leaf_key) })
    }

    fn get_branch(&self, key: &[u8; 32]) -> Option<Branch<32, Sha256>> {
        let get_node = |key: &[u8; 32]| {
            if let Some(node) = self.get_branch(key) {
                Node::Branch(node)
            } else if let Some(leaf) = self.get_leaf(key) {
                Node::Leaf(leaf)
            } else if let Some(compact) = self.get_compact_leaf(key) {
                Node::Compact(compact)
            } else {
                self.empty_tree()[0].clone()
            }
        };
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(BRANCHES_TABLE).ok()?;
        let red_key = [self.namespace.as_bytes(), key].concat();
        let data = table.get(red_key.as_slice()).ok()??;

        let (l_hash, r_hash, sum) = Self::deserialize_branch(data.value());

        // Create computed branch with just the hashes and sum
        Some(unsafe { Branch::new_with_hash(get_node(&l_hash), get_node(&r_hash), *key, sum) })
    }

    fn serialize_branch(branch: &Branch<32, Sha256>) -> Vec<u8> {
        let (left, right) = branch.children();
        let mut data = Vec::with_capacity(72); // 32 + 32 + 8 bytes
        data.extend_from_slice(left.hash().as_ref());
        data.extend_from_slice(right.hash().as_ref());
        data.extend_from_slice(&branch.sum().to_be_bytes());
        data
    }
    fn deserialize_branch(data: &[u8]) -> ([u8; 32], [u8; 32], u64) {
        let l_hash: [u8; 32] = data[0..32].try_into().unwrap();
        let r_hash: [u8; 32] = data[32..64].try_into().unwrap();
        let sum = u64::from_be_bytes(data[64..72].try_into().unwrap());
        (l_hash, r_hash, sum)
    }

    fn serialize_leaf(leaf: &Leaf<32, Sha256>) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + leaf.value().len());
        data.extend_from_slice(&leaf.sum().to_be_bytes());
        data.extend_from_slice(leaf.value());
        data
    }
    fn deserialize_leaf(data: &[u8]) -> (u64, Vec<u8>) {
        let sum = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let value = data[8..].to_vec();
        (sum, value)
    }
    fn serialize_compact_leaf(compact_leaf: &CompactLeaf<32, Sha256>) -> Vec<u8> {
        let mut data = Vec::with_capacity(32 + 8 + compact_leaf.leaf().value().len()); // key + leaf
        data.extend_from_slice(compact_leaf.key());
        data.extend_from_slice(Self::serialize_leaf(compact_leaf.leaf()).as_slice());
        data
    }
    fn deserialize_compact_leaf(data: &[u8]) -> ([u8; 32], u64, Vec<u8>) {
        let key: [u8; 32] = data[0..32].try_into().unwrap();
        let sum = u64::from_be_bytes(data[32..40].try_into().unwrap());
        let value = data[40..].to_vec();
        (key, sum, value)
    }
}

impl NamespaceableTreeStore for RedbStore {
    fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.to_string();
    }
    fn get_leaf(&self, key: &[u8; 32]) -> Option<Leaf<32, Sha256>> {
        self.get_leaf(key)
    }
}

impl Db<32, Sha256> for RedbStore {
    type DbError = database::Error;
    fn get_root_node(&self) -> Option<Branch<32, Sha256>> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(ROOTS_TABLE).ok()?;
        let key = self.namespace.as_bytes();
        let data = table.get(key).ok()??;
        let root_hash: [u8; 32] = data.value().try_into().ok()?;

        self.get_branch(&root_hash)
    }

    fn get_children(
        &self,
        height: usize,
        key: [u8; 32],
    ) -> Result<(Node<32, Sha256>, Node<32, Sha256>), TreeError<Self::DbError>> {
        let get_node = |height: usize, key: [u8; 32]| {
            if key == self.empty_tree()[height].hash() {
                self.empty_tree()[height].clone()
            } else if let Some(node) = self.get_branch(&key) {
                Node::Branch(node.clone())
            } else if let Some(leaf) = self.get_leaf(&key) {
                Node::Leaf(leaf.clone())
            } else if let Some(compact) = self.get_compact_leaf(&key) {
                Node::Compact(compact.clone())
            } else {
                self.empty_tree()[height].clone()
            }
        };
        let node = get_node(height, key);
        if key != self.empty_tree()[height].hash()
            && node.hash() == self.empty_tree()[height].hash()
        {
            return Err(TreeError::NodeNotFound);
        }

        if let Node::Branch(branch) = node {
            let left = get_node(height + 1, branch.left().hash());
            let right = get_node(height + 1, branch.right().hash());
            Ok((left, right))
        } else {
            Err(TreeError::ExpectedBranch)
        }
    }

    fn insert_leaf(&mut self, leaf: Leaf<32, Sha256>) -> Result<(), TreeError<Self::DbError>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))?;
        {
            let mut table = write_txn
                .open_table(LEAVES_TABLE)
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
            let red_key = [self.namespace.as_bytes(), leaf.hash().as_ref()].concat();
            let data = Self::serialize_leaf(&leaf);
            table
                .insert(red_key.as_slice(), data.as_slice())
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
        }
        write_txn
            .commit()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))
    }

    fn insert_branch(
        &mut self,
        branch: Branch<32, Sha256>,
    ) -> Result<(), TreeError<Self::DbError>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))?;
        {
            let mut table = write_txn
                .open_table(BRANCHES_TABLE)
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
            let red_key = [self.namespace.as_bytes(), branch.hash().as_ref()].concat();
            let data = Self::serialize_branch(&branch);
            table
                .insert(red_key.as_slice(), data.as_slice())
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
        }
        write_txn
            .commit()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))
    }

    fn insert_compact_leaf(
        &mut self,
        compact_leaf: CompactLeaf<32, Sha256>,
    ) -> Result<(), TreeError<Self::DbError>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))?;
        {
            let mut table = write_txn
                .open_table(COMPACT_LEAVES_TABLE)
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
            let red_key = [self.namespace.as_bytes(), compact_leaf.hash().as_ref()].concat();
            let data = Self::serialize_compact_leaf(&compact_leaf);
            table
                .insert(red_key.as_slice(), data.as_slice())
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
        }
        write_txn
            .commit()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))
    }

    fn empty_tree(&self) -> Arc<[Node<32, Sha256>; TREE_SIZE]> {
        Arc::clone(&self.empty_tree)
    }

    fn update_root(&mut self, root: Branch<32, Sha256>) -> Result<(), TreeError<Self::DbError>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))?;
        {
            let mut table = write_txn
                .open_table(ROOTS_TABLE)
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
            table
                .insert(self.namespace.as_bytes(), root.hash().as_slice())
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
        }
        write_txn
            .commit()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))
    }

    fn delete_branch(&mut self, key: &[u8; 32]) -> Result<(), TreeError<Self::DbError>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))?;
        {
            let mut table = write_txn
                .open_table(BRANCHES_TABLE)
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
            let red_key = [self.namespace.as_bytes(), key].concat();
            table
                .remove(red_key.as_slice())
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
        }
        write_txn
            .commit()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))
    }

    fn delete_leaf(&mut self, key: &[u8; 32]) -> Result<(), TreeError<Self::DbError>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))?;
        {
            let mut table = write_txn
                .open_table(LEAVES_TABLE)
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
            let red_key = [self.namespace.as_bytes(), key].concat();
            table
                .remove(red_key.as_slice())
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
        }
        write_txn
            .commit()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))
    }

    fn delete_compact_leaf(&mut self, key: &[u8; 32]) -> Result<(), TreeError<Self::DbError>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))?;
        {
            let mut table = write_txn
                .open_table(COMPACT_LEAVES_TABLE)
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
            let red_key = [self.namespace.as_bytes(), key].concat();
            table
                .remove(red_key.as_slice())
                .map_err(Error::from)
                .map_err(database::Error::from)
                .map_err(TreeError::DbError)?;
        }
        write_txn
            .commit()
            .map_err(|e| TreeError::DbError(database::Error::from(Error::from(e))))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use mssmt::CompactMSSMT;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_basic_operations() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        let store = RedbStore::new(path).unwrap();

        // Create a leaf node
        let leaves = vec![
            Leaf::<32, Sha256>::new(
                vec![
                    3, 69, 105, 48, 149, 168, 143, 196, 124, 146, 130, 251, 153, 40, 220, 187, 204,
                    75, 204, 162, 5, 163, 152, 173, 169, 92, 13, 146, 235, 83, 77, 86, 96,
                ],
                4,
            ),
            Leaf::<32, Sha256>::new(
                vec![
                    3, 213, 82, 219, 95, 226, 45, 248, 61, 101, 8, 190, 100, 239, 21, 227, 210,
                    230, 170, 225, 173, 45, 49, 205, 48, 254, 189, 229, 81, 26, 113, 229, 214,
                ],
                32,
            ),
            Leaf::new(
                vec![
                    2, 254, 76, 244, 107, 252, 39, 30, 79, 130, 54, 211, 29, 168, 29, 151, 151,
                    220, 214, 125, 245, 11, 35, 207, 79, 109, 150, 171, 245, 244, 175, 230, 123,
                ],
                64,
            ),
            Leaf::new(
                vec![
                    2, 19, 101, 29, 109, 219, 178, 150, 220, 199, 173, 107, 186, 220, 9, 67, 227,
                    32, 65, 137, 116, 215, 2, 108, 110, 26, 217, 6, 96, 61, 95, 167, 6,
                ],
                32,
            ),
            Leaf::new(
                vec![
                    3, 226, 75, 169, 162, 33, 16, 218, 8, 198, 148, 198, 37, 140, 204, 230, 235,
                    80, 47, 182, 127, 134, 211, 136, 232, 134, 194, 65, 42, 88, 82, 82, 140,
                ],
                16,
            ),
            Leaf::new(
                vec![
                    3, 86, 40, 215, 234, 2, 221, 31, 160, 230, 65, 133, 61, 229, 151, 37, 134, 146,
                    42, 149, 252, 44, 227, 203, 55, 208, 19, 188, 113, 69, 53, 149, 63,
                ],
                2,
            ),
        ];
        let mut tree = CompactMSSMT::<32, Sha256, database::Error>::new(Box::new(store.clone()));
        let mut sum = 0;
        for leaf in leaves.clone() {
            sum += leaf.sum();
            tree.insert(leaf.hash(), leaf).unwrap();
        }
        assert_eq!(tree.root().unwrap().sum(), sum);
        assert_eq!(
            tree.root().unwrap().hash(),
            [
                44, 224, 253, 196, 179, 87, 196, 249, 225, 141, 243, 110, 68, 145, 166, 129, 2,
                132, 149, 250, 107, 131, 119, 148, 10, 55, 45, 126, 72, 35, 212, 3
            ]
        );
    }
}
