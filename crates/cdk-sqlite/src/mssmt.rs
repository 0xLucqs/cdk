//! SQLite storage backend for Merkle Sum Sparse Tree
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cdk_common::common::NamespaceableTreeStore;
use merkle_sum_sparse_tree::node::{Branch, CompactLeaf, ComputedNode, Leaf, Node};
use merkle_sum_sparse_tree::tree::{Db, EmptyTree};
use sha2::Sha256;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row as SqliteRow, SqlitePool};
use tokio::runtime::Handle;

use crate::mint::error::Error;

const TREE_SIZE: usize = 257;

/// SQLite storage backend for Merkle Sum Sparse Tree
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
    namespace: String,
    empty_tree: Arc<[Node<32, Sha256>; TREE_SIZE]>,
}

impl SqliteStore {
    /// Create a new SQLite store with the given pool and namespace
    pub async fn new(path: &Path) -> Result<Self, Error> {
        let path = path.to_str().ok_or(Error::InvalidDbPath)?;
        let db_options = SqliteConnectOptions::from_str(path)?
            .busy_timeout(Duration::from_secs(5))
            .read_only(false)
            .create_if_missing(true)
            .auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::Full);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(db_options)
            .await?;

        let empty_tree = EmptyTree::<32, Sha256>::empty_tree();
        let store = Self {
            pool,
            namespace: "default".to_string(),
            empty_tree,
        };
        store.migrate().await;
        Ok(store)
    }

    /// Run database migrations
    pub async fn migrate(&self) {
        sqlx::migrate!("./src/mint/migrations")
            .run(&self.pool)
            .await
            .expect("Failed to create tables");
    }

    fn get_leaf(&self, key: &[u8; 32]) -> Option<Leaf<32, Sha256>> {
        let row = tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query(
                    r#"
            SELECT hash_key, value, sum, l_hash_key, r_hash_key
            FROM mssmt_nodes
            WHERE hash_key = ? AND namespace = ?
            "#,
                )
                .bind::<&[u8]>(key.as_ref())
                .bind(&self.namespace)
                .fetch_optional(&self.pool),
            )
        })
        .ok()?;

        if let Some(row) = row {
            let value: Vec<u8> = row.get("value");
            let sum: i64 = row.get("sum");
            let l_hash: Vec<u8> = row.get("l_hash_key");
            let r_hash: Vec<u8> = row.get("r_hash_key");
            if l_hash.is_empty() && r_hash.is_empty() {
                Some(Leaf::new(value, sum as u64))
            } else {
                None
            }
        } else {
            None
        }
    }

    fn get_branch(&self, key: &[u8; 32]) -> Option<Branch<32, Sha256>> {
        let row = tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query(
                    r#"
            SELECT hash_key, l_hash_key, r_hash_key, sum
            FROM mssmt_nodes 
            WHERE hash_key = ? AND namespace = ?
            "#,
                )
                .bind::<&[u8]>(key.as_ref())
                .bind(&self.namespace)
                .fetch_optional(&self.pool),
            )
        })
        .ok()?;

        if let Some(row) = row {
            let l_hash: Vec<u8> = row.get("l_hash_key");
            let r_hash: Vec<u8> = row.get("r_hash_key");
            let sum: i64 = row.get("sum");

            let l_hash_array: [u8; 32] = l_hash.try_into().ok()?;
            let r_hash_array: [u8; 32] = r_hash.try_into().ok()?;

            // Create computed branch with just the hashes and sum
            Some(unsafe {
                Branch::new_with_hash(
                    Node::Branch(
                        self.get_branch(&l_hash_array)
                            .unwrap_or_else(Branch::empty_branch),
                    ),
                    Node::Branch(
                        self.get_branch(&r_hash_array)
                            .unwrap_or_else(Branch::empty_branch),
                    ),
                    *key,
                    sum as u64,
                )
            })
        } else {
            None
        }
    }
}

impl NamespaceableTreeStore for SqliteStore {
    fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.to_string();
    }
    fn get_leaf(&self, key: &[u8; 32]) -> Option<Leaf<32, Sha256>> {
        self.get_leaf(key)
    }
}

impl Db<32, Sha256> for SqliteStore {
    fn get_root_node(&self) -> Option<Branch<32, Sha256>> {
        let row = tokio::task::block_in_place(|| Handle::current().block_on(sqlx::query(
            r#"
            SELECT nodes.hash_key, nodes.l_hash_key, nodes.r_hash_key, nodes.key, nodes.value, nodes.sum, nodes.namespace
            FROM mssmt_nodes nodes
            JOIN mssmt_roots roots
                ON roots.root_hash = nodes.hash_key AND
                    roots.namespace = ?
            "#
        )
        .bind(&self.namespace)
        .fetch_optional(&self.pool)))
        .ok()?;

        if let Some(row) = row {
            let root_hash: Vec<u8> = row.get("hash_key");
            let root_hash_array: [u8; 32] = root_hash.try_into().ok()?;
            self.get_branch(&root_hash_array)
        } else {
            None
        }
    }

    fn get_children(&self, height: usize, key: [u8; 32]) -> (Node<32, Sha256>, Node<32, Sha256>) {
        let rows = tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query(
                    r#"
WITH RECURSIVE mssmt_branches_cte (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace, depth
) AS (
    SELECT 
        r.hash_key, r.l_hash_key, r.r_hash_key, r.key, r.value, r.sum, r.namespace, 0 as depth
    FROM mssmt_nodes r
    WHERE r.hash_key = ? AND r.namespace = ?
    
    UNION ALL
    
    SELECT 
        n.hash_key, n.l_hash_key, n.r_hash_key, n.key, n.value, n.sum, n.namespace, b.depth + 1
    FROM mssmt_nodes n
    INNER JOIN mssmt_branches_cte b 
        ON n.namespace = b.namespace
       AND (n.hash_key = b.l_hash_key OR n.hash_key = b.r_hash_key)
)
SELECT *
FROM mssmt_branches_cte
WHERE depth < 3;
            "#,
                )
                .bind::<&[u8]>(key.as_ref())
                .bind(&self.namespace)
                .fetch_all(&self.pool),
            )
        })
        .unwrap_or_default();

        let mut left = self.empty_tree[height + 1].clone();
        let mut right = self.empty_tree[height + 1].clone();

        if rows.is_empty() {
            return (left, right);
        }

        // Get the root node's child hashes
        let root_row = &rows[0];
        let left_hash: Vec<u8> = root_row.get("l_hash_key");
        let right_hash: Vec<u8> = root_row.get("r_hash_key");

        // Process child nodes
        for row in rows.iter().skip(1) {
            let hash_key: Vec<u8> = row.get("hash_key");
            let l_hash_key: Option<Vec<u8>> = row.get("l_hash_key");
            let r_hash_key: Option<Vec<u8>> = row.get("r_hash_key");
            let key_bytes: Option<Vec<u8>> = row.get("key");
            let value: Option<Vec<u8>> = row.get("value");
            let sum: i64 = row.get("sum");

            let is_left = hash_key == left_hash;
            let is_right = hash_key == right_hash;

            if !is_left && !is_right {
                continue;
            }

            let node = if l_hash_key.is_none() && r_hash_key.is_none() {
                // This is a leaf node
                let value = value.unwrap_or_default();
                let leaf = Leaf::new(value, sum as u64);

                if let Some(key_bytes) = key_bytes {
                    Node::Compact(unsafe {
                        CompactLeaf::new_with_hash(
                            hash_key.try_into().unwrap(),
                            leaf,
                            key_bytes.try_into().unwrap(),
                        )
                    })
                } else {
                    Node::Leaf(leaf)
                }
            } else {
                // This is a branch node
                Node::Computed(ComputedNode::new(hash_key.try_into().unwrap(), sum as u64))
            };

            if is_left {
                left = node;
            } else {
                right = node;
            }
        }
        (left, right)
    }

    fn insert_leaf(&mut self, leaf: Leaf<32, Sha256>) {
        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query(
                    r#"
            INSERT OR IGNORE INTO mssmt_nodes (
                hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
            ) VALUES (?, NULL, NULL, NULL, ?, ?, ?)
            "#,
                )
                .bind::<&[u8]>(leaf.hash().as_ref())
                .bind(leaf.value())
                .bind(leaf.sum() as i64)
                .bind(&self.namespace)
                .execute(&self.pool),
            )
        })
        .expect("Failed to insert leaf");
    }

    fn insert_branch(&mut self, branch: Branch<32, Sha256>) {
        let (left, right) = branch.children();

        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query(
                    r#"
            INSERT OR FAIL INTO mssmt_nodes (
                hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
            ) VALUES (?, ?, ?, NULL, NULL, ?, ?)
            "#,
                )
                .bind::<&[u8]>(branch.hash().as_ref())
                .bind::<&[u8]>(left.hash().as_ref())
                .bind::<&[u8]>(right.hash().as_ref())
                .bind(branch.sum() as i64)
                .bind(&self.namespace)
                .execute(&self.pool),
            )
        })
        .expect("Failed to insert branch");
    }

    fn insert_compact_leaf(&mut self, compact_leaf: CompactLeaf<32, Sha256>) {
        let leaf = compact_leaf.leaf();

        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query(
                    r#"
            INSERT OR FAIL INTO mssmt_nodes (
                hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
            ) VALUES (?, NULL, NULL, ?, ?, ?, ?)
            "#,
                )
                .bind::<&[u8]>(compact_leaf.hash().as_ref())
                .bind::<&[u8]>(compact_leaf.key().as_ref())
                .bind(leaf.value())
                .bind(leaf.sum() as i64)
                .bind(&self.namespace)
                .execute(&self.pool),
            )
        })
        .expect("Failed to insert compact leaf");
    }

    fn empty_tree(&self) -> Arc<[Node<32, Sha256>; TREE_SIZE]> {
        Arc::clone(&self.empty_tree)
    }

    fn update_root(&mut self, root: Branch<32, Sha256>) {
        // Skip empty root updates
        if root.hash() == self.empty_tree()[0].hash() {
            return;
        }

        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query(
                    r#"
            INSERT INTO mssmt_roots (
                root_hash, namespace
            ) VALUES (
                ?, ?
            ) ON CONFLICT (namespace)
                DO UPDATE SET root_hash = EXCLUDED.root_hash
            "#,
                )
                .bind::<&[u8]>(root.hash().as_ref())
                .bind(&self.namespace)
                .execute(&self.pool),
            )
        })
        .expect("Failed to update root");
    }

    fn delete_branch(&mut self, key: &[u8; 32]) {
        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query("DELETE FROM mssmt_nodes WHERE hash_key = ? AND namespace = ?")
                    .bind::<&[u8]>(key.as_ref())
                    .bind(&self.namespace)
                    .execute(&self.pool),
            )
        })
        .expect("Failed to delete branch");
    }

    fn delete_leaf(&mut self, key: &[u8; 32]) {
        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query("DELETE FROM mssmt_nodes WHERE hash_key = ? AND namespace = ?")
                    .bind::<&[u8]>(key.as_ref())
                    .bind(&self.namespace)
                    .execute(&self.pool),
            )
        })
        .expect("Failed to delete leaf");
    }

    fn delete_compact_leaf(&mut self, key: &[u8; 32]) {
        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                sqlx::query("DELETE FROM mssmt_nodes WHERE hash_key = ? AND namespace = ?")
                    .bind::<&[u8]>(key.as_ref())
                    .bind(&self.namespace)
                    .execute(&self.pool),
            )
        })
        .expect("Failed to delete compact leaf");
    }
}

#[cfg(test)]
mod tests {
    use merkle_sum_sparse_tree::compact_tree::CompactMSSMT;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_basic_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.db");
        let store = SqliteStore::new(&path).await.unwrap();

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
        let mut tree = CompactMSSMT::<32, Sha256>::new(Box::new(store.clone()));
        let mut sum = 0;
        for leaf in leaves.clone() {
            sum += leaf.sum();
            tree.insert(leaf.hash(), leaf);
        }
        assert_eq!(tree.root().sum(), sum);
        assert_eq!(
            tree.root().hash(),
            [
                44, 224, 253, 196, 179, 87, 196, 249, 225, 141, 243, 110, 68, 145, 166, 129, 2,
                132, 149, 250, 107, 131, 119, 148, 10, 55, 45, 126, 72, 35, 212, 3
            ]
        );
    }
}
