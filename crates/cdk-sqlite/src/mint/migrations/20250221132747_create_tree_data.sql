-- Create tables for Merkle-Sum Sparse Merkle Tree (MS-SMT)

-- Table for storing MS-SMT nodes
CREATE TABLE IF NOT EXISTS mssmt_nodes (
    hash_key BLOB UNIQUE NOT NULL,       -- Node's unique identifier (32 bytes)
    l_hash_key BLOB,             -- Left child's hash (for branches)
    r_hash_key BLOB,             -- Right child's hash (for branches)
    key BLOB,                    -- Key for compacted leaves
    value BLOB,                  -- Value for leaves
    sum INTEGER NOT NULL,        -- Node's sum value
    namespace TEXT NOT NULL,     -- Tree namespace for partitioning
    PRIMARY KEY (hash_key, namespace)
);

-- Table for storing MS-SMT roots
CREATE TABLE IF NOT EXISTS mssmt_roots (
    namespace TEXT NOT NULL PRIMARY KEY,
    root_hash BLOB NOT NULL
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_mssmt_nodes_namespace ON mssmt_nodes(namespace);
CREATE INDEX IF NOT EXISTS idx_mssmt_nodes_children ON mssmt_nodes(l_hash_key, r_hash_key); 