use crate::{Error, Proof, DEFAULT_HASH_CODE, link_scanner::LinkScanner};
use anyhow::Result;
use cid::{Cid, Code};
use forest_db::{Error as DbError, Store};
use ipld_blockstore::BlockStore;
use serde::Serialize;
use std::cell::RefCell;
use std::{collections::HashMap, error::Error as StdError};

/// Blockstore wrapper which tracks interactions with the underlying store to be used for
/// proof generation.
pub struct ProofGenerator<'s, BS> {
    base: &'s BS,
    visited: RefCell<HashMap<Cid, Vec<u8>>>,
}

impl<'bs, BS> ProofGenerator<'bs, BS>
where
    BS: BlockStore,
{
    pub fn new(base: &'bs BS) -> Self {
        Self {
            base,
            visited: Default::default(),
        }
    }

    /// Generates a proof with the raw serialized bytes of the element being proven. This
    /// will use as many nodes as it can connect since the tracking started.
    pub fn generate_proof<I: Serialize>(&self, proof_item: &I) -> Result<Proof> {
        self.generate_proof_raw(serde_cbor::to_vec(proof_item)?, None)
    }

    /// Generates a proof with the raw serialized bytes of the element being proven up to the
    /// root provided. If the item being proved does not link to the root, an error will be
    /// returned.
    pub fn generate_proof_to_cid<I: Serialize>(&self, proof_item: &I, root: Cid) -> Result<Proof> {
        self.generate_proof_raw(serde_cbor::to_vec(proof_item)?, Some(root))
    }

    /// Generates a proof with the raw serialized bytes of the element being proven.
    /// This function takes the raw serialized bytes that is being proved, as well as the
    /// optional root to generate a proof to.
    ///
    /// This does not currently generate a canonical or shortest proof, this will just find
    /// the first connection.
    pub fn generate_proof_raw(&self, bytes: Vec<u8>, root: Option<Cid>) -> Result<Proof> {
        let mut current_cid = cid::new_from_cbor(&bytes, DEFAULT_HASH_CODE);
        if !self.visited.borrow().contains_key(&current_cid) {
            return Err(Error::NodeNotFound.into());
        }

        let visited = self.visited.borrow();
        let total_nodes = visited.len();
        let mut unvisited_nodes = visited.iter();

        let mut proof_nodes = Vec::with_capacity(total_nodes);
        proof_nodes.push(bytes);

        // Keeps track of all nodes which link to the key node.
        // All Nodes in the `Vec` link to the hashmap key `Cid`.
        //* This can be modified to keep track of all links and compute shortest canonical path.
        let mut scan_cache = HashMap::<Cid, (Cid, Vec<u8>)>::with_capacity(total_nodes);

        'proof: loop {
            if let Some(r) = root {
                if r == current_cid {
                    break;
                }
            }

            if let Some((c_cid, c_bytes)) = scan_cache.remove(&current_cid) {
                // Link has been scanned already, push the cached node and update the current cid.
                proof_nodes.push(c_bytes);
                current_cid = c_cid;
                continue 'proof;
            }

            // Scan for links until one is found to be connected.
            for (u_cid, u_bytes) in &mut unvisited_nodes {
                // Create iterator which scans over links lazily.
                let scanner = LinkScanner::from(u_bytes.as_ref());

                // Iterate through links: use node if it links to current node add to cache if not.
                let mut link_buffer = Vec::with_capacity(8);
                for link in scanner {
                    if link == current_cid {
                        // The current node's link was found in another node, include to proof
                        // chain and discard other links found. The other links can be discarded
                        // because the Ipld graph is acyclic.
                        proof_nodes.push(u_bytes.clone());
                        current_cid = *u_cid;
                        continue 'proof;
                    }

                    // Push link found to buffer, will be added to cache if not found in node.
                    link_buffer.push(link);
                }

                for link in link_buffer {
                    //* This can be modified to keep the smaller node, but this doesn't matter
                    scan_cache.entry(link).or_insert((*u_cid, u_bytes.clone()));
                }
            }

            break;
        }

        Ok(Proof { nodes: proof_nodes })
    }
}

impl<BS> BlockStore for ProofGenerator<'_, BS>
where
    BS: BlockStore,
{
    fn get_bytes(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Box<dyn StdError>> {
        let bytes = self.base.get_bytes(cid)?;
        if let Some(bytes) = &bytes {
            self.visited
                .borrow_mut()
                .entry(*cid)
                .or_insert(bytes.clone());
        }
        Ok(bytes)
    }

    fn put_raw(&self, bytes: Vec<u8>, code: Code) -> Result<Cid, Box<dyn StdError>> {
        let cid = cid::new_from_cbor(&bytes, code);
        self.visited
            .borrow_mut()
            .entry(cid)
            .or_insert(bytes.clone());
        self.write(cid.to_bytes(), bytes)?;
        Ok(cid)
    }
}

impl<BS> Store for ProofGenerator<'_, BS>
where
    BS: Store,
{
    fn read<K>(&self, key: K) -> Result<Option<Vec<u8>>, DbError>
    where
        K: AsRef<[u8]>,
    {
        self.base.read(key)
    }
    fn write<K, V>(&self, key: K, value: V) -> Result<(), DbError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.base.write(key, value)
    }
    fn delete<K>(&self, key: K) -> Result<(), DbError>
    where
        K: AsRef<[u8]>,
    {
        self.base.delete(key)
    }
    fn exists<K>(&self, key: K) -> Result<bool, DbError>
    where
        K: AsRef<[u8]>,
    {
        self.base.exists(key)
    }
    fn bulk_read<K>(&self, keys: &[K]) -> Result<Vec<Option<Vec<u8>>>, DbError>
    where
        K: AsRef<[u8]>,
    {
        self.base.bulk_read(keys)
    }
    fn bulk_write<K, V>(&self, values: &[(K, V)]) -> Result<(), DbError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.base.bulk_write(values)
    }
    fn bulk_delete<K>(&self, keys: &[K]) -> Result<(), DbError>
    where
        K: AsRef<[u8]>,
    {
        self.base.bulk_delete(keys)
    }
}
