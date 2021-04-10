use crate::{link_scanner::LinkScanner, Error, Proof, DEFAULT_HASH_CODE};
use anyhow::Result;
use cid::{Cid, Code};
use forest_db::{Error as DbError, Store};
use ipld_blockstore::BlockStore;
use serde::Serialize;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::{collections::HashMap, error::Error as StdError};

/// Blockstore wrapper which tracks interactions with the underlying store to be used for
/// proof generation.
///
/// This structure can be used in place of a blockstore, but the computation will be the quickest
/// if it's only used to load/store values used in the proof.
///
/// # Example
/// The Ipld dag for the following example looks something like:
///      r
///     /|\
///    a b c
///     / \
///    d   e
///
///
/// ```
/// use cid::{Cid, Code};
/// use ipld_blockstore::BlockStore;
/// use ipld_proofs::ProofGenerator;
/// use forest_ipld::ipld;
///
/// let bs = forest_db::MemoryDB::default();
///
/// let e = bs.put(&8u8, Code::Blake2b256).unwrap();
/// let d = bs.put(&"Some data", Code::Blake2b256).unwrap();
/// let c = bs.put(&"Some other value", Code::Blake2b256).unwrap();
/// let b = bs.put(&(d, e), Code::Blake2b256).unwrap();
/// let a = bs.put(&ipld!([2u8, "3", 4u64]), Code::Blake2b256).unwrap();
/// let root = bs.put(&ipld!([a, b, c]), Code::Blake2b256).unwrap();
///
/// // Start using the proof generator here
/// let p_gen = ProofGenerator::new(&bs);
///
/// // Retrieve data from a store
/// let [_, b, _]: [Cid; 3] = p_gen.get(&root).unwrap().unwrap();
/// let (d, _): (Cid, Cid) = p_gen.get(&b).unwrap().unwrap();
/// let data: String = p_gen.get(&d).unwrap().unwrap();
///     
/// // Generate a proof of the data
/// let proof = p_gen.generate_proof(&data).unwrap();
/// assert_eq!(proof.nodes().len(), 3);
/// assert_eq!(proof.root(), root);
/// proof.validate().unwrap();

/// // Or generate only to a specific node
/// let proof = p_gen.generate_proof_to_cid(&"Some data", &b).unwrap();
/// assert_eq!(proof.nodes().len(), 2);
/// assert_eq!(proof.root(), b);
/// proof.validate().unwrap();
/// ```
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
    pub fn generate_proof_to_cid<I: Serialize>(&self, proof_item: &I, root: &Cid) -> Result<Proof> {
        self.generate_proof_raw(serde_cbor::to_vec(proof_item)?, Some(root))
    }

    /// Generates a proof with the raw serialized bytes of the element being proven.
    /// This function takes the raw serialized bytes that is being proved, as well as the
    /// optional root to generate a proof to.
    ///
    /// This does not currently generate a canonical or shortest proof, this will just find
    /// the first connection.
    pub fn generate_proof_raw(&self, bytes: Vec<u8>, root: Option<&Cid>) -> Result<Proof> {
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
                if r == &current_cid {
                    break 'proof;
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
                let scanner = LinkScanner::from(u_bytes);

                // Iterate through links: use node if it links to current node add to cache if not.
                let mut link_buffer = SmallVec::<[Cid; 8]>::new();
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
                    scan_cache
                        .entry(link)
                        .or_insert_with(|| (*u_cid, u_bytes.clone()));
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

        // Intentionally not using cache to avoid consensus inconsistencies with base.
        if let Some(bytes) = &bytes {
            self.visited
                .borrow_mut()
                .entry(*cid)
                .or_insert_with(|| bytes.clone());
        }
        Ok(bytes)
    }

    fn put_raw(&self, bytes: Vec<u8>, code: Code) -> Result<Cid, Box<dyn StdError>> {
        let cid = cid::new_from_cbor(&bytes, code);
        self.visited
            .borrow_mut()
            .entry(cid)
            .or_insert_with(|| bytes.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use forest_ipld::ipld;

    #[test]
    fn puts_tracked() {
        let bs = forest_db::MemoryDB::default();
        let p_gen = ProofGenerator::new(&bs);

        let cid = p_gen.put(&8, DEFAULT_HASH_CODE).unwrap();
        assert_eq!(p_gen.get::<u8>(&cid).unwrap(), Some(8));
        assert_eq!(p_gen.visited.borrow().len(), 1);

        let proof = p_gen.generate_proof(&8).unwrap();
        proof.validate().unwrap();
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn dag_tracking_generation() {
        //      r        u
        //     /|\
        //    a b c
        //       / \
        //      d   e
        //      |
        //      f <-
        //      |
        //      g

        let bs = forest_db::MemoryDB::default();

        // Scope variables to make sure others are dropped
        let r = {
            let g = bs.put(&"value", DEFAULT_HASH_CODE).unwrap();
            let f = bs.put(&ipld!([g, 3u8]), DEFAULT_HASH_CODE).unwrap();
            let d = bs.put(&ipld!([5u8, f]), DEFAULT_HASH_CODE).unwrap();
            let e = bs.put(&8u8, DEFAULT_HASH_CODE).unwrap();
            let c = bs
                .put(&ipld!({ "d": d, "e": e }), DEFAULT_HASH_CODE)
                .unwrap();
            let b = bs.put(&"Some other value", DEFAULT_HASH_CODE).unwrap();
            let a = bs.put(&ipld!([2u8, "3", 4u64]), DEFAULT_HASH_CODE).unwrap();
            bs.put(&ipld!([a, b, c]), DEFAULT_HASH_CODE).unwrap()
        };

        let u = bs.put(&"unrelated node", DEFAULT_HASH_CODE).unwrap();

        // Start using the proof generator here
        let p_gen = ProofGenerator::new(&bs);

        // Load unrelated node to make sure it doesn't affect proof
        assert_eq!(
            p_gen.get::<String>(&u).unwrap().unwrap(),
            "unrelated node".to_string()
        );

        let [_, _, c]: [Cid; 3] = p_gen.get(&r).unwrap().unwrap();

        #[derive(Debug, serde::Deserialize)]
        struct TmpC {
            d: Cid,
            e: Cid,
        }
        let TmpC { d, .. } = p_gen.get(&c).unwrap().unwrap();
        let (_, d): (u8, Cid) = p_gen.get(&d).unwrap().unwrap();
        let prove_node: (Cid, u8) = p_gen.get(&d).unwrap().unwrap();
        assert_eq!(
            p_gen.get::<String>(&prove_node.0).unwrap().unwrap(),
            "value".to_string()
        );

        // Generate proof all the way to the root node
        let proof = p_gen.generate_proof(&prove_node).unwrap();
        assert_eq!(proof.nodes().len(), 4);
        assert_eq!(proof.root(), r);
        proof.validate().unwrap();

        // Generate proof only to the `c` node
        let proof = p_gen.generate_proof_to_cid(&prove_node, &c).unwrap();
        assert_eq!(proof.nodes().len(), 3);
        assert_eq!(proof.root(), c);
        proof.validate().unwrap();
    }
}
