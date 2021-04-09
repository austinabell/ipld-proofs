use cid::{Cid, Code};
use forest_db::{Error, Store};
use ipld_blockstore::BlockStore;
use std::{collections::HashMap, error::Error as StdError};
use std::cell::RefCell;

/// Blockstore wrapper which tracks interactions with the underlying store to be used for
/// proof generation.
///
/// This structure is not threadsafe because 
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
}

impl<BS> BlockStore for ProofGenerator<'_, BS>
where
    BS: BlockStore,
{
    fn get_bytes(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Box<dyn StdError>> {
        let bytes = self.base.get_bytes(cid)?;
        if let Some(bytes) = &bytes {
            self.visited.borrow_mut().entry(*cid).or_insert(bytes.clone());
        }
        Ok(bytes)
    }

    fn put_raw(&self, bytes: Vec<u8>, code: Code) -> Result<Cid, Box<dyn StdError>> {
        let cid = cid::new_from_cbor(&bytes, code);
        self.visited.borrow_mut().entry(cid).or_insert(bytes.clone());
        self.write(cid.to_bytes(), bytes)?;
        Ok(cid)
    }
}

impl<BS> Store for ProofGenerator<'_, BS>
where
    BS: Store,
{
    fn read<K>(&self, key: K) -> Result<Option<Vec<u8>>, Error>
    where
        K: AsRef<[u8]>,
    {
        self.base.read(key)
    }
    fn write<K, V>(&self, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.base.write(key, value)
    }
    fn delete<K>(&self, key: K) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
    {
        self.base.delete(key)
    }
    fn exists<K>(&self, key: K) -> Result<bool, Error>
    where
        K: AsRef<[u8]>,
    {
        self.base.exists(key)
    }
    fn bulk_read<K>(&self, keys: &[K]) -> Result<Vec<Option<Vec<u8>>>, Error>
    where
        K: AsRef<[u8]>,
    {
        self.base.bulk_read(keys)
    }
    fn bulk_write<K, V>(&self, values: &[(K, V)]) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.base.bulk_write(values)
    }
    fn bulk_delete<K>(&self, keys: &[K]) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
    {
        self.base.bulk_delete(keys)
    }
}
