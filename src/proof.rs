use crate::DEFAULT_HASH_CODE;
use anyhow::Result;
use cid::Cid;

/// Describes an Ipld proof.
/// Contains only nodes connected to the root. These nodes are ordered from the root to the base.
pub struct Proof {
    pub(crate) nodes: Vec<Vec<u8>>,
}

impl Proof {
    /// Validates that the proof nodes are all directly connected to each other.
    pub fn validate(&self) -> Result<()> {
        // TODO
        Ok(())
    }

    /// Returns [Cid] root of the proof.
    pub fn root(&self) -> Cid {
        let root_node = self.nodes.last().expect("empty proof should be impossible to create");
        cid::new_from_cbor(root_node, DEFAULT_HASH_CODE)
    }

    /// Returns reference to nodes in the proof.
    pub fn nodes(&self) -> &[Vec<u8>] {
        &self.nodes
    }
}
