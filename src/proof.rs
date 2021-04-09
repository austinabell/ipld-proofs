use crate::{link_scanner::LinkScanner, Error, DEFAULT_HASH_CODE};
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
        let mut prev_cid = cid::new_from_cbor(
            self.nodes
                .first()
                .expect("empty proof should be impossible to create"),
            DEFAULT_HASH_CODE,
        );

        for node in self.nodes.iter().skip(1) {
            // Check to make sure the link exists within the parent node.
            if !LinkScanner::from(node).any(|c| c == prev_cid) {
                return Err(Error::InvalidProof {
                    link: prev_cid,
                    data: node.clone(),
                }
                .into());
            }

            prev_cid = cid::new_from_cbor(&node, DEFAULT_HASH_CODE);
        }

        Ok(())
    }

    /// Returns [Cid] root of the proof.
    pub fn root(&self) -> Cid {
        let root_node = self
            .nodes
            .last()
            .expect("empty proof should be impossible to create");
        cid::new_from_cbor(root_node, DEFAULT_HASH_CODE)
    }

    /// Returns reference to nodes in the proof.
    pub fn nodes(&self) -> &[Vec<u8>] {
        &self.nodes
    }
}
