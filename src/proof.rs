use crate::{link_scanner::LinkScanner, Error, DEFAULT_HASH_CODE};
use anyhow::Result;
use cid::Cid;
use forest_encoding::ser::SerializeSeq;
use forest_encoding::serde_bytes;
use serde::{
    de::{Deserializer, SeqAccess, Visitor},
    ser::Serializer,
    Deserialize, Serialize,
};
use std::fmt;

/// Describes an Ipld proof.
/// Contains only nodes connected to the root. These nodes are ordered from the root to the base.
///
/// Proofs can only be generated through the [ProofGenerator](crate::ProofGenerator) struct.
#[derive(Debug, PartialEq)]
pub struct Proof {
    pub(crate) nodes: Vec<Vec<u8>>,
}

impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.nodes.len()))?;
        for e in &self.nodes {
            seq.serialize_element(&serde_bytes::Bytes::new(&e))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProofVisitor;

        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = Vec<Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a vector of bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<Vec<u8>>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = if let Some(hint) = seq.size_hint() {
                    Vec::with_capacity(hint)
                } else {
                    Vec::new()
                };

                while let Some(elem) = seq.next_element::<serde_bytes::ByteBuf>()? {
                    vec.push(elem.into_vec());
                }
                Ok(vec)
            }
        }
        Ok(Proof {
            nodes: deserializer.deserialize_seq(ProofVisitor)?,
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_symmetric() {
        let proof = Proof {
            nodes: vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()],
        };
        let serialized_bytes = serde_cbor::to_vec(&proof).unwrap();
        assert_eq!(
            serde_cbor::from_slice::<Proof>(&serialized_bytes).unwrap(),
            proof
        );
    }
}
