use thiserror::Error;
use cid::Cid;

#[derive(Error, Debug)]
pub enum Error {
    #[error(
        "Node attempted to prove was not visited by the proof generator. /
        Ensure that the proof generator was used to retrieve the data."
    )]
    NodeNotFound,
    #[error("Invalid proof, Cid {link:} not found in node: {data:?}")]
    InvalidProof {
        link: Cid,
        data: Vec<u8>,
    }
}
