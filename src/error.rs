use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(
        "Node attempted to prove was not visited by the proof generator. /
        Ensure that the proof generator was used to retrieve the data."
    )]
    NodeNotFound,
}
