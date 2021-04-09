mod error;
mod generator;
mod link_scanner;
mod proof;

use cid::Code;

pub use self::error::*;
pub use self::generator::*;
pub use self::proof::*;

/// Hashing function assumption for more succinct proofs. If the proof needs to handle more hashing
/// functions, then it should be built on a feature, because it would require a Cid be included
/// with every proof node.
const DEFAULT_HASH_CODE: Code = Code::Blake2b256;
