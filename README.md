# ipld-proofs

[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/austinabell/ipld-proofs/ci.yml?branch=main&style=for-the-badge" height="20">](https://github.com/austinabell/ipld-proofs/actions?query=branch%3Amain)

This library will generate and validate proofs for the existence of data in an [Ipld](https://docs.ipld.io/) dag. These proofs are not true Merkle proofs, as compared with Ethereum because the Ipld dag is not a binary tree. Because of this, all nodes on the path to the data are included in the proof, which includes the data itself.

There are many different paths to generating proofs, each with tradeoffs. Here are the options, with the boxes ticked for the functionality that exists in this library currently.
- [x] Generate first proof path discovered
    - ✓ Computationally less expensive because it doesn't need to parse all blocks traversed
    - ✕ Potentially less succinct proof when multiple paths of links connect with the node (unlikely)
    - ✕ Not canonical, generating the same proof on different hardware could lead to different results
- [ ] Generate shortest path to node
    - ✓ Almost always the least amount of data for the proof and least amount of nodes in proof
    - ✕ Computationally more expensive to calculate the shortest path
    - ✕ Has to parse all nodes before traversing, cannot be done lazily
- [ ] Generate proof with the least amount of data
    - ✓ Guaranteed to be smallest data footprint
    - ✕ Can be more expensive if the roots of each proof nodes need to be recomputed/stored
- [ ] Generate proof storing all nodes used when generating proof
    - ✓ Allows proof to be used with expected data structures so certain things can be verified without requiring additional context
    - ✕ Larger proof because unnecessary nodes will be included
- [ ] Attaching Cid links to each node in proof
    - ✓ Removes need to re-hash to generate Cids
    - ✓ Allows for multiple hash functions being used in the proof section
    - ✕ Much larger proof because it would include a Cid (hash) for every single node in the proof

The design is chosen primarily with Filecoin in mind, as it would be the primary beneficiary of having Ipld proofs. The benefit is being able to prove that data exists in state at a given state root, block, tipset, or even previous chain history. This can be very useful to be able to verify a specific section of the state without the overhead of having to run a full validator node.

A workflow for generating a proof for a dag that visually looks like this:

```
           r
          /|\
         a b c
          / \
prove -> d   e
```

Is shown below, where only the nodes on the path to the `d` node are included in the proof.

```rust
use cid::{Cid, Code};
use ipld_blockstore::BlockStore;
use ipld_proofs::ProofGenerator;
use forest_ipld::ipld;

let bs = forest_db::MemoryDB::default();

let e = bs.put(&8u8, Code::Blake2b256).unwrap();
let d = bs.put(&"Some data", Code::Blake2b256).unwrap();
let c = bs.put(&"Some other value", Code::Blake2b256).unwrap();
let b = bs.put(&(d, e), Code::Blake2b256).unwrap();
let a = bs.put(&ipld!([2u8, "3", 4u64]), Code::Blake2b256).unwrap();
let root = bs.put(&ipld!([a, b, c]), Code::Blake2b256).unwrap();

// Start using the proof generator here
let p_gen = ProofGenerator::new(&bs);

// Retrieve data from a store
let [_, b, _]: [Cid; 3] = p_gen.get(&root).unwrap().unwrap();
let (d, _): (Cid, Cid) = p_gen.get(&b).unwrap().unwrap();
let data: String = p_gen.get(&d).unwrap().unwrap();
    
// Generate a proof of the data
let proof = p_gen.generate_proof(&data).unwrap();
assert_eq!(proof.nodes().len(), 3);
assert_eq!(proof.root(), root);
proof.validate().unwrap();

// Or generate only to a specific node
let proof = p_gen.generate_proof_to_cid(&"Some data", &b).unwrap();
assert_eq!(proof.nodes().len(), 2);
assert_eq!(proof.root(), b);
proof.validate().unwrap();
```
