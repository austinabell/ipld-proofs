# ipld-proof-gen

This library will generate and validate proofs for the existance of data in an [Ipld](https://docs.ipld.io/) dag.

There are many different paths to generating proofs, each with tradeoffs. Here are the options, with the boxes ticked for the functionality that exists in this library currently.
- [x] Generate first proof path discovered
    - ✓ Computationally less expensive because it doesn't need to parse all blocks traversed.
    - ✕ Potentially less succinct proof when multiple paths of links connect with the node (unlikely).
    - ✕ Not canonical, generating the same proof on different hardware could lead to different results.
- [ ] Generate shortest path to node
    - ✓ Canonical and almost always the least amount of data for the proof
    - ✕ Computationally more expensive to calculate shortest path
- [ ] Generate proof with least amount of data
    - ✓ Canonical and guaranteed to be smallest data footprint
    - ✕ Can be more expensive if roots of each proof nodes need to be recomputed/stored.
- [ ] Generate proof storing all nodes used when generating proof
    - ✓ Allows proof to be used with expected data structures so certain things can be verified without requiring additional context
    - ✕ Larger proof because unnecessary nodes will be included
- [ ] Attaching Cid links to each node in proof
    - ✓ Removes need to re-hash to generate Cids
    - ✓ Allows for multiple hash functions being used in the proof section
    - ✕ Much larger proof because it would include a Cid (hash) for every single node in the proof

The design is chosen primarily with Filecoin in mind, as it would be the primary beneficiary of having Ipld proofs. The benefit is being able to prove that data exists in state at a given state root, block, tipset, or even previous chain history. This can be very useful to be able to verify a specific section of the state without the overhead of having to run a full validator node.
