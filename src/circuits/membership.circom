pragma circom 2.0.0;

include "node_modules/circomlib/circuits/mimc.circom";
include "node_modules/circomlib/circuits/merkletree.circom";

// Membership proof circuit - proves membership in a set without revealing which member
template MembershipProof(levels) {
    signal input secret;          // Private: the secret value
    signal input pathElements[levels];  // Private: merkle proof path
    signal input pathIndices[levels];   // Private: merkle proof indices

    signal output merkleRoot;     // Public: the merkle root of the membership set
    signal output nullifierHash;  // Public: nullifier to prevent double-spending

    // Hash the secret to create leaf
    component hasher = MiMC7(2);
    hasher.x_in <== secret;
    hasher.k <== 0;

    // Verify merkle proof
    component merkleProof = MerkleTreeChecker(levels);
    merkleProof.leaf <== hasher.out;
    merkleProof.root <== merkleRoot;

    for (var i = 0; i < levels; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }

    // Create nullifier hash to prevent reuse
    component nullifier = MiMC7(2);
    nullifier.x_in <== secret;
    nullifier.k <== 1; // Different key for nullifier
    nullifierHash <== nullifier.out;

    // Constraint to ensure proof is valid
    merkleProof.root === merkleRoot;
}

component main = MembershipProof(20);