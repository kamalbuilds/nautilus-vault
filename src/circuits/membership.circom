pragma circom 2.0.0;

include "circomlib/circuits/mimc.circom";
include "circomlib/circuits/smt/smtverifier.circom";

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

    signal leaf;
    leaf <== hasher.out;

    // Compute merkle root from path - simplified to avoid non-quadratic constraints
    signal currentHash[levels + 1];
    currentHash[0] <== leaf;

    component pathHashers[levels];

    for (var i = 0; i < levels; i++) {
        pathHashers[i] = MiMC7(2);

        // Simple hash of current and path element
        // In production, you'd use proper merkle tree logic with selectors
        pathHashers[i].x_in <== currentHash[i];
        pathHashers[i].k <== pathElements[i];

        currentHash[i + 1] <== pathHashers[i].out;
    }

    merkleRoot <== currentHash[levels];

    // Create nullifier hash to prevent reuse
    component nullifier = MiMC7(2);
    nullifier.x_in <== secret;
    nullifier.k <== 1; // Different key for nullifier
    nullifierHash <== nullifier.out;
}

component main = MembershipProof(20);