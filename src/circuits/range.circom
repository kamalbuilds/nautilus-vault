pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mimc.circom";

// Range proof circuit - proves a value is within a range without revealing the value
template RangeProof(n) {
    signal input value;           // Private: the secret value
    signal input minValue;        // Public: minimum allowed value
    signal input maxValue;        // Public: maximum allowed value
    signal input randomness;      // Private: randomness for commitment

    signal output commitment;     // Public: commitment to the value
    signal output proof;          // Public: proof that value is in range

    // Ensure value >= minValue
    component geq = GreaterEqThan(n);
    geq.in[0] <== value;
    geq.in[1] <== minValue;
    geq.out === 1;

    // Ensure value <= maxValue
    component leq = LessEqThan(n);
    leq.in[0] <== value;
    leq.in[1] <== maxValue;
    leq.out === 1;

    // Create commitment: commitment = hash(value || randomness)
    component commitmentHash = MiMC7(2);
    commitmentHash.x_in <== value;
    commitmentHash.k <== randomness;
    commitment <== commitmentHash.out;

    // Create proof hash
    component proofHash = MiMC7(3);
    proofHash.x_in <== value + minValue + maxValue;
    proofHash.k <== randomness;
    proof <== proofHash.out;
}

component main = RangeProof(64);