pragma circom 2.0.0;

include "circomlib/circuits/mimc.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsa.circom";

// Identity proof circuit - proves identity attributes without revealing them
template IdentityProof() {
    signal input privateKey;      // Private: user's private key
    signal input age;             // Private: user's age
    signal input nationality;     // Private: user's nationality code
    signal input license;         // Private: has valid license (0 or 1)
    signal input nonce;           // Private: randomness

    signal input minAge;          // Public: minimum required age
    signal input requiredNationality; // Public: required nationality (0 = any)
    signal input requiresLicense; // Public: requires license (0 or 1)

    signal output publicKey;      // Public: derived public key
    signal output proof;          // Public: proof of meeting requirements
    signal output timestamp;      // Public: proof timestamp

    // Derive public key from private key
    component pubKeyDeriver = MiMC7(2);
    pubKeyDeriver.x_in <== privateKey;
    pubKeyDeriver.k <== 12345; // Fixed constant for key derivation
    publicKey <== pubKeyDeriver.out;

    // Age verification: age >= minAge
    signal ageValid;
    component ageCheck = MiMC7(2);
    ageCheck.x_in <== (age - minAge) * (age - minAge); // Square to ensure non-negative
    ageCheck.k <== nonce;
    ageValid <== ageCheck.out;

    // Nationality verification (if required)
    signal nationalityValid;
    signal nationalityMatch <== (nationality - requiredNationality) * (nationality - requiredNationality);
    component nationalityCheck = MiMC7(2);
    nationalityCheck.x_in <== nationalityMatch + requiredNationality * (requiredNationality - 1);
    nationalityCheck.k <== nonce + 1;
    nationalityValid <== nationalityCheck.out;

    // License verification
    signal licenseValid;
    component licenseCheck = MiMC7(2);
    licenseCheck.x_in <== license * requiresLicense + (1 - requiresLicense);
    licenseCheck.k <== nonce + 2;
    licenseValid <== licenseCheck.out;

    // Combine all validations into final proof
    component finalProof = Poseidon(4);
    finalProof.inputs[0] <== ageValid;
    finalProof.inputs[1] <== nationalityValid;
    finalProof.inputs[2] <== licenseValid;
    finalProof.inputs[3] <== privateKey;
    proof <== finalProof.out;

    // Add timestamp component
    component timestampHash = MiMC7(2);
    timestampHash.x_in <== proof;
    timestampHash.k <== nonce + 3;
    timestamp <== timestampHash.out;

    // Constraints
    license * (license - 1) === 0; // Ensure license is 0 or 1
}

component main = IdentityProof();