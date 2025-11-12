#!/usr/bin/env node

/**
 * Circuit compilation and key generation script
 * Compiles Circom circuits and generates proving/verification keys
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const snarkjs = require('snarkjs');

const CIRCUITS_DIR = path.join(__dirname);
const COMPILED_DIR = path.join(__dirname, '../../circuits/compiled');
const KEYS_DIR = path.join(__dirname, '../../circuits/keys');

// Ensure directories exist
if (!fs.existsSync(COMPILED_DIR)) {
  fs.mkdirSync(COMPILED_DIR, { recursive: true });
}
if (!fs.existsSync(KEYS_DIR)) {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
}

const circuits = [
  { name: 'membership', file: 'membership.circom' },
  { name: 'range', file: 'range.circom' },
  { name: 'identity', file: 'identity.circom' }
];

async function compileCircuit(circuitName, circuitFile) {
  console.log(`\n🔨 Compiling circuit: ${circuitName}`);

  const circuitPath = path.join(CIRCUITS_DIR, circuitFile);
  const outputDir = path.join(COMPILED_DIR, circuitName);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  try {
    // Compile circuit to R1CS and WASM
    console.log(`  📝 Compiling ${circuitFile} to R1CS and WASM...`);
    execSync(`circom ${circuitPath} --r1cs --wasm --sym -o ${outputDir}`, {
      stdio: 'inherit',
      cwd: CIRCUITS_DIR
    });

    console.log(`  ✅ Circuit ${circuitName} compiled successfully`);
    return true;
  } catch (error) {
    console.error(`  ❌ Failed to compile circuit ${circuitName}:`, error.message);
    return false;
  }
}

async function generateKeys(circuitName) {
  console.log(`\n🔑 Generating keys for circuit: ${circuitName}`);

  const r1csPath = path.join(COMPILED_DIR, circuitName, `${circuitName}.r1cs`);
  const ptauPath = path.join(KEYS_DIR, 'powersOfTau28_hez_final_15.ptau');
  const zkeyPath = path.join(KEYS_DIR, `${circuitName}.zkey`);
  const vkeyPath = path.join(KEYS_DIR, `${circuitName}_verification_key.json`);

  try {
    // Download powers of tau file if it doesn't exist
    if (!fs.existsSync(ptauPath)) {
      console.log('  📥 Downloading powers of tau ceremony file...');
      execSync(`wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau -O ${ptauPath}`, {
        stdio: 'inherit'
      });
    }

    // Generate proving key
    console.log(`  🔐 Generating proving key...`);
    await snarkjs.zKey.newZKey(r1csPath, ptauPath, zkeyPath);

    // Export verification key
    console.log(`  🔓 Exporting verification key...`);
    const vKey = await snarkjs.zKey.exportVerificationKey(zkeyPath);
    fs.writeFileSync(vkeyPath, JSON.stringify(vKey, null, 2));

    console.log(`  ✅ Keys generated successfully for ${circuitName}`);
    return true;
  } catch (error) {
    console.error(`  ❌ Failed to generate keys for ${circuitName}:`, error.message);
    return false;
  }
}

async function validateSetup(circuitName) {
  console.log(`\n🔍 Validating setup for circuit: ${circuitName}`);

  const wasmPath = path.join(COMPILED_DIR, circuitName, `${circuitName}.wasm`);
  const zkeyPath = path.join(KEYS_DIR, `${circuitName}.zkey`);
  const vkeyPath = path.join(KEYS_DIR, `${circuitName}_verification_key.json`);

  try {
    // Check if all files exist
    if (!fs.existsSync(wasmPath)) throw new Error(`WASM file not found: ${wasmPath}`);
    if (!fs.existsSync(zkeyPath)) throw new Error(`ZKey file not found: ${zkeyPath}`);
    if (!fs.existsSync(vkeyPath)) throw new Error(`Verification key not found: ${vkeyPath}`);

    // Load verification key to validate format
    const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
    if (!vKey.protocol || vKey.protocol !== 'groth16') {
      throw new Error('Invalid verification key format');
    }

    console.log(`  ✅ Setup validation passed for ${circuitName}`);
    return true;
  } catch (error) {
    console.error(`  ❌ Setup validation failed for ${circuitName}:`, error.message);
    return false;
  }
}

async function createTestProof(circuitName) {
  console.log(`\n🧪 Creating test proof for circuit: ${circuitName}`);

  const wasmPath = path.join(COMPILED_DIR, circuitName, `${circuitName}.wasm`);
  const zkeyPath = path.join(KEYS_DIR, `${circuitName}.zkey`);

  try {
    let input;

    // Create test inputs based on circuit type
    switch (circuitName) {
      case 'membership':
        input = {
          secret: "12345",
          pathElements: Array(20).fill("0"),
          pathIndices: Array(20).fill(0)
        };
        break;
      case 'range':
        input = {
          value: 25,
          minValue: 18,
          maxValue: 65,
          randomness: "123456789"
        };
        break;
      case 'identity':
        input = {
          privateKey: "987654321",
          age: 30,
          nationality: 1,
          license: 1,
          nonce: "555555",
          minAge: 18,
          requiredNationality: 1,
          requiresLicense: 1
        };
        break;
      default:
        throw new Error(`Unknown circuit: ${circuitName}`);
    }

    // Generate proof
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath
    );

    // Verify proof
    const vKey = JSON.parse(fs.readFileSync(
      path.join(KEYS_DIR, `${circuitName}_verification_key.json`)
    ));

    const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    if (isValid) {
      console.log(`  ✅ Test proof generated and verified successfully for ${circuitName}`);

      // Save test proof for reference
      const testProofPath = path.join(KEYS_DIR, `${circuitName}_test_proof.json`);
      fs.writeFileSync(testProofPath, JSON.stringify({
        proof,
        publicSignals,
        input
      }, null, 2));

      return true;
    } else {
      throw new Error('Test proof verification failed');
    }
  } catch (error) {
    console.error(`  ❌ Test proof failed for ${circuitName}:`, error.message);
    return false;
  }
}

async function main() {
  console.log('🚀 Starting circuit compilation and key generation...\n');

  let allSuccess = true;

  for (const circuit of circuits) {
    console.log(`\n${'='.repeat(50)}`);
    console.log(`Processing circuit: ${circuit.name}`);
    console.log(`${'='.repeat(50)}`);

    // Compile circuit
    const compiled = await compileCircuit(circuit.name, circuit.file);
    if (!compiled) {
      allSuccess = false;
      continue;
    }

    // Generate keys
    const keysGenerated = await generateKeys(circuit.name);
    if (!keysGenerated) {
      allSuccess = false;
      continue;
    }

    // Validate setup
    const setupValid = await validateSetup(circuit.name);
    if (!setupValid) {
      allSuccess = false;
      continue;
    }

    // Create test proof
    const testPassed = await createTestProof(circuit.name);
    if (!testPassed) {
      allSuccess = false;
      continue;
    }
  }

  console.log(`\n${'='.repeat(50)}`);
  if (allSuccess) {
    console.log('🎉 All circuits compiled and tested successfully!');
    console.log('\n📁 Generated files:');
    console.log(`  - Compiled circuits: ${COMPILED_DIR}`);
    console.log(`  - Keys and proofs: ${KEYS_DIR}`);
  } else {
    console.log('❌ Some circuits failed to compile or test');
    process.exit(1);
  }
  console.log(`${'='.repeat(50)}`);
}

if (require.main === module) {
  main().catch(error => {
    console.error('💥 Build script failed:', error);
    process.exit(1);
  });
}

module.exports = {
  compileCircuit,
  generateKeys,
  validateSetup,
  createTestProof
};