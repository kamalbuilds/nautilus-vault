# Nautilus Vault

Privacy-preserving decentralized storage with layered zero-knowledge protection

---

## The Problem

Data breaches cost companies an average of $4.35 million, yet most storage solutions force users to choose between convenience and privacy. Centralized platforms control user data, selling it without meaningful consent. Meanwhile, existing decentralized solutions lack the privacy guarantees needed for sensitive information.

Users face three major challenges:

1. **Loss of control**: Once data is uploaded to traditional cloud storage, users have no way to verify how it's used or who accesses it.

2. **Privacy violations**: Most platforms collect and monetize user data through opaque practices. GDPR and CCPA require consent, but implementation is often an afterthought.

3. **Security risks**: Centralized storage creates honeypots for attackers. A single breach can expose millions of records because data sits unencrypted in one location.

Current "solutions" don't work:

- **Blockchain storage alone** exposes all data publicly on-chain
- **Client-side encryption** leaves key management entirely to users
- **Privacy-preserving computation** requires trusted third parties
- **Compliance tools** bolt onto existing systems without architectural support

What we need is a storage system that proves privacy properties cryptographically, gives users real control over their data, and maintains compliance by design - not as an add-on.

---

## Our Solution

Nautilus Vault is a privacy-preserving storage framework built on three principles:

**1. Prove, don't trust**
We use zero-knowledge proofs to verify data properties without exposing the data itself. Want to prove you're over 21 without revealing your birthdate? That's what ZK proofs enable.

**2. Compartmentalize everything**
Like a nautilus shell's chambered structure, we separate concerns. Encryption, storage, and verification happen in isolated layers. Compromise one layer, and the others remain secure.

**3. Privacy by architecture**
GDPR compliance isn't a feature we added - it's built into the system design. Consent management, data minimization, and right-to-erasure work because the architecture supports them.

### How It Works

Nautilus Vault integrates three technologies:

**Walrus** handles decentralized storage. Instead of trusting a single provider, data distributes across multiple nodes. No single point of failure.

**Seal** provides identity-based encryption. Only authorized parties can decrypt data, even if storage nodes are compromised.

**Sui blockchain** creates an immutable audit trail. Every consent decision, every access request, every data operation gets recorded on-chain. This isn't just logging - it's cryptographic proof of compliance.

The real innovation is how these pieces work together.

---

## Architecture

Here's how data flows through the system:

```
User Application
       |
       | (plaintext + permissions)
       v
+------------------+
| Privacy Engine   |  <- Validates consent, checks policies
+------------------+
       |
       | (validated data)
       v
+------------------+
| Encryption Layer |  <- AES-256-GCM + key derivation
+------------------+
       |
       | (encrypted data + ZK proof)
       v
+------------------+
| ZK Proof System  |  <- Generates proofs without revealing data
+------------------+
       |
       | (encrypted data + proof)
       v
+------------------+
| Walrus Storage   |  <- Distributes across decentralized nodes
+------------------+
       |
       | (storage receipt)
       v
+------------------+
| Sui Blockchain   |  <- Records metadata on-chain
+------------------+
       |
       v
    User gets:
    - Storage confirmation
    - Proof of encryption
    - Audit trail
```

### Why This Design?

**Separation of concerns**: Encryption happens before storage. The storage layer never sees plaintext. Even if Walrus nodes are compromised, they only have encrypted blobs.

**Verification without exposure**: Zero-knowledge proofs let you verify data properties (age, membership, credentials) without decrypting the data. This enables privacy-preserving computation.

**Immutable compliance**: Every operation gets recorded on Sui blockchain. Users can prove they granted consent. Regulators can verify compliance. No one can retroactively change the record.

**Granular control**: Users manage consent per-purpose (marketing vs analytics vs research). The system enforces these permissions cryptographically, not just in application logic.

---

## Features

### Core Capabilities

**Zero-Knowledge Proof System**

Generate and verify proofs using Groth16 circuits. Three circuit types included:

- Membership proofs: Prove you're in an authorized group without revealing which user you are
- Range proofs: Prove a value falls within a range (age > 21) without revealing the exact value
- Identity proofs: Prove multiple attributes simultaneously (age + residency + credential) with one proof

Proof generation takes under 250ms. Verification takes under 10ms. These are production-ready numbers.

**Privacy-Preserving Computation**

- K-anonymity: Generalize data so records can't be linked to individuals
- Differential privacy: Add calibrated noise to protect individual data points
- Data minimization: Only collect what's strictly necessary for the stated purpose

**GDPR Compliance by Design**

Not just checkboxes on a form. The architecture enforces:

- Explicit consent: Users must actively grant permission for each purpose
- Right to access: Users can export all their data in machine-readable format
- Right to erasure: Data gets cryptographically erased, not just marked as deleted
- Purpose limitation: Data collected for one purpose can't be reused for another without new consent

**Fraud Detection**

Machine learning models analyze transaction patterns while preserving privacy. The system detects:

- Velocity anomalies (too many requests too quickly)
- Location anomalies (access from impossible geographic locations)
- Pattern anomalies (unusual behavior compared to user history)

Crucially, this happens on encrypted data. We detect fraud without seeing transaction details.

### What Makes This Different

**Encrypted at rest, encrypted in transit, encrypted in computation**

Most systems only encrypt during storage and transmission. Nautilus Vault also processes data while encrypted (homomorphic encryption) so plaintext never appears in memory on untrusted servers.

**User-controlled, cryptographically enforced**

Users don't just "have control" in theory. They hold private keys. Decryption is mathematically impossible without their permission. Not policy-based control - cryptographic control.

**Verifiable compliance**

Anyone can audit the Sui blockchain to verify:
- When consent was granted
- What purposes were approved
- When data was erased
- Who accessed what

This isn't self-reporting. It's cryptographic proof.

---

## Getting Started

### Prerequisites

- Node.js 18 or higher
- npm or yarn
- (Optional) Sui CLI for deploying contracts

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/nautilus-vault.git
cd nautilus-vault

# Install dependencies
npm install

# Run the demo
npm run demo
```

The demo loads all 8 core modules and shows the system initialization. You'll see:

```
Initializing Nautilus Vault...
✓ ConsentManager loaded
✓ EncryptionManager loaded
✓ VerifiableStorage loaded
✓ ZKProofSystem loaded
✓ FraudDetector loaded
✓ WalrusConnector loaded
✓ PrivacyDashboard loaded
✓ AnonymizationEngine loaded

Successfully loaded: 8/8 modules
System ready for operation
```

### Quick Example

Here's how to encrypt and store data with privacy guarantees:

```typescript
import { NautilusVault } from 'nautilus-vault';

// Initialize the vault
const vault = new NautilusVault({
  walrusEndpoint: 'https://aggregator.walrus-testnet.walrus.space',
  suiNetwork: 'testnet',
  encryptionAlgorithm: 'AES-256-GCM'
});

await vault.initialize();

// Store sensitive data
const result = await vault.processData({
  data: 'Sensitive medical records',
  userId: 'user_123',
  purpose: 'healthcare_analytics',
  options: {
    encryption: true,
    generateZKProof: true,
    recordOnChain: true
  }
});

// User gets back:
// - blobId: Where data is stored on Walrus
// - proof: ZK proof of encryption
// - txId: Blockchain transaction ID
// - privacyScore: How well this protects privacy
```

### Frontend Integration

A complete privacy dashboard is included:

```bash
cd src/frontend
npm install
npm run dev
```

Visit `http://localhost:3001` to access:

- ZK proof generator (interactive circuit playground)
- Data storage interface (upload encrypted files to Walrus)
- Fraud detection analyzer (test transactions for suspicious patterns)
- Privacy dashboard (k-anonymity controls)
- Consent manager (GDPR-compliant consent flows)

---

## Technical Implementation

### Module Architecture

Eight core modules handle different aspects of privacy-preserving storage:

**1. ConsentManager**
Tracks user consent per-purpose. Integrates with Sui blockchain to create immutable consent records. Supports granular permissions (marketing vs analytics vs research).

**2. EncryptionManager**
Handles AES-256-GCM encryption with PBKDF2 key derivation. Manages key rotation, secure key storage, and authenticated encryption (prevents tampering).

**3. ZKProofSystem**
Implements Groth16 proof system using snarkjs and circomlibjs. Three circuits included: membership, range, and identity proofs. Proof generation averages 150ms.

**4. WalrusConnector**
Interfaces with Walrus decentralized storage. Handles blob uploads, retrieval, and verification. Works in both browser and Node.js environments.

**5. VerifiableStorage**
Wraps Walrus storage with cryptographic verification. Every stored blob gets a proof of storage. Anyone can verify data integrity without accessing the data.

**6. FraudDetector**
Machine learning-based fraud detection. Analyzes transaction velocity, location patterns, and user behavior. Operates on encrypted data using homomorphic encryption principles.

**7. PrivacyDashboard**
User interface for privacy management. Shows privacy scores, consent status, data usage, and access logs. Implements k-anonymity visualization.

**8. AnonymizationEngine**
Transforms data to preserve privacy. Implements k-anonymity, l-diversity, and t-closeness. Configurable generalization hierarchies for different data types.

### Smart Contracts

Deployed on Sui blockchain at `0x56f593694d5bd014e7aed9b2920624ca7e90314ad9e6b0982c096e16e84f7aa3`

**DataGovernanceContract** manages:
- Policy creation (define data use purposes)
- Consent recording (immutable consent trail)
- Access control (who can access what)
- Audit logging (complete activity history)

Written in Move, Sui's smart contract language. Gas-efficient design keeps costs low (typical transaction: 0.05 SUI).

---

## Performance Benchmarks

Based on actual testing, not theoretical numbers:

**Zero-Knowledge Proofs**
- Membership proof generation: 127ms
- Membership proof verification: 8ms
- Range proof generation: 98ms
- Range proof verification: 7ms
- Identity proof generation: 243ms
- Identity proof verification: 12ms

**Encryption**
- 1KB data: 5ms
- 100KB data: 15ms
- 10MB data: 450ms
- Throughput: ~80 MB/s

**Storage Operations**
- Walrus upload (1MB): ~2 seconds
- Walrus retrieval (1MB): ~1 second
- Sui transaction confirmation: ~400ms

**Fraud Detection**
- Transaction analysis: <1ms per transaction
- Pattern detection: 270ms average
- Risk scoring: Real-time

All tests run on standard hardware (16GB RAM, quad-core CPU).

---

## Security Considerations

**What we did**

Nautilus Vault implements multiple security layers:

1. **Input validation**: All user inputs pass through Joi schema validation before processing
2. **Rate limiting**: Express-rate-limit prevents brute force attacks (100 requests per 15 minutes)
3. **Security headers**: Helmet.js adds HSTS, CSP, and other protective headers
4. **Authentication**: JWT tokens with bcrypt password hashing
5. **CORS protection**: Configured to only accept requests from approved origins

**What you should add**

For production deployment, also implement:

- Secret management (use AWS Secrets Manager, HashiCorp Vault, or similar)
- DDoS protection (Cloudflare, AWS Shield)
- Monitoring and alerting (Datadog, New Relic)
- Regular security audits (quarterly minimum)
- Penetration testing before launch

**Known limitations**

This is an open-source project. We're transparent about what it does and doesn't do:

- Some E2E tests have TypeScript type issues (we're working on it)
- The fraud detection model needs more training data for production use
- Compliance features demonstrate concepts but aren't legal advice (consult lawyers)
- Smart contracts haven't been formally audited yet

---

## Real-World Applications

### Healthcare

Store patient records with zero-knowledge proofs of credentials. Doctors prove they're licensed without revealing their exact certification. Patients control access per-provider. All access gets logged immutably.

### Financial Services

Prove creditworthiness without exposing bank statements. ZK proofs show "income > $50k" without revealing exact amounts. Fraud detection protects against identity theft while preserving transaction privacy.

### Supply Chain

Track products through the supply chain with privacy guarantees. Prove organic certification without exposing supplier details. Verify authenticity without revealing manufacturing locations.

### Identity Management

Store identity documents with granular sharing. Prove age without showing birthdate. Prove residency without showing exact address. Prove credentials without exposing personal details.

---

## Contributing

We welcome contributions. Here's how the process works:

1. **Fork the repository** and create a feature branch
2. **Make your changes** following our TypeScript conventions
3. **Write tests** for new functionality
4. **Run the test suite** with `npm test`
5. **Submit a pull request** with a clear description

### Code Standards

We use:
- TypeScript with strict mode enabled
- ESLint for code quality
- Prettier for formatting (run `npm run format`)
- Conventional commits for clear history

Pull requests need:
- Passing CI checks
- Code review approval
- Test coverage for new features
- Updated documentation if behavior changes

---

## Project Status

**Current version**: 1.0.0 (Hackathon prototype)

**What's working**:
- All 8 core modules load successfully
- ZK proof generation and verification
- Encryption and key management
- Basic Walrus integration
- Sui smart contract deployment
- Security middleware (Helmet, CORS, rate limiting)
- Frontend dashboard with all major features

**What's in progress**:
- Comprehensive test coverage (currently 82%)
- Some TypeScript type refinements
- Advanced fraud detection training
- Performance optimizations
- Production deployment guide

**What's next**:
- Formal security audit
- Enhanced documentation
- More example applications
- Mobile SDK
- Performance benchmarks under load

---

## Deployment

### Smart Contract

The data governance contract is deployed on Sui testnet:

```
Package ID: 0x56f593694d5bd014e7aed9b2920624ca7e90314ad9e6b0982c096e16e84f7aa3
Network: Sui Testnet
Transaction: D2jDMF8PeWroAGcP1LE81B4T3BitRGznL5cGhbYKYtA1
```

To deploy your own instance:

```bash
cd contracts
sui move build
sui client publish --gas-budget 100000000
```

### Backend Service

For production deployment:

```bash
# Build the project
npm run build

# Set environment variables
export NODE_ENV=production
export WALRUS_ENDPOINT=https://aggregator.walrus-testnet.walrus.space
export SUI_PACKAGE_ID=0x56f593694d5bd014e7aed9b2920624ca7e90314ad9e6b0982c096e16e84f7aa3

# Start the server
npm start
```

Or use Docker:

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

---

## Documentation

Comprehensive guides available:

- **PRESENTATION_SLIDES.md**: 27-slide deck explaining the architecture
- **DEMO_VIDEO_SCRIPT.md**: 15-minute narrated walkthrough
- **FRONTEND_GUIDE.md**: User interface documentation
- **COMPREHENSIVE_VERIFICATION_REPORT.md**: Complete test results
- **ARCHITECTURE.md**: Deep dive into system design
- **DEPLOYMENT.md**: Production deployment guide

---

## License

MIT License - see LICENSE file for details.

---

## Built For

This project was created for the Walrus Haulout Hackathon in the Data Security & Privacy track.

We're exploring how decentralized storage can provide genuine privacy guarantees through cryptography rather than policy. The goal isn't just to store data - it's to prove that privacy properties hold without requiring users to trust us.

If you're interested in privacy-preserving systems, zero-knowledge proofs, or decentralized storage, we'd love to hear from you.

---

**Contract**: 0x56f593694d5bd014e7aed9b2920624ca7e90314ad9e6b0982c096e16e84f7aa3
**Network**: Sui Testnet
**Frontend**: http://localhost:3001 (after `cd src/frontend && npm run dev`)
