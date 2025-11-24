# System Architecture - Nautilus Vault

**Comprehensive architectural documentation with C4 model diagrams**

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [C4 Model Diagrams](#c4-model-diagrams)
3. [Component Descriptions](#component-descriptions)
4. [Data Flow Patterns](#data-flow-patterns)
5. [Integration Architecture](#integration-architecture)
6. [Security Architecture](#security-architecture)
7. [Deployment Architecture](#deployment-architecture)
8. [Architecture Decisions](#architecture-decisions)

---

## Architecture Overview

### System Context

The Nautilus Vault provides enterprise-grade privacy and security capabilities for decentralized applications built on the Walrus ecosystem. It integrates zero-knowledge proofs, homomorphic encryption, and blockchain governance into a unified TypeScript framework.

### Design Principles

1. **Privacy by Design**: Privacy mechanisms integrated at every layer
2. **Modular Architecture**: Loosely coupled components with clear interfaces
3. **Defense in Depth**: Multiple layers of security controls
4. **Fail-Safe Defaults**: Secure configurations out of the box
5. **Separation of Concerns**: Clear boundaries between security, privacy, and storage

---

## C4 Model Diagrams

### Level 1: System Context Diagram

```
                    ┌─────────────────────┐
                    │   End Users         │
                    │ (Web, Mobile, API)  │
                    └──────────┬──────────┘
                               │
                               │ HTTPS/REST
                               ▼
    ┌──────────────────────────────────────────────────┐
    │                                                   │
    │        Nautilus Vault                     │
    │                                                   │
    │  Privacy & Security Framework for Walrus         │
    │  - Zero-Knowledge Proofs                         │
    │  - Homomorphic Encryption                        │
    │  - Consent Management                            │
    │  - Data Governance                               │
    │                                                   │
    └─────────┬─────────────┬─────────────┬───────────┘
              │             │             │
              ▼             ▼             ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │   Walrus    │ │     Seal    │ │    Sui      │
    │  Network    │ │  Encryption │ │ Blockchain  │
    │             │ │             │ │             │
    │ Decentralized│ │ Homomorphic│ │ Smart       │
    │  Storage    │ │  Encryption │ │ Contracts   │
    └─────────────┘ └─────────────┘ └─────────────┘
```

**External Systems:**
- **Walrus Network**: Decentralized blob storage
- **Seal**: Homomorphic encryption layer for privacy-preserving computation
- **Sui Blockchain**: Smart contract platform for governance and verification

---

### Level 2: Container Diagram

```
┌───────────────────────────────────────────────────────────────┐
│                  Nautilus Vault                         │
│                                                                │
│  ┌──────────────────────────────────────────────────────┐    │
│  │           API Gateway (Express.js)                    │    │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────────┐  │    │
│  │  │ Helmet │ │  CORS  │ │ Rate   │ │ JWT Auth     │  │    │
│  │  │        │ │        │ │ Limit  │ │ Guard        │  │    │
│  │  └────────┘ └────────┘ └────────┘ └──────────────┘  │    │
│  └────────────────────────┬─────────────────────────────┘    │
│                            │                                   │
│  ┌─────────────────────────┴────────────────────────────┐    │
│  │           Business Logic Layer (TypeScript)           │    │
│  │                                                        │    │
│  │  ┌──────────────────┐        ┌──────────────────┐    │    │
│  │  │  Privacy Engine  │        │ Security Engine  │    │    │
│  │  │                  │        │                  │    │    │
│  │  │ - ZK Proofs      │        │ - Encryption     │    │    │
│  │  │ - Consent Mgr    │◄──────►│ - Key Mgmt       │    │    │
│  │  │ - Anonymizer     │        │ - Fraud Detect   │    │    │
│  │  │ - Privacy Score  │        │ - Auth/AuthZ     │    │    │
│  │  └──────────────────┘        └──────────────────┘    │    │
│  │                                                        │    │
│  └────────────────────────┬───────────────────────────┘      │
│                            │                                   │
│  ┌─────────────────────────┴────────────────────────────┐    │
│  │        Integration Layer (Connectors)                 │    │
│  │                                                        │    │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐    │    │
│  │  │  Walrus    │  │   Seal     │  │    Sui      │    │    │
│  │  │ Connector  │  │ Integration│  │  Connector  │    │    │
│  │  └────────────┘  └────────────┘  └─────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**Container Responsibilities:**
1. **API Gateway**: HTTP routing, authentication, rate limiting
2. **Business Logic**: Core security and privacy functionality
3. **Integration Layer**: External system connectors

---

### Level 3: Component Diagram - Privacy Engine

```
┌────────────────────────────────────────────────────────────┐
│                    PRIVACY ENGINE                           │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │           ZK Proof System Component                  │  │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────────┐    │  │
│  │  │ Membership│  │   Range   │  │   Identity   │    │  │
│  │  │  Circuit  │  │  Circuit  │  │   Circuit    │    │  │
│  │  └─────┬─────┘  └─────┬─────┘  └──────┬───────┘    │  │
│  │        │              │                │             │  │
│  │        └──────────────┼────────────────┘             │  │
│  │                       ▼                               │  │
│  │           ┌───────────────────────┐                  │  │
│  │           │  Proof Generator      │                  │  │
│  │           │  - snarkjs            │                  │  │
│  │           │  - Groth16            │                  │  │
│  │           └───────────────────────┘                  │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │          Consent Manager Component                   │  │
│  │  ┌────────────────┐         ┌─────────────────┐     │  │
│  │  │ Consent        │         │   Purpose       │     │  │
│  │  │ Request Mgr    │◄───────►│   Validator     │     │  │
│  │  └────────┬───────┘         └─────────────────┘     │  │
│  │           │                                          │  │
│  │           ▼                                          │  │
│  │  ┌────────────────┐         ┌─────────────────┐     │  │
│  │  │ Consent        │         │   Audit         │     │  │
│  │  │ Store          │────────►│   Logger        │     │  │
│  │  └────────────────┘         └─────────────────┘     │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │        Anonymization Engine Component                │  │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐   │  │
│  │  │ k-Anonymity│  │Differential│  │ Generalize  │   │  │
│  │  │  Enforcer  │  │  Privacy   │  │  Transform  │   │  │
│  │  └────────────┘  └────────────┘  └─────────────┘   │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │         Privacy Dashboard Component                  │  │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐   │  │
│  │  │  Privacy   │  │  Consent   │  │   Data      │   │  │
│  │  │  Score     │  │  Status    │  │   Usage     │   │  │
│  │  │  Calculator│  │  Tracker   │  │   Metrics   │   │  │
│  │  └────────────┘  └────────────┘  └─────────────┘   │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

### Level 3: Component Diagram - Security Engine

```
┌────────────────────────────────────────────────────────────┐
│                   SECURITY ENGINE                           │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │        Encryption Manager Component                  │  │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐   │  │
│  │  │   AES-256  │  │    Key     │  │     IV      │   │  │
│  │  │    GCM     │  │ Derivation │  │  Generator  │   │  │
│  │  │  Cipher    │  │  (PBKDF2)  │  │  (Crypto)   │   │  │
│  │  └─────┬──────┘  └──────┬─────┘  └──────┬──────┘   │  │
│  │        │                │                │           │  │
│  │        └────────────────┼────────────────┘           │  │
│  │                         ▼                            │  │
│  │            ┌────────────────────┐                    │  │
│  │            │  Encryption Core   │                    │  │
│  │            │  - node-forge      │                    │  │
│  │            │  - crypto          │                    │  │
│  │            └────────────────────┘                    │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │          Fraud Detector Component                    │  │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐   │  │
│  │  │  Pattern   │  │  Anomaly   │  │   Risk      │   │  │
│  │  │  Analyzer  │  │  Detection │  │   Scorer    │   │  │
│  │  └─────┬──────┘  └──────┬─────┘  └──────┬──────┘   │  │
│  │        │                │                │           │  │
│  │        └────────────────┼────────────────┘           │  │
│  │                         ▼                            │  │
│  │            ┌────────────────────┐                    │  │
│  │            │   ML Model         │                    │  │
│  │            │  - ml-matrix       │                    │  │
│  │            │  - ml-regression   │                    │  │
│  │            └────────────────────┘                    │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │        Authentication Manager Component              │  │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐   │  │
│  │  │    JWT     │  │   Token    │  │   Session   │   │  │
│  │  │  Generator │  │  Validator │  │   Manager   │   │  │
│  │  └────────────┘  └────────────┘  └─────────────┘   │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │          Key Management Component                    │  │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐   │  │
│  │  │    Key     │  │    Key     │  │    Key      │   │  │
│  │  │ Generation │  │  Rotation  │  │   Storage   │   │  │
│  │  └────────────┘  └────────────┘  └─────────────┘   │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

### Level 4: Code Structure

```
src/
├── api/
│   ├── routes/
│   │   ├── privacy.routes.ts      # Privacy API endpoints
│   │   ├── security.routes.ts     # Security API endpoints
│   │   └── walrus.routes.ts       # Walrus integration endpoints
│   ├── middleware/
│   │   ├── auth.middleware.ts     # JWT authentication
│   │   ├── ratelimit.middleware.ts# Rate limiting
│   │   └── validation.middleware.ts# Input validation
│   └── controllers/
│       ├── privacy.controller.ts  # Privacy business logic
│       └── security.controller.ts # Security business logic
│
├── privacy/
│   ├── zk-proof-system.ts         # Zero-knowledge proofs
│   ├── consent-manager.ts         # Consent management
│   ├── anonymization-engine.ts    # Data anonymization
│   ├── privacy-engine.ts          # Privacy orchestrator
│   └── privacy-dashboard.ts       # Privacy metrics
│
├── security/
│   ├── encryption-manager.ts      # Encryption/decryption
│   ├── key-manager.ts             # Key management
│   ├── fraud-detector.ts          # Fraud detection
│   ├── authentication.ts          # Auth handling
│   └── security-headers.ts        # HTTP security
│
├── walrus/
│   ├── walrus-connector.ts        # Walrus API client
│   ├── verifiable-storage.ts      # Verified storage
│   ├── seal-integration.ts        # Seal encryption
│   └── data-flow-manager.ts       # Data orchestration
│
├── blockchain/
│   ├── sui-connector.ts           # Sui blockchain client
│   ├── contract-interfaces.ts     # Smart contract ABIs
│   └── governance.ts              # On-chain governance
│
└── circuits/
    ├── membership.circom          # Membership ZK circuit
    ├── range.circom               # Range ZK circuit
    └── identity.circom            # Identity ZK circuit
```

---

## Component Descriptions

### Privacy Components

#### 1. ZK Proof System

**Purpose**: Generate and verify zero-knowledge proofs for privacy-preserving claims

**Technologies**:
- snarkjs (Groth16 proof system)
- circomlibjs (circuit library)
- Custom circom circuits

**Key Features**:
- Membership proofs (Merkle tree verification)
- Range proofs (age/value constraints)
- Identity proofs (multi-attribute verification)
- Sub-second proof generation
- Sub-10ms verification

**Interfaces**:
```typescript
interface ZKProofSystem {
  generateProof(circuit: string, inputs: any): Promise<Proof>;
  verifyProof(proof: Proof): Promise<boolean>;
  generateMembershipProof(secret: string, set: string[]): Promise<Proof>;
  generateRangeProof(value: number, min: number, max: number): Promise<Proof>;
}
```

#### 2. Consent Manager

**Purpose**: GDPR-compliant consent tracking and management

**Key Features**:
- Granular purpose-based consent
- Consent withdrawal support
- Audit trail logging
- Legal basis tracking
- Expiration management

**Data Model**:
```typescript
interface ConsentRecord {
  id: string;
  subjectId: string;
  purpose: string;
  legalBasis: 'consent' | 'contract' | 'legal_obligation';
  granted: boolean;
  timestamp: Date;
  expiresAt?: Date;
  metadata: Record<string, any>;
}
```

#### 3. Anonymization Engine

**Purpose**: Apply privacy-preserving transformations to data

**Techniques**:
- k-anonymity enforcement
- Differential privacy noise injection
- Generalization transforms
- Suppression of identifiers

**Configuration**:
```typescript
interface AnonymizationConfig {
  method: 'k-anonymity' | 'differential-privacy' | 'generalization';
  k?: number;
  epsilon?: number;
  quasiIdentifiers: string[];
  sensitiveAttributes: string[];
}
```

---

### Security Components

#### 1. Encryption Manager

**Purpose**: Provide encryption/decryption services

**Algorithms**:
- AES-256-GCM (symmetric encryption)
- PBKDF2 (key derivation)
- RSA-2048 (asymmetric encryption - optional)

**Key Management**:
- Secure key generation
- Key rotation support
- Key storage in environment variables

**Interface**:
```typescript
interface EncryptionManager {
  encrypt(data: Buffer, key: string): Promise<EncryptedData>;
  decrypt(encryptedData: EncryptedData, key: string): Promise<Buffer>;
  deriveKey(password: string, salt: Buffer): Promise<Buffer>;
  generateIV(): Buffer;
}
```

#### 2. Fraud Detector

**Purpose**: Detect fraudulent transactions and anomalies

**Techniques**:
- Pattern analysis
- Statistical anomaly detection
- ML-based risk scoring

**Features**:
- Real-time scoring
- Historical pattern learning
- Configurable thresholds

---

### Integration Components

#### 1. Walrus Connector

**Purpose**: Interface with Walrus decentralized storage

**Operations**:
- Blob upload (store)
- Blob download (retrieve)
- Blob verification
- Metadata management

**API Integration**:
```typescript
interface WalrusConnector {
  store(data: Buffer, options: StoreOptions): Promise<BlobId>;
  retrieve(blobId: string): Promise<Buffer>;
  verify(blobId: string, hash: string): Promise<boolean>;
  getMetadata(blobId: string): Promise<BlobMetadata>;
}
```

#### 2. Seal Integration

**Purpose**: Homomorphic encryption for privacy-preserving computation

**Capabilities**:
- Encrypted computation
- Session key management
- CKKS encryption scheme

**Status**: In development (API updates in progress)

#### 3. Sui Connector

**Purpose**: Interact with Sui blockchain for governance

**Operations**:
- Transaction submission
- Smart contract calls
- Event listening
- Balance queries

---

## Data Flow Patterns

### Pattern 1: Privacy-Preserving Data Storage

```
┌─────────┐                                           ┌──────────┐
│  User   │                                           │  Walrus  │
│ Request │                                           │ Network  │
└────┬────┘                                           └────▲─────┘
     │                                                      │
     │ 1. Submit data                                      │
     ▼                                                      │
┌─────────────────┐                                        │
│ Consent Check   │                                        │
│ (Consent Mgr)   │                                        │
└────┬────────────┘                                        │
     │ 2. Verify consent                                   │
     ▼                                                      │
┌─────────────────┐                                        │
│ Anonymization   │                                        │
│ (Privacy Engine)│                                        │
└────┬────────────┘                                        │
     │ 3. Apply k-anonymity                                │
     ▼                                                      │
┌─────────────────┐                                        │
│ ZK Proof Gen    │                                        │
│ (ZK System)     │                                        │
└────┬────────────┘                                        │
     │ 4. Generate proof                                   │
     ▼                                                      │
┌─────────────────┐                                        │
│ Encryption      │                                        │
│ (Enc Manager)   │                                        │
└────┬────────────┘                                        │
     │ 5. AES-256 encrypt                                  │
     ▼                                                      │
┌─────────────────┐                                        │
│ Walrus Upload   │───────────────────────────────────────►│
│ (Connector)     │  6. Store encrypted blob               │
└────┬────────────┘                                        │
     │                                                      │
     │ 7. Return blob ID + proof                           │
     ▼                                                      │
┌─────────────────┐                                        │
│ Blockchain Log  │                                        │
│ (Sui Connector) │                                        │
└────┬────────────┘                                        │
     │ 8. Record transaction                               │
     ▼                                                      │
┌─────────┐                                                │
│Response │                                                │
│ to User │                                                │
└─────────┘                                                │
```

---

### Pattern 2: Privacy Dashboard Query

```
User Request
     │
     ▼
┌─────────────────┐
│ Authentication  │  JWT verification
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│ Consent Query   │  Fetch user consents
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│ Data Usage Query│  Query storage metadata
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│ Privacy Score   │  Calculate privacy metrics
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│ Dashboard Build │  Aggregate & format
└────┬────────────┘
     │
     ▼
JSON Response
```

---

## Integration Architecture

### External System Integration

```
┌───────────────────────────────────────────────────────┐
│         Nautilus Vault                         │
└────┬──────────────────┬──────────────────┬───────────┘
     │                  │                  │
     ▼                  ▼                  ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────────┐
│   Walrus    │  │    Seal     │  │   Sui Blockchain│
│   Network   │  │ Encryption  │  │                 │
└─────────────┘  └─────────────┘  └─────────────────┘
     │                  │                  │
     ▼                  ▼                  ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────────┐
│ REST API    │  │  Library    │  │   JSON-RPC      │
│ /v1/store   │  │  @mysten/   │  │   API           │
│ /v1/retrieve│  │   seal      │  │   /api/v1/      │
└─────────────┘  └─────────────┘  └─────────────────┘
```

**Integration Patterns**:
- **Walrus**: REST API with retry logic and exponential backoff
- **Seal**: TypeScript library integration with error handling
- **Sui**: JSON-RPC with transaction batching

---

## Security Architecture

### Defense in Depth Layers

```
Layer 1: Network Security
├── Firewall (UFW)
├── DDoS Protection
└── TLS 1.2+ Encryption

Layer 2: Application Security
├── Helmet.js Security Headers
├── CORS Policy Enforcement
├── Rate Limiting (100 req/15min)
└── Input Validation (Joi)

Layer 3: Authentication & Authorization
├── JWT with RS256
├── Role-Based Access Control
└── Session Management

Layer 4: Data Security
├── AES-256-GCM Encryption
├── PBKDF2 Key Derivation
├── Secure Key Storage
└── Data Minimization

Layer 5: Privacy Layer
├── Zero-Knowledge Proofs
├── Consent Management
├── Anonymization
└── Audit Logging

Layer 6: Blockchain Security
├── On-Chain Verification
├── Immutable Audit Trail
└── Smart Contract Governance
```

---

## Deployment Architecture

### Production Deployment

```
                     Internet
                        │
                        ▼
                 ┌──────────────┐
                 │   Cloudflare │
                 │   CDN + WAF  │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │     Nginx    │
                 │ Reverse Proxy│
                 │  + SSL Term  │
                 └──────┬───────┘
                        │
          ┌─────────────┼─────────────┐
          │                           │
          ▼                           ▼
   ┌──────────────┐           ┌──────────────┐
   │   Node.js    │           │   Node.js    │
   │  Instance 1  │           │  Instance 2  │
   │   (PM2)      │           │   (PM2)      │
   └──────┬───────┘           └──────┬───────┘
          │                           │
          └─────────────┬─────────────┘
                        │
          ┌─────────────┴─────────────┐
          │                           │
          ▼                           ▼
   ┌──────────────┐           ┌──────────────┐
   │  PostgreSQL  │           │    Redis     │
   │  (Primary)   │           │  (Cache)     │
   └──────────────┘           └──────────────┘
```

---

## Architecture Decisions

### ADR-001: Seal Integration Architecture

**Status**: Accepted
**Date**: 2025-11-22
**Decision**: Migrate from Nautilus to Seal for homomorphic encryption
**Rationale**: Better Walrus ecosystem integration, active development

See [docs/ADR-001-SEAL-INTEGRATION-DECISION.md](ADR-001-SEAL-INTEGRATION-DECISION.md) for full details.

### ADR-002: Zero-Knowledge Proof System

**Status**: Accepted
**Date**: 2025-11-11
**Decision**: Use Groth16 proof system via snarkjs
**Rationale**: Best performance/security tradeoff, mature tooling

**Alternatives Considered**:
- PLONK: More flexible but slower verification
- STARK: No trusted setup but larger proof sizes
- Bulletproofs: Smaller proofs but slower

### ADR-003: Modular Architecture

**Status**: Accepted
**Date**: 2025-11-08
**Decision**: Implement modular component architecture
**Rationale**: Easier testing, better maintainability, flexible deployment

**Trade-offs**:
- Pro: Loose coupling, independent testing
- Con: More boilerplate, interface management

---

## Performance Considerations

### Scalability Targets

| Metric | Target | Current |
|--------|--------|---------|
| API Response Time (p95) | <100ms | ~50ms |
| ZK Proof Generation | <500ms | ~150ms |
| Encryption Throughput | >50 MB/s | ~80 MB/s |
| Concurrent Users | 10,000 | Tested to 1,000 |
| Walrus Upload | <2s | ~450ms |

### Optimization Strategies

1. **Caching**: Redis for frequently accessed data
2. **Connection Pooling**: Reuse database connections
3. **Lazy Loading**: Load heavy dependencies on demand
4. **Worker Threads**: Offload ZK proof generation
5. **CDN**: Static assets via Cloudflare

---

## Future Architecture Enhancements

### Planned Improvements

1. **Multi-Region Deployment**: Geographic distribution
2. **Microservices**: Break into smaller services
3. **Event-Driven**: Implement event sourcing
4. **GraphQL API**: Add GraphQL layer
5. **Seal Full Integration**: Complete homomorphic encryption

---

**Architecture Version**: 1.0.0
**Last Updated**: 2025-11-22
**Maintainer**: Walrus Security Architecture Team
