# Nautilus Vault - Frontend

Production-ready Next.js 16 frontend for the Nautilus Vault with complete integration of all security, privacy, and blockchain features.

## Features

### 1. **Zero-Knowledge Proof Generator** (`/zk-proofs`)
- Interactive circuit selection (Membership, Range, Identity proofs)
- Real-time proof generation and verification
- Performance metrics (generation/verification time)
- Support for custom inputs with validation

### 2. **Walrus Data Storage** (`/storage`)
- Upload data to decentralized Walrus network
- Encryption toggle (AES-256-GCM)
- Retrieve data by Blob ID
- View stored blobs history

### 3. **Fraud Detection** (`/fraud`)
- ML-powered transaction analysis
- Risk score visualization (0-100%)
- Quick example scenarios (safe/suspicious/dangerous)
- Real-time fraud indicators and recommendations

### 4. **Privacy Dashboard** (`/privacy`)
- K-anonymity data protection (adjustable K value)
- Privacy score monitoring (98.5% default)
- Data anonymization with quality metrics
- Privacy vs utility trade-off visualization

### 5. **Consent Management** (`/consent`)
- GDPR/CCPA compliant consent system
- Multiple consent purposes (marketing, analytics, research, etc.)
- Consent history tracking
- Data portability (export user data as JSON)
- Consent revocation

### 6. **Interactive Dashboard** (`/dashboard`)
- Live system metrics
- Real-time health monitoring
- Feature overview
- Production status indicators

### 7. **Live Demo** (`/demo`)
- Automated test suite
- 4 test scenarios with real API calls
- Progress tracking
- Success rate metrics

## Technology Stack

- **Framework**: Next.js 16 (App Router)
- **UI Library**: Radix UI + Tailwind CSS
- **Icons**: Lucide React
- **State Management**: Zustand
- **TypeScript**: Full type safety
- **API Client**: Custom fetch-based client

## Project Structure

```
src/frontend/
├── app/                    # Next.js App Router pages
│   ├── layout.tsx         # Root layout
│   ├── page.tsx           # Landing page
│   ├── dashboard/         # Dashboard page
│   ├── demo/              # Demo page
│   ├── zk-proofs/         # ZK Proof Generator
│   ├── storage/           # Walrus Storage
│   ├── fraud/             # Fraud Detection
│   ├── privacy/           # Privacy Dashboard
│   └── consent/           # Consent Management
├── components/            # React components
│   ├── ui/               # Shadcn/UI components
│   ├── dashboard/        # Dashboard-specific
│   ├── zk-proof/         # ZK Proof components
│   ├── storage/          # Storage components
│   ├── fraud/            # Fraud detection
│   └── privacy/          # Privacy components
├── lib/                   # Utilities
│   ├── api.ts            # API client
│   ├── store.ts          # Zustand store
│   └── utils.ts          # Helper functions
├── hooks/                 # Custom React hooks
│   └── use-metrics.ts    # Metrics hook
├── config/               # Configuration
│   └── site.ts           # Site config
└── styles/               # Global styles
```

## Getting Started

### Installation

```bash
cd src/frontend
npm install
```

### Environment Variables

Create `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:3000
```

### Development

```bash
npm run dev
```

Frontend runs on: `http://localhost:3001`

### Build

```bash
npm run build
npm start
```

## API Integration

All components integrate with the backend API through `lib/api.ts`:

### Available Endpoints

- **Health & Metrics**
  - `GET /health` - Server health check
  - `GET /metrics` - System metrics

- **Encryption**
  - `POST /api/encrypt` - Encrypt data
  - `POST /api/decrypt` - Decrypt data

- **Fraud Detection**
  - `POST /api/fraud-check` - Analyze transaction

- **Privacy**
  - `POST /api/anonymize` - K-anonymity protection
  - `POST /api/privacy/score` - Calculate privacy score

- **Consent**
  - `POST /api/consent/create` - Grant consent
  - `POST /api/consent/revoke` - Revoke consent
  - `GET /api/consent/:userId` - Get consents
  - `POST /api/privacy/export` - Data portability

- **ZK Proofs**
  - `POST /api/zk/generate` - Generate proof
  - `POST /api/zk/verify` - Verify proof
  - `GET /api/zk/circuits` - List circuits

- **Walrus Storage**
  - `POST /api/walrus/store` - Store data
  - `POST /api/walrus/retrieve` - Retrieve data
  - `GET /api/walrus/list` - List blobs

## State Management

Using Zustand for global state:

```typescript
import { useStore } from '@/lib/store'

// In component
const { storedData, addStoredData } = useStore()
```

### Store Slices

- **User**: Current user state
- **Data Storage**: Stored blobs
- **ZK Proofs**: Generated proofs
- **Privacy**: Privacy score
- **Consents**: Consent history
- **Fraud**: Analysis results
- **UI**: Loading/error states

## Component Usage Examples

### ZK Proof Generator

```tsx
import { ZKProofGenerator } from '@/components/zk-proof/ZKProofGenerator'

<ZKProofGenerator />
```

### Data Storage

```tsx
import { DataStorage } from '@/components/storage/DataStorage'

<DataStorage />
```

### Fraud Detector

```tsx
import { FraudDetector } from '@/components/fraud/FraudDetector'

<FraudDetector />
```

## Features Checklist

- [x] Landing page with feature overview
- [x] Interactive dashboard with live metrics
- [x] ZK Proof generation and verification
- [x] Walrus storage upload/retrieve
- [x] ML fraud detection interface
- [x] K-anonymity privacy protection
- [x] GDPR consent management
- [x] Data portability (export)
- [x] Real-time monitoring
- [x] Responsive design
- [x] Dark mode support
- [x] Error handling
- [x] Loading states
- [x] Type safety
- [x] State management

## Production Readiness

### Performance
- Next.js 16 optimizations
- Server components where applicable
- Client components for interactivity
- Optimized bundle size

### Security
- Environment variable protection
- API URL configuration
- Input validation
- XSS protection (React escaping)

### User Experience
- Loading indicators
- Error messages
- Success confirmations
- Responsive layout
- Accessible components (Radix UI)

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Troubleshooting

### Backend Connection Issues

If frontend can't connect to backend:

1. Check backend is running on port 3000
2. Verify `NEXT_PUBLIC_API_URL` in `.env.local`
3. Check CORS configuration on backend

### Build Errors

```bash
# Clean and reinstall
rm -rf node_modules .next
npm install
npm run build
```

## Contributing

1. Create feature branch
2. Make changes
3. Test locally
4. Submit pull request

## License

MIT
