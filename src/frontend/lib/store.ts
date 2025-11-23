import { create } from 'zustand'

export interface User {
  id: string
  name: string
  email: string
}

export interface StoredBlob {
  id: string
  blobId: string
  name: string
  size: number
  encrypted: boolean
  timestamp: Date
}

export interface ZKProof {
  id: string
  circuitName: string
  proof: any
  publicSignals: any
  verified: boolean
  timestamp: Date
}

export interface Consent {
  id: string
  purposes: string[]
  granted: boolean
  timestamp: Date
}

export interface FraudAnalysis {
  id: string
  riskScore: number
  isFraud: boolean
  details: any
  timestamp: Date
}

interface AppState {
  // User state
  user: User | null
  setUser: (user: User | null) => void

  // Data storage state
  storedData: StoredBlob[]
  addStoredData: (data: StoredBlob) => void
  removeStoredData: (id: string) => void

  // ZK Proof state
  zkProofs: ZKProof[]
  addZKProof: (proof: ZKProof) => void
  clearZKProofs: () => void

  // Privacy state
  privacyScore: number
  updatePrivacyScore: (score: number) => void

  // Consent state
  consents: Consent[]
  addConsent: (consent: Consent) => void
  revokeConsent: (id: string) => void

  // Fraud detection state
  fraudAnalyses: FraudAnalysis[]
  addFraudAnalysis: (analysis: FraudAnalysis) => void

  // UI state
  loading: boolean
  setLoading: (loading: boolean) => void
  error: string | null
  setError: (error: string | null) => void
}

export const useStore = create<AppState>((set) => ({
  // User state
  user: null,
  setUser: (user) => set({ user }),

  // Data storage state
  storedData: [],
  addStoredData: (data) => set((state) => ({ storedData: [...state.storedData, data] })),
  removeStoredData: (id) => set((state) => ({
    storedData: state.storedData.filter((d) => d.id !== id)
  })),

  // ZK Proof state
  zkProofs: [],
  addZKProof: (proof) => set((state) => ({ zkProofs: [...state.zkProofs, proof] })),
  clearZKProofs: () => set({ zkProofs: [] }),

  // Privacy state
  privacyScore: 98.5,
  updatePrivacyScore: (score) => set({ privacyScore: score }),

  // Consent state
  consents: [],
  addConsent: (consent) => set((state) => ({ consents: [...state.consents, consent] })),
  revokeConsent: (id) => set((state) => ({
    consents: state.consents.map((c) => c.id === id ? { ...c, granted: false } : c)
  })),

  // Fraud detection state
  fraudAnalyses: [],
  addFraudAnalysis: (analysis) => set((state) => ({
    fraudAnalyses: [...state.fraudAnalyses, analysis]
  })),

  // UI state
  loading: false,
  setLoading: (loading) => set({ loading }),
  error: null,
  setError: (error) => set({ error }),
}))
