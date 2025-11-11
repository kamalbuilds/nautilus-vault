'use client'

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Shield,
  Eye,
  Cpu,
  Lock,
  FileCheck,
  Globe,
  Zap,
  Database,
  CheckCircle,
  ArrowRight
} from "lucide-react"

const securityFeatures = [
  {
    title: "Military-Grade Encryption",
    description: "AES-256-GCM encryption with advanced key management",
    icon: Lock,
    status: "active"
  },
  {
    title: "Zero-Knowledge Proof Systems",
    description: "Privacy-preserving computation and verification",
    icon: Eye,
    status: "active"
  },
  {
    title: "ML-Powered Fraud Detection",
    description: "Real-time threat analysis with machine learning",
    icon: Cpu,
    status: "active"
  },
  {
    title: "Real-time Threat Analysis",
    description: "Continuous security monitoring and response",
    icon: Zap,
    status: "active"
  },
  {
    title: "Cryptographic Data Verification",
    description: "Blockchain-based integrity verification",
    icon: Shield,
    status: "active"
  },
  {
    title: "Privacy-Preserving Computation",
    description: "Secure multi-party computation protocols",
    icon: Database,
    status: "active"
  }
]

const privacyFeatures = [
  {
    title: "GDPR/CCPA Full Compliance",
    description: "Complete regulatory compliance framework",
    icon: FileCheck,
    status: "certified"
  },
  {
    title: "Automated Consent Management",
    description: "Dynamic consent tracking and management",
    icon: CheckCircle,
    status: "active"
  },
  {
    title: "K-Anonymity Data Protection",
    description: "Advanced anonymization with quality metrics",
    icon: Eye,
    status: "active"
  },
  {
    title: "Right to be Forgotten",
    description: "Automated data deletion and purging",
    icon: Shield,
    status: "active"
  },
  {
    title: "Differential Privacy",
    description: "Statistical privacy with noise injection",
    icon: Lock,
    status: "active"
  },
  {
    title: "Audit Trail & Reporting",
    description: "Comprehensive compliance reporting",
    icon: FileCheck,
    status: "active"
  }
]

const walrusFeatures = [
  {
    title: "Decentralized Storage Integration",
    description: "Seamless integration with Walrus storage network",
    icon: Database,
    status: "integrated"
  },
  {
    title: "Seal Privacy Computation",
    description: "Private computation using Seal protocols",
    icon: Lock,
    status: "active"
  },
  {
    title: "Nautilus Secure Data Flows",
    description: "Secure data pipeline orchestration",
    icon: ArrowRight,
    status: "active"
  },
  {
    title: "Sui Smart Contract Governance",
    description: "Blockchain-based security governance",
    icon: Globe,
    status: "active"
  },
  {
    title: "Cryptographic Verification",
    description: "On-chain verification and attestation",
    icon: Shield,
    status: "active"
  },
  {
    title: "Distributed Consensus",
    description: "Byzantine fault-tolerant consensus",
    icon: Zap,
    status: "active"
  }
]

function FeatureCard({ title, description, icon: Icon, status }: any) {
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'certified':
        return <Badge variant="default" className="bg-green-600">Certified</Badge>
      case 'integrated':
        return <Badge variant="outline" className="border-blue-500 text-blue-600">Integrated</Badge>
      default:
        return <Badge variant="secondary">Active</Badge>
    }
  }

  return (
    <Card className="group hover:shadow-md transition-shadow">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <Icon className="h-5 w-5 text-primary" />
          {getStatusBadge(status)}
        </div>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  )
}

export function FeaturesGrid() {
  return (
    <div className="space-y-8">
      {/* Security Features */}
      <div>
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Advanced Security Features
        </h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {securityFeatures.map((feature, index) => (
            <FeatureCard key={index} {...feature} />
          ))}
        </div>
      </div>

      {/* Privacy & Compliance */}
      <div>
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Eye className="h-5 w-5" />
          Privacy & Compliance
        </h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {privacyFeatures.map((feature, index) => (
            <FeatureCard key={index} {...feature} />
          ))}
        </div>
      </div>

      {/* Walrus Ecosystem */}
      <div>
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Globe className="h-5 w-5" />
          Walrus Ecosystem Integration
        </h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {walrusFeatures.map((feature, index) => (
            <FeatureCard key={index} {...feature} />
          ))}
        </div>
      </div>
    </div>
  )
}