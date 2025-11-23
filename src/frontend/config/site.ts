export type SiteConfig = typeof siteConfig

export const siteConfig = {
  name: "Nautilus Vault",
  description:
    "Enterprise-grade security, privacy, and compliance platform built on the Walrus ecosystem.",
  mainNav: [
    {
      title: "Home",
      href: "/",
    },
    {
      title: "Dashboard",
      href: "/dashboard",
    },
    {
      title: "ZK Proofs",
      href: "/zk-proofs",
    },
    {
      title: "Storage",
      href: "/storage",
    },
    {
      title: "Fraud Detection",
      href: "/fraud",
    },
    {
      title: "Privacy",
      href: "/privacy",
    },
    {
      title: "Consent",
      href: "/consent",
    },
    {
      title: "Demo",
      href: "/demo",
    },
  ],
  links: {
    twitter: "https://twitter.com/walrus",
    github: "https://github.com/walrus-security-suite",
    docs: "https://walrus.security/docs",
  },
}
