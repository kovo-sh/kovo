import type { runData } from '../actions.ts'
import type { CapabilityTier, OwaspCategory, Phase, WorkerPhase } from '../domain.ts'

export type RunDetail = Awaited<ReturnType<typeof runData>>
export type Worker = RunDetail['assignments'][number]

export const phaseNames: Record<Phase, string> = {
  consent: 'Discovery consent',
  discovery: 'Discovery',
  review: 'Awaiting scope approval',
  threat_model: 'Threat model',
  investigation: 'Investigation',
  verification: 'Verification',
  complete: 'Complete',
}

export const workerPhaseNames: Record<WorkerPhase, string> = {
  discovery: 'Discovery',
  threat_model: 'Threat model',
  investigation: 'Investigation',
  verification: 'Verification',
  retest: 'Fix verification',
}

export const workerPhases: WorkerPhase[] = ['discovery', 'threat_model', 'investigation', 'verification']

export const capabilityTierMeta: Record<CapabilityTier, { name: string; short: string; summary: string }> = {
  0: {
    name: 'Tier 0 · Offline Prepared',
    short: 'Tier 0 · Offline',
    summary: 'Zero live network traffic. Prepared metadata, DNS zone exports, lockfiles, and access policy records only.',
  },
  1: {
    name: 'Tier 1 · Deep Read-Only + Safe Probes',
    short: 'Tier 1 · Read-Only',
    summary: 'Approved GET/HEAD/OPTIONS, JS/API harvesting, scoped browser inspection, live DNS/TLS, CVE correlation, and benign read-only differential probes.',
  },
  2: {
    name: 'Tier 2 · Multi-Persona Validation',
    short: 'Tier 2 · Multi-Persona',
    summary: 'Tier 1 plus opaque persona auth injection on allowlisted origins and bounded synchronized bursts for BOLA/IDOR, RBAC, and session checks.',
  },
  3: {
    name: 'Tier 3 · Approval-Gated State & Execution',
    short: 'Tier 3 · Approval-Gated',
    summary: 'Tier 2 plus blocking HITL approval cards for non-idempotent state probes and strictly non-destructive RCE proof-of-execution.',
  },
}

export const owaspCategoryLabels: Record<OwaspCategory, string> = {
  'broken-access-control': 'Broken Access Control',
  'auth-identity': 'Auth & Identity',
  'injection-input': 'Injection & Input',
  'cors-client-side': 'CORS & Client-Side',
  'ssrf-redirects': 'SSRF & Redirects',
  'crypto-tls-transport': 'Crypto, TLS & Transport',
  'misconfig-exposure': 'Misconfiguration & Exposure',
  'upload-storage': 'Upload & Storage',
  'business-logic-race': 'Business Logic & Race',
  'dns-takeover-infra': 'DNS Takeover & Infra',
  'llm-ai-security': 'LLM & AI Security',
}

export function formatUsd(amount: number) {
  if (!Number.isFinite(amount)) return '$0.00'
  return amount < 0.01 && amount > 0 ? '<$0.01' : `$${amount.toFixed(2)}`
}
