import type { runData } from '../actions.ts'
import type { ApprovalPolicy, CapabilityTier, OwaspCategory, Phase } from '../domain.ts'

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
    summary: 'Tier 2 plus policy-gated state probes and strictly non-destructive RCE proof-of-execution.',
  },
}

export const approvalPolicyMeta: Record<ApprovalPolicy, {
  label: string
  short: string
  optionLabel: string
  summary: string
}> = {
  auto_review: {
    label: 'Auto-Review',
    short: 'Auto-Review',
    optionLabel: 'Auto-Review (Recommended)',
    summary: 'Fast-paths benign/read-only probes, evaluates grey-area writes via an independent Safety-Judge LLM, and always escalates DELETE, uploads, billing/admin, and RCE probes.',
  },
  yolo: {
    label: 'YOLO',
    short: 'YOLO',
    optionLabel: 'YOLO (Autonomous)',
    summary: 'Auto-approves all in-scope Tier 3 probes with full audit logging. Hard broker invariants (scope, SSRF/RFC1918 block, destructive/webshell denylist, RPS cap, circuit breakers) remain enforced.',
  },
  strict: {
    label: 'Strict',
    short: 'Strict',
    optionLabel: 'Strict (Manual HITL)',
    summary: 'Every Tier 3 state-changing probe pauses and requires explicit manual operator approval.',
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
