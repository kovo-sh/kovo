import type { runData } from '../actions.ts'
import type { ApprovalPolicy, BoardMemberState, BoardMessageKind, CapabilityTier, OwaspCategory, Phase } from '../domain.ts'

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
    name: 'Offline Review',
    short: 'Offline',
    summary: 'No live network traffic. Reviews prepared exports, DNS records, lockfiles, and access policies only.',
  },
  1: {
    name: 'Read-Only Scan',
    short: 'Read-Only',
    summary: 'Safe read-only HTTP checks, JavaScript and API discovery, scoped browser inspection, live DNS/TLS checks, and benign verification probes.',
  },
  2: {
    name: 'Authenticated Testing',
    short: 'Authenticated',
    summary: 'Includes read-only checks plus signed-in testing with your test accounts on approved hosts for cross-account access, role, and session checks.',
  },
  3: {
    name: 'Active Testing (Approval-Gated)',
    short: 'Active (Gated)',
    summary: 'Includes authenticated testing plus approval-gated state checks and strictly non-destructive proof-of-execution verification.',
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
    summary: 'Fast-paths safe read-only checks, reviews write requests with an independent safety checker, and always asks you before deletes, uploads, billing/admin actions, or execution checks.',
  },
  yolo: {
    label: 'Autonomous',
    short: 'Autonomous',
    optionLabel: 'Autonomous (Auto-approve in scope)',
    summary: 'Automatically approves all in-scope active checks with full audit logging. Hard safety guardrails (approved hosts only, private network block, destructive denylist, rate limits, and circuit breakers) remain enforced.',
  },
  strict: {
    label: 'Manual Approval',
    short: 'Manual',
    optionLabel: 'Manual (Approve every write)',
    summary: 'Pauses and requires your explicit approval before every state-changing test request.',
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

export const boardKindLabels: Record<BoardMessageKind, string> = {
  brief: 'BRIEF',
  claim: 'CLAIM',
  handoff: 'HANDOFF',
  lead: 'LEAD',
  blocker: 'BLOCKER',
  approval: 'APPROVAL',
  verdict: 'VERDICT',
  status: 'STATUS',
  note: 'NOTE',
}

export const boardStateMeta: Record<BoardMemberState, { label: string; symbol: string; className: string }> = {
  working: { label: 'working', symbol: '●', className: 'state-working' },
  waiting: { label: 'waiting', symbol: '○', className: 'state-waiting' },
  paused: { label: 'paused', symbol: '⏸', className: 'state-paused' },
  retired: { label: 'retired', symbol: '✓', className: 'state-retired' },
}

export const boardRoleLabels: Record<string, string> = {
  operator: 'Operator',
  coordinator: 'Coordinator',
  specialist: 'Specialist',
  verifier: 'Verifier',
  system: 'System',
}
