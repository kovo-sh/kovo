import type { projectData } from '../../actions.ts'
import type { CapabilityTier, PersonaLoginAdapter, PublicPersona } from '../../domain.ts'

export type ProjectTabId = 'overview' | 'inventory' | 'personas' | 'sources' | 'guardrails'

export const PROJECT_TABS: readonly { id: ProjectTabId; label: string }[] = [
  { id: 'overview', label: 'Overview & Runs' },
  { id: 'inventory', label: 'Inventory' },
  { id: 'personas', label: 'Test Accounts' },
  { id: 'sources', label: 'Source & Specs' },
  { id: 'guardrails', label: 'Guardrails & Lab' },
]

export function isProjectTab(value: unknown): value is ProjectTabId {
  return typeof value === 'string' && PROJECT_TABS.some(t => t.id === value)
}

export type ProjectLoaderData = Awaited<ReturnType<typeof projectData>>

export interface PersonaTestState {
  status: 'testing' | 'ok' | 'warn' | 'error'
  message: string
}

export interface DiscoveredGithubRepo {
  fullName: string
  private: boolean
  defaultBranch: string
  updatedAt: string | null
  description: string | null
}

export interface MissionPreset {
  id: string
  name: string
  tierLabel: string
  tier: CapabilityTier
  summary: string
  goal: string
  usdCap: number
  rps: number
  concurrency: number
  maxTurns: number
}

export const MISSION_PRESETS: MissionPreset[] = [
  {
    id: 'passive-recon',
    name: 'Passive Recon',
    tierLabel: 'Tier 1 · Read-Only',
    tier: 1,
    summary: 'Map hosts, JS bundles, routes, headers, auth boundaries, and crown-jewel assets with zero mutations.',
    goal: 'Enumerate public attack surfaces, classify crown-jewel APIs vs static origins, inspect JS bundles and headers, and verify reachable read-only issues without state-changing requests.',
    usdCap: 10,
    rps: 3,
    concurrency: 4,
    maxTurns: 40,
  },
  {
    id: 'bola-idor',
    name: 'Authenticated BOLA / IDOR',
    tierLabel: 'Tier 2 · Authenticated',
    tier: 2,
    summary: 'Cross-user authorization matrix probing with User A vs User B sessions across APIs and Server Actions.',
    goal: 'Verify tenant and user isolation across all authenticated API routes and Server Actions using paired test accounts. Capture control vs probe HTTP proofs for every cross-user boundary.',
    usdCap: 15,
    rps: 4,
    concurrency: 6,
    maxTurns: 80,
  },
  {
    id: 'greybox-deep',
    name: 'Full Grey-Box Deep Pentest',
    tierLabel: 'Tier 2 · Code + Live',
    tier: 2,
    summary: 'Combine static repo/spec auditing with live authenticated runtime probes and independent replay verification.',
    goal: 'Audit synced specs and source handlers alongside live authenticated endpoints. Trace Server Actions, middleware auth guards, business-logic workflows, and verify all findings via replay.',
    usdCap: 25,
    rps: 5,
    concurrency: 6,
    maxTurns: 150,
  },
  {
    id: 'active-hitl',
    name: 'Approval-Gated Active',
    tierLabel: 'Tier 3 · HITL',
    tier: 3,
    summary: 'Controlled state-changing verification with mandatory operator approval before every risky probe.',
    goal: 'Validate high-impact state transitions, race conditions, and business-logic bypasses with mandatory human-in-the-loop approval gates prior to any mutating verification probe.',
    usdCap: 30,
    rps: 3,
    concurrency: 4,
    maxTurns: 120,
  },
  {
    id: 'offline-audit',
    name: 'Offline Repo / Spec Audit',
    tierLabel: 'Tier 0 · Offline',
    tier: 0,
    summary: 'Zero live network traffic. Analyze synced repositories, OpenAPI/GraphQL specs, lockfiles, and prepared metadata.',
    goal: 'Perform an offline source-first and specification security audit across imported specs, lockfiles, DNS exports, and access policy records with zero outbound target traffic.',
    usdCap: 10,
    rps: 1,
    concurrency: 4,
    maxTurns: 60,
  },
]

export const LOGIN_URL_PLACEHOLDERS: Record<PersonaLoginAdapter, string> = {
  auto: 'Optional — auto-detected for Clerk',
  clerk: 'Optional — auto-detected for Clerk',
  json: 'https://app.example.com/api/auth/sign-in/email',
  supabase: 'Optional — defaults to <origin>/auth/v1/token?grant_type=password',
  form: 'Optional — defaults to <origin>/login',
}

export function safeHost(origin: string): string {
  try {
    const u = new URL(origin)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch {
    return origin
  }
}

export function formatPersonaAuthBadge(persona: PublicPersona): string {
  if (persona.authKind === 'login') {
    const email = persona.loginConfig?.email
    const adapter = persona.loginConfig?.adapter ?? 'auto'
    return email ? `${email} · login (${adapter})` : `login (${adapter})`
  }
  return persona.headerName ? `${persona.authKind} · ${persona.headerName}` : persona.authKind
}

export function formatGithubPatBadge(status: ProjectLoaderData['githubPatStatus']): string {
  if (!status.configured) return 'Optional · Not connected'
  const kindLabel = status.tokenKind === 'fine_grained'
    ? 'Fine-grained PAT'
    : status.tokenKind === 'classic'
      ? 'Classic PAT'
      : 'GitHub PAT'
  return status.source === 'fixture' ? `${kindLabel} · fixture` : `${kindLabel} saved`
}

export function formatIsoDay(iso: string | null): string | null {
  if (!iso) return null
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) return null
  return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}
