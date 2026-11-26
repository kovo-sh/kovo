import type { projectData } from '../../actions.ts'
import type { PersonaLoginAdapter, PublicPersona } from '../../domain.ts'

export type ProjectTabId = 'overview' | 'runs' | 'inventory' | 'personas' | 'sources' | 'guardrails'

export const PROJECT_TABS: readonly { id: ProjectTabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'runs', label: 'Runs' },
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

export const LOGIN_URL_PLACEHOLDERS: Record<PersonaLoginAdapter, string> = {
  auto: 'Optional — auto-detected for Clerk',
  clerk: 'Optional — auto-detected for Clerk',
  clerk_client: 'Optional — auto-detected, or https://<instance>.clerk.accounts.dev',
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
    if (adapter === 'clerk_client') {
      return email ? `${email} · Clerk __client (auto-refresh)` : 'Clerk __client (auto-refresh)'
    }
    return email ? `${email} · login (${adapter})` : `login (${adapter})`
  }
  return persona.headerName ? `${persona.authKind} · ${persona.headerName}` : persona.authKind
}

export function formatGithubPatBadge(status: ProjectLoaderData['githubPatStatus']): string {
  if (!status.configured) return 'Not connected'
  return status.login ? `GitHub connected · @${status.login}` : 'GitHub connected'
}

export function formatIsoDay(iso: string | null): string | null {
  if (!iso) return null
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) return null
  return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}
