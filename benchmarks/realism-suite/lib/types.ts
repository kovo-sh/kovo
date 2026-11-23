// Shared types for every realism fixture and for grading submitted findings.
export interface Persona {
  id: string
  email: string
  password: string
  role: 'anonymous' | 'member' | 'admin' | 'service'
  tenant: string
  /** Opaque session material a scanner may replay (synthetic, per-run). */
  token?: string
  notes?: string
}

export interface ApiRefEntry {
  origin: string
  method: string
  path: string
  auth: 'none' | 'user' | 'admin' | 'tenant'
  notes?: string
}

export interface RouteRef {
  method: string
  path: string
  mounts?: string[]
  hops?: string[]
}

export interface FixtureStartOptions {
  seed?: number
  /** Async callback delay range in ms. Production defaults are 15_000–30_000; tests shrink it. */
  callbackDelayMs?: [number, number]
  /** WAN jitter range in ms. Default 50–300. */
  jitterMs?: [number, number]
  /** Monorepo scale target (minimum 2,500). */
  routeCount?: number
  /** Keep the materialized white-box tree on disk after stop (tests use this to inspect). */
  keepSource?: boolean
}

export interface StartedFixture {
  name: string
  title: string
  origins: Record<string, string>
  hosts: Record<string, string>
  personas: Persona[]
  api: ApiRefEntry[]
  routes?: RouteRef[]
  sourceDir?: string
  stop: () => Promise<void>
}

export interface FixtureModule {
  name: string
  title: string
  start: (options?: FixtureStartOptions) => Promise<StartedFixture>
}

export interface TruthFinding {
  id: string
  title: string
  vulnClass: string
  cwe?: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  origin?: string
  method?: string
  endpoint: string
  trigger?: { method: string; endpoint: string }
  persona?: string
  impact: string
  chain?: string
  evidence?: string[]
}

export interface TruthChain {
  id: string
  title: string
  members: string[]
  description: string
}

export interface TruthDecoy {
  id: string
  origin?: string
  method?: string
  endpoint: string
  vulnClass?: string
  reason: string
}

export interface Truth {
  fixture: string
  version: number
  summary: string
  findings: TruthFinding[]
  chains: TruthChain[]
  decoys: TruthDecoy[]
  invariants?: Record<string, unknown>
}

export interface SubmittedFinding {
  title?: string
  vulnClass?: string
  cwe?: string
  origin?: string
  method?: string
  endpoint: string
  status?: string
  persona?: string
  chain?: string
  evidence?: string[]
}

export interface ClaimResult {
  finding: SubmittedFinding
  kind: 'true_positive' | 'decoy_false_positive' | 'unmatched_false_positive' | 'ignored'
  matched?: TruthFinding | TruthDecoy
  reason: string
}

export interface ChainResult {
  id: string
  title: string
  total: number
  covered: number
  complete: boolean
}

export interface GradeResult {
  fixture: string
  submitted: number
  ignored: number
  truePositives: number
  falsePositives: number
  precision: number
  recall: number
  missed: TruthFinding[]
  chains: ChainResult[]
  claims: ClaimResult[]
}
