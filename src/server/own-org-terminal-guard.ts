/**
 * R3-05 Confirmation-Kernel Own-Org Benign-Read / Create FP Guard & Class Normalization.
 *
 * Pure, deterministic, fail-closed helpers extracted from `v8-oracle-hydrate.ts` to keep
 * shared kernel modules within strict LOC ceilings.
 */
import { stepReadsState } from './oracle-invariants.ts'
import type { OracleTerminalContractKind } from './oracle-spec.ts'
import type { HydratableEntry } from './v8-oracle-hydrate.ts'

export const normalizeTerminalVulnClass = (cls: string): string => cls.trim().toLowerCase().replace(/[\s-]+/g, '_')

// Access-control contract exemptions: csrf (ambient-cookie cross-site write), mass_assignment (field persistence),
// and signed/presigned URL mint classes validate distinct invariants outside the own-org benign read/create guard.
const OWN_ORG_ACCESS_CONTRACT_EXEMPT_RE = /^(?:csrf|mass_assignment|signed_url_.*|.*_signed_url|presigned_url_.*|.*_presigned_url|azure_sas_mint)$/i
const OWN_ORG_AUTH_OR_LOGIC_RE = /^(?:auth_bypass|authentication_bypass|broken_auth|business_logic|workflow_bypass|workflow_skip|invariant_violation)$/i
const OWN_ORG_BUSINESS_LOGIC_RE = /^business_logic$/i
const OWN_ORG_SENSITIVE_READ_PATH_RE = /(?:^|\/)(?:vault|audit|secrets?|credentials?|keys?|tokens?|admin|owner|internal|treasury|backups?)(?:\/|$)/i
const OWN_ORG_PRIVILEGED_WRITE_PATH_RE = /(?:^|\/)(?:admin|owner|internal|vault|scim|webhooks?|roles?|permissions?|secrets?|credentials?|keys?|tokens?)(?:\/|$)/i
const OWN_ORG_INVITE_PATH_RE = /(?:^|\/)invites?(?:\/|$)/i
const OWN_ORG_SINGLE_ITEM_TAIL_RE = /^(?:content|download|raw|file|blob|body|secret|secrets|export|approve|reject|rebind|settle|settle-race|capture|refund|revoke|rotate|promote|demote|delete|cancel|sync|verify|redeem|resolve|callback|webhook|execute|run|trigger|commit|finalize|transfer|withdraw|deploy|publish|impersonate|escalate)$/i
const OWN_ORG_TENANT_SCOPE_PATH_RE = /(?:^|\/)(?:orgs?|organizations?|tenants?|workspaces?)\/([^/]+)/i
const OWN_ORG_PAGINATION_KEY_RE = /^(?:next_?(?:page_?)?token|prev(?:ious)?_?(?:page_?)?token|page_?token|continuation_?token|resume_?token|scroll_?token|sync_?token|cursor_?token|cursor|next_?cursor|prev_?cursor)$/i
const OWN_ORG_SENSITIVE_WORD_RE = /^(?:secret|secrets|password|passwd|private|credential|credentials|apikey|api_key|vault|audit|token|tokens|signing|canary|ssn|card|iban|private_key|access_token|refresh_token|auth_token|session_token|id_token|bearer_token)$/i
const OWN_ORG_SLUG_RE = /\bslug=([a-z0-9][a-z0-9._-]{0,63})/i
const OWN_ORG_DYNAMIC_SEG_RE = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?=[0-9a-f]*\d)[0-9a-f]{8,}|[0-9a-f]{16,}|(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{8,}|[a-z]+[_-][a-z0-9_-]*\d[a-z0-9_-]*|:id|<scrubbed>)$/i

const actorOfGuardEntry = (e: HydratableEntry): string | null =>
  e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)

function normalizeGuardPath(raw: string | null | undefined): string {
  const base = (raw ?? '').split(/[?#]/, 1)[0]!.replace(/\/+$/, '').toLowerCase()
  if (!base) return ''
  const stack: string[] = []
  for (const rawSeg of base.split('/')) {
    if (!rawSeg) continue
    let seg = rawSeg
    if (seg.includes('%')) { try { seg = decodeURIComponent(seg) } catch { /* keep raw */ } }
    seg = seg.split(';', 1)[0]!.trim().toLowerCase()
    if (!seg || seg === '.') continue
    if (seg === '..') { stack.pop(); continue }
    stack.push(seg)
  }
  return stack.length > 0 ? '/' + stack.join('/') : '/'
}

function isSensitivePayloadKey(key: string): boolean {
  const lk = key.trim().toLowerCase()
  if (!lk || OWN_ORG_PAGINATION_KEY_RE.test(lk)) return false
  const norm = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
  if (OWN_ORG_PAGINATION_KEY_RE.test(norm)) return false
  if (OWN_ORG_SENSITIVE_WORD_RE.test(norm)) return true
  return norm.split(/[^a-z0-9]+/).filter(Boolean).some(w => OWN_ORG_SENSITIVE_WORD_RE.test(w))
}

function isNonSensitiveCollectionPayload(parsed: unknown): boolean {
  if (Array.isArray(parsed)) return true
  if (!parsed || typeof parsed !== 'object') return false
  let hasArray = false, hasSensitive = false, visited = 0
  const walk = (node: unknown, depth: number): void => {
    if (hasSensitive || depth > 3 || visited > 128 || !node || typeof node !== 'object') return
    if (Array.isArray(node)) { hasArray = true; return }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      visited += 1
      if (isSensitivePayloadKey(k)) { hasSensitive = true; return }
      if (Array.isArray(v)) hasArray = true
      else if (v && typeof v === 'object' && depth < 3) walk(v, depth + 1)
    }
  }
  walk(parsed, 0)
  return hasArray && !hasSensitive
}

/** Generic fail-closed guard rejecting own-org directory/invite/collection GETs and plain own-org POST creates without verified impact. */
export function evaluateOwnOrgTerminalGuard(params: {
  normCls: string
  contract: OracleTerminalContractKind | null
  isPrivEscCls: boolean
  isCrossTenantCls: boolean
  termEx: HydratableEntry | undefined
  terminalCtrl: HydratableEntry | undefined
  attackerTenants: ReadonlySet<string>
  personaRoleLabels?: Readonly<Record<string, string>>
  ownTenantOnly: boolean
  hasForeignTenantData: boolean
  hasPostMutation: boolean
  hasV8Oracle: boolean
  isReadOnlyDir: boolean
  hasTermDerivedCrypto: boolean
  hasVerifiedTermStateTransition: boolean
  hasVerifiedTermValueBinding: boolean
}): string | null {
  if (params.hasV8Oracle || params.hasPostMutation || !params.termEx) return null
  const isAccessOrLogic = (params.contract === 'access_control' && !OWN_ORG_ACCESS_CONTRACT_EXEMPT_RE.test(params.normCls))
    || OWN_ORG_AUTH_OR_LOGIC_RE.test(params.normCls)
  if (!params.isPrivEscCls && !params.isCrossTenantCls && !isAccessOrLogic) return null
  if (params.isReadOnlyDir) {
    return 'terminal_impact_unproven: privilege_escalation/bfla/cross-tenant/access-control/business-logic cannot confirm on a read-only directory/roster/metadata listing GET without private payload content, a state-mutating terminal action + postChainReadbackExchangeIds, or a verified v8 oracle family.'
  }

  const cleanPath = normalizeGuardPath(params.termEx.step.route ?? params.termEx.step.pathAndQuery)
  const termActor = actorOfGuardEntry(params.termEx), ctrlActor = params.terminalCtrl ? actorOfGuardEntry(params.terminalCtrl) : null
  const ownTokens = new Set<string>(params.attackerTenants)
  for (const lbl of [params.termEx.actorRoleLabel, termActor ? params.personaRoleLabels?.[termActor] : undefined, ctrlActor ? params.personaRoleLabels?.[ctrlActor] : undefined]) {
    const sm = lbl ? OWN_ORG_SLUG_RE.exec(lbl) : null
    if (sm?.[1]) ownTokens.add(sm[1].toLowerCase())
  }
  const scopeMatch = cleanPath ? OWN_ORG_TENANT_SCOPE_PATH_RE.exec(cleanPath) : null
  const scopeTenant = scopeMatch?.[1]?.toLowerCase() ?? null
  const pathTargetsOwnTenant = Boolean(!params.hasForeignTenantData && scopeTenant && ownTokens.has(scopeTenant))
  const pathTargetsForeignTenant = Boolean(scopeTenant && ownTokens.size > 0 && !ownTokens.has(scopeTenant))
  const ownOrgScoped = params.ownTenantOnly || pathTargetsOwnTenant

  const ctrlStatus = params.terminalCtrl?.step.status ?? null
  const ctrlAuthzDenied = ctrlStatus === 401 || ctrlStatus === 403 || ctrlStatus === 409 || ctrlStatus === 412 || ctrlStatus === 422
  const hasEscalatedCapDelta = Boolean(
    params.hasVerifiedTermValueBinding && ctrlAuthzDenied
    && (Boolean(termActor?.startsWith('cap:')) || (params.termEx.consumedCapabilities?.length ?? 0) > 0)
    && termActor !== ctrlActor,
  )

  const segs = cleanPath.split('/').filter(Boolean)
  const lastSeg = segs[segs.length - 1] ?? ''
  if (stepReadsState(params.termEx.step) && !OWN_ORG_SENSITIVE_READ_PATH_RE.test(cleanPath)) {
    let parsed = params.termEx.step.json
    if (parsed === undefined && typeof params.termEx.step.body === 'string' && /^[\[{]/.test(params.termEx.step.body.trim())) {
      try { parsed = JSON.parse(params.termEx.step.body) } catch { parsed = undefined }
    }
    const isCollectionPayload = isNonSensitiveCollectionPayload(parsed)
    const isInvitePath = Boolean(cleanPath && OWN_ORG_INVITE_PATH_RE.test(cleanPath))
    const isCollectionPath = Boolean(lastSeg && !OWN_ORG_DYNAMIC_SEG_RE.test(lastSeg) && !OWN_ORG_SINGLE_ITEM_TAIL_RE.test(lastSeg))
    const unattributedOwnCollection = !params.hasForeignTenantData && !pathTargetsForeignTenant && params.attackerTenants.size > 0 && !hasEscalatedCapDelta && isCollectionPath && isCollectionPayload
    if ((ownOrgScoped && (isInvitePath || (isCollectionPath && isCollectionPayload))) || unattributedOwnCollection) {
      return 'terminal_impact_unproven: own-org directory/invite/collection GET listing is non-terminal impact without foreign-tenant exposure, a state-mutating terminal action + postChainReadbackExchangeIds, or a verified v8 oracle family.'
    }
  }

  const hasNonScopeDynamicSeg = segs.some((seg, i) => {
    const prev = i > 0 ? segs[i - 1]! : ''
    return !/^(?:orgs?|organizations?|tenants?|workspaces?)$/i.test(prev) && OWN_ORG_DYNAMIC_SEG_RE.test(seg)
  })
  const isPlainCollectionCreate = params.termEx.step.method.toUpperCase() === 'POST'
    && !OWN_ORG_PRIVILEGED_WRITE_PATH_RE.test(cleanPath)
    && !hasNonScopeDynamicSeg
    && !OWN_ORG_SINGLE_ITEM_TAIL_RE.test(lastSeg)
  const unattributedOwnCreate = ownOrgScoped || (!params.hasForeignTenantData && !pathTargetsForeignTenant && !params.isCrossTenantCls)
  if (unattributedOwnCreate && isPlainCollectionCreate && ((isAccessOrLogic && !params.hasTermDerivedCrypto && !params.hasVerifiedTermStateTransition) || (params.isPrivEscCls && !params.hasTermDerivedCrypto && !params.hasVerifiedTermStateTransition && !hasEscalatedCapDelta))) {
    return 'terminal_impact_unproven: plain own-org POST resource creation requires a verified v8 oracle family, postChainReadbackExchangeIds proving unauthorized persisted impact, forged cryptographic signature, or verified state_transition_binding.'
  }

  if (!ownOrgScoped) return null
  if (OWN_ORG_BUSINESS_LOGIC_RE.test(params.normCls)) {
    const hasExplicitDelta = !stepReadsState(params.termEx.step) && !isPlainCollectionCreate && ctrlAuthzDenied
      && (params.hasTermDerivedCrypto || params.hasVerifiedTermStateTransition || hasEscalatedCapDelta)
    if (!hasExplicitDelta) {
      return 'terminal_impact_unproven: own-org business_logic without postChainReadbackExchangeIds requires a verified v8 oracle family (e.g. economic_conservation) or an explicit forged-signature, state-transition, or escalated-credential mutation delta on the same resource.'
    }
  }
  return null
}
