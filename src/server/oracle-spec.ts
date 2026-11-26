/**
 * Authoritative Typed OracleSpec Registry & Admission Contract (`R3-13`).
 *
 * Single source of truth for confirmation-kernel oracle identity, CWE ownership,
 * strongest-wins `labelToOracle()` resolution, terminal contract mapping, impact-class
 * alignment, boundary classification, and claim-evaluator dispatch.
 *
 * Pure leaf module (zero runtime imports from other `src/server/*` modules) so every
 * confirmation-kernel file (`terminal-oracle-registry.ts`, `proof-receipt.ts`,
 * `v8-oracle-hydrate.ts`, `oracle-invariants.ts`, `verify-claims.ts`) derives directly
 * from this registry without introducing import cycles or parallel regex ladders.
 */

export type OracleRuleId =
  | 'impact'
  | 'oob'
  | 'timing'
  | 'boolean'
  | 'status_differential'
  | 'browser'
  | 'redirect'
  | 'conserved_balance'
  | 'auth_bypass'
  | 'webhook'

export type V8OracleFamilyId =
  | 'dual_tenant_abac'
  | 'temporal_revocation'
  | 'economic_conservation'
  | 'cryptographic_scope_replay'
  | 'parser_cache_differential'
  | 'cross_surface_pivot'

export type OracleImpactClass =
  | 'authorization'
  | 'bfla'
  | 'mass_assignment'
  | 'csrf'
  | 'business_logic'
  | 'markup'
  | 'disclosure'
  | 'injection'
  | 'other'

export type OracleBoundaryClass = 'auth' | 'access' | 'mfa' | 'other'

export type OracleTerminalContractKind =
  | 'v8_dual_tenant'
  | 'v8_temporal'
  | 'v8_economic'
  | 'v8_crypto'
  | 'v8_parser_cache'
  | 'v8_pivot'
  | 'access_control'
  | 'auth_or_logic'
  | 'oob'
  | 'browser'
  | 'injection_or_redirect'

export type OracleBindingKind =
  | 'nonce'
  | 'persona_tenant'
  | 'canary'
  | 'host_challenge'
  | 'crypto_signature'
  | 'state_ledger'
  | 'none_ticketed'

export type OracleInputProvenance = 'host_observed' | 'host_minted' | 'worker_citation'

export type OracleReflectionPolicy =
  | 'anti_reflection_required'
  | 'executable_context_only'
  | 'not_applicable'

export type OraclePublicnessPolicy = 'non_public_required' | 'not_applicable'

export type OracleClaimKind =
  | 'oob'
  | 'timing'
  | 'structural_diff'
  | 'race'
  | 'impact'
  | 'boundary'
  | 'mfa'
  | 'dom_sentinel'
  | 'composite_receipt'
  | 'host_evaluated_expression'

export type OracleSpecKind = 'single_hop' | 'v8_family'

export interface OracleInputSpec {
  readonly name: string
  readonly provenance: OracleInputProvenance
  readonly required: boolean
}

export interface OracleControlSpec {
  readonly kind: string
  readonly description: string
}

export interface OracleArchetypeExemption {
  readonly archetype: string
  readonly ticket: string
  readonly reason: string
  readonly expires: string
}

export interface OracleEvidenceAlignment {
  readonly key: string
  readonly vulnClass: string
  readonly cwe: string
  readonly category: string
  readonly cweNumbers: readonly number[]
}

export interface OracleSpec {
  readonly id: string
  readonly kind: OracleSpecKind
  readonly singleHopRule?: OracleRuleId
  readonly v8Family?: V8OracleFamilyId
  readonly impactClass?: Exclude<OracleImpactClass, 'other'>
  readonly canonicalVulnClass: string
  readonly cwes: readonly string[]
  readonly labels: readonly string[]
  readonly labelPrefixes?: readonly string[]
  readonly terminalContract: OracleTerminalContractKind
  readonly boundaryClass: OracleBoundaryClass
  readonly descriptorImpactClass: OracleImpactClass | null
  /** Optional per-label overrides for `classifyImpactDescriptor` (e.g. `path_traversal` stays `'other'`). */
  readonly descriptorImpactLabelOverrides?: Readonly<Record<string, OracleImpactClass>>
  /** Optional evidence-class alignment metadata (`IMPACT_CLASS_LABELS` / `IMPACT_CLASS_CWES`). */
  readonly evidenceAlignment?: OracleEvidenceAlignment
  readonly claimKinds: readonly OracleClaimKind[]
  /** Higher rank = stricter evidence bar. `labelToOracle()` ALWAYS selects highest rank (never weakest). */
  readonly strictnessRank: number
  readonly inputs: readonly OracleInputSpec[]
  readonly controls: readonly OracleControlSpec[]
  readonly bindingKind: OracleBindingKind
  readonly bindingTicket?: string
  readonly reflectionPolicy: OracleReflectionPolicy
  readonly publicnessPolicy: OraclePublicnessPolicy
  readonly archetypeExemptions: readonly OracleArchetypeExemption[]
}

export interface LabelToOracleQuery {
  readonly label?: string | null
  readonly vulnClass?: string | null
  readonly labels?: readonly string[]
  readonly cwe?: string | null
  readonly cwes?: readonly string[]
  readonly claimKind?: OracleClaimKind | null
  readonly terminalVulnClass?: string | null
  readonly oobEventIds?: readonly string[]
  readonly scope?: 'all' | 'single_hop' | 'v8_family'
  /** Promote exact matches to the canonical strongest spec sharing the matched spec's primary CWE. */
  readonly canonical?: boolean
}

export interface OracleSpecAdmissionError {
  readonly field: string
  readonly message: string
}

const VALID_CWE_RE = /^CWE-[1-9]\d*$/
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/
const VALID_SINGLE_HOP_RULES = new Set<OracleRuleId>([
  'impact',
  'oob',
  'timing',
  'boolean',
  'status_differential',
  'browser',
  'redirect',
  'conserved_balance',
  'auth_bypass',
  'webhook',
])
const VALID_V8_FAMILIES = new Set<V8OracleFamilyId>([
  'dual_tenant_abac',
  'temporal_revocation',
  'economic_conservation',
  'cryptographic_scope_replay',
  'parser_cache_differential',
  'cross_surface_pivot',
])
const VALID_PROVENANCE = new Set<OracleInputProvenance>(['host_observed', 'host_minted', 'worker_citation'])
const VALID_BINDING_KINDS = new Set<OracleBindingKind>([
  'nonce',
  'persona_tenant',
  'canary',
  'host_challenge',
  'crypto_signature',
  'state_ledger',
  'none_ticketed',
])
const VALID_REFLECTION = new Set<OracleReflectionPolicy>([
  'anti_reflection_required',
  'executable_context_only',
  'not_applicable',
])
const VALID_PUBLICNESS = new Set<OraclePublicnessPolicy>(['non_public_required', 'not_applicable'])

/** Normalize a CWE token (e.g. `"cwe-89"` or `"CWE-89"`) to `"CWE-89"`, or null when invalid. */
export function normalizeOracleCwe(raw: string | null | undefined): string | null {
  if (!raw) return null
  const trimmed = raw.trim().toUpperCase()
  return VALID_CWE_RE.test(trimmed) ? trimmed : null
}

/** Validate an `OracleSpec` against the R3-13 admission contract. Returns all violations. */
export function validateOracleSpec(spec: OracleSpec): OracleSpecAdmissionError[] {
  const errors: OracleSpecAdmissionError[] = []
  if (!spec.id || !/^[a-z0-9][a-z0-9:_-]{1,63}$/.test(spec.id)) {
    errors.push({ field: 'id', message: `Invalid oracle spec id "${spec.id}".` })
  }
  if (spec.kind === 'single_hop') {
    if (!spec.singleHopRule || !VALID_SINGLE_HOP_RULES.has(spec.singleHopRule)) {
      errors.push({ field: 'singleHopRule', message: `single_hop spec "${spec.id}" requires a valid singleHopRule.` })
    }
    if (spec.v8Family !== undefined) {
      errors.push({ field: 'v8Family', message: `single_hop spec "${spec.id}" must not declare v8Family.` })
    }
    if (spec.singleHopRule === 'impact' && !spec.impactClass) {
      errors.push({ field: 'impactClass', message: `impact spec "${spec.id}" requires an impactClass.` })
    }
  } else if (spec.kind === 'v8_family') {
    if (!spec.v8Family || !VALID_V8_FAMILIES.has(spec.v8Family)) {
      errors.push({ field: 'v8Family', message: `v8_family spec "${spec.id}" requires a valid v8Family.` })
    }
    if (spec.singleHopRule !== undefined) {
      errors.push({ field: 'singleHopRule', message: `v8_family spec "${spec.id}" must not declare singleHopRule.` })
    }
  } else {
    errors.push({ field: 'kind', message: `Unsupported oracle spec kind "${String(spec.kind)}".` })
  }
  if (!spec.canonicalVulnClass || !spec.canonicalVulnClass.trim()) {
    errors.push({ field: 'canonicalVulnClass', message: `Spec "${spec.id}" requires a non-empty canonicalVulnClass.` })
  }
  if (!Array.isArray(spec.cwes) || spec.cwes.length === 0) {
    errors.push({ field: 'cwes', message: `Spec "${spec.id}" must declare at least one canonical CWE.` })
  } else {
    for (const cwe of spec.cwes) {
      if (!VALID_CWE_RE.test(cwe)) {
        errors.push({ field: 'cwes', message: `Spec "${spec.id}" declares invalid CWE "${cwe}".` })
      }
    }
  }
  if (!Array.isArray(spec.labels) || spec.labels.length === 0) {
    errors.push({ field: 'labels', message: `Spec "${spec.id}" must declare at least one lowercase label.` })
  } else {
    for (const label of spec.labels) {
      if (!label || label !== label.trim().toLowerCase()) {
        errors.push({ field: 'labels', message: `Spec "${spec.id}" label "${label}" must be trimmed lowercase.` })
      }
    }
  }
  if (!Number.isInteger(spec.strictnessRank) || spec.strictnessRank < 1 || spec.strictnessRank > 100) {
    errors.push({ field: 'strictnessRank', message: `Spec "${spec.id}" strictnessRank must be an integer in 1..100.` })
  }
  if (!Array.isArray(spec.inputs) || spec.inputs.length === 0) {
    errors.push({ field: 'inputs', message: `Spec "${spec.id}" must declare input provenance.` })
  } else {
    let hasHostInput = false
    for (const inp of spec.inputs) {
      if (!inp.name || !inp.name.trim()) {
        errors.push({ field: 'inputs', message: `Spec "${spec.id}" has an unnamed input.` })
      }
      if (!VALID_PROVENANCE.has(inp.provenance)) {
        errors.push({ field: 'inputs', message: `Spec "${spec.id}" input "${inp.name}" has invalid provenance.` })
      }
      if (inp.provenance === 'host_observed' || inp.provenance === 'host_minted') hasHostInput = true
    }
    if (!hasHostInput) {
      errors.push({ field: 'inputs', message: `Spec "${spec.id}" must declare at least one host_observed or host_minted input.` })
    }
  }
  if (!Array.isArray(spec.controls) || spec.controls.length === 0) {
    errors.push({ field: 'controls', message: `Spec "${spec.id}" must declare at least one legitimate negative control.` })
  } else {
    for (const ctl of spec.controls) {
      if (!ctl.kind.trim() || !ctl.description.trim()) {
        errors.push({ field: 'controls', message: `Spec "${spec.id}" has an incomplete control declaration.` })
      }
    }
  }
  if (!VALID_BINDING_KINDS.has(spec.bindingKind)) {
    errors.push({ field: 'bindingKind', message: `Spec "${spec.id}" declares invalid bindingKind "${String(spec.bindingKind)}".` })
  } else if (spec.bindingKind === 'none_ticketed' && (!spec.bindingTicket || !spec.bindingTicket.trim())) {
    errors.push({ field: 'bindingTicket', message: `Spec "${spec.id}" with bindingKind=none_ticketed requires a non-empty bindingTicket.` })
  }
  if (!VALID_REFLECTION.has(spec.reflectionPolicy)) {
    errors.push({ field: 'reflectionPolicy', message: `Spec "${spec.id}" declares invalid reflectionPolicy.` })
  }
  if (!VALID_PUBLICNESS.has(spec.publicnessPolicy)) {
    errors.push({ field: 'publicnessPolicy', message: `Spec "${spec.id}" declares invalid publicnessPolicy.` })
  }
  for (const ex of spec.archetypeExemptions ?? []) {
    if (!ex.archetype.trim() || !ex.ticket.trim() || !ex.reason.trim() || !ISO_DATE_RE.test(ex.expires)) {
      errors.push({ field: 'archetypeExemptions', message: `Spec "${spec.id}" has an invalid archetype exemption.` })
    }
  }
  return errors
}

function freezeSpec(spec: OracleSpec): OracleSpec {
  return Object.freeze({
    ...spec,
    cwes: Object.freeze([...spec.cwes]),
    labels: Object.freeze([...spec.labels]),
    ...(spec.labelPrefixes ? { labelPrefixes: Object.freeze([...spec.labelPrefixes]) } : {}),
    ...(spec.descriptorImpactLabelOverrides
      ? { descriptorImpactLabelOverrides: Object.freeze({ ...spec.descriptorImpactLabelOverrides }) }
      : {}),
    ...(spec.evidenceAlignment
      ? {
          evidenceAlignment: Object.freeze({
            ...spec.evidenceAlignment,
            cweNumbers: Object.freeze([...spec.evidenceAlignment.cweNumbers]),
          }),
        }
      : {}),
    claimKinds: Object.freeze([...spec.claimKinds]),
    inputs: Object.freeze(spec.inputs.map(i => Object.freeze({ ...i }))),
    controls: Object.freeze(spec.controls.map(c => Object.freeze({ ...c }))),
    archetypeExemptions: Object.freeze(spec.archetypeExemptions.map(e => Object.freeze({ ...e }))),
  })
}

export class OracleSpecRegistry {
  private readonly byId = new Map<string, OracleSpec>()
  private readonly byLabel = new Map<string, OracleSpec[]>()
  private readonly byCwe = new Map<string, OracleSpec[]>()
  private readonly prefixSpecs: OracleSpec[] = []
  private sealed = false

  register(spec: OracleSpec): OracleSpec {
    if (this.sealed) {
      throw new Error(`OracleSpecRegistry is sealed; cannot register "${spec.id}" after initialization.`)
    }
    const errors = validateOracleSpec(spec)
    if (errors.length > 0) {
      throw new Error(`OracleSpec admission failed for "${spec.id}": ${errors.map(e => `${e.field}: ${e.message}`).join('; ')}`)
    }
    if (this.byId.has(spec.id)) {
      throw new Error(`OracleSpec "${spec.id}" is already registered.`)
    }
    const frozen = freezeSpec(spec)
    this.byId.set(frozen.id, frozen)
    for (const label of frozen.labels) {
      const list = this.byLabel.get(label) ?? []
      list.push(frozen)
      this.byLabel.set(label, list)
    }
    if (frozen.labelPrefixes?.length) {
      this.prefixSpecs.push(frozen)
    }
    for (const cwe of frozen.cwes) {
      const list = this.byCwe.get(cwe) ?? []
      list.push(frozen)
      this.byCwe.set(cwe, list)
    }
    return frozen
  }

  seal(): this {
    this.sealed = true
    return this
  }

  get(id: string): OracleSpec | undefined {
    return this.byId.get(id)
  }

  list(): readonly OracleSpec[] {
    return [...this.byId.values()]
  }

  listSingleHopRules(): readonly OracleRuleId[] {
    const out: OracleRuleId[] = []
    const seen = new Set<OracleRuleId>()
    for (const spec of this.byId.values()) {
      if (spec.kind === 'single_hop' && spec.singleHopRule && !seen.has(spec.singleHopRule)) {
        seen.add(spec.singleHopRule)
        out.push(spec.singleHopRule)
      }
    }
    return out
  }

  listV8Families(): readonly V8OracleFamilyId[] {
    const out: V8OracleFamilyId[] = []
    const seen = new Set<V8OracleFamilyId>()
    for (const spec of this.byId.values()) {
      if (spec.kind === 'v8_family' && spec.v8Family && !seen.has(spec.v8Family)) {
        seen.add(spec.v8Family)
        out.push(spec.v8Family)
      }
    }
    return out
  }

  private specsForLabel(normLabel: string): OracleSpec[] {
    const out: OracleSpec[] = []
    const direct = this.byLabel.get(normLabel)
    if (direct) out.push(...direct)
    for (const spec of this.prefixSpecs) {
      if (spec.labelPrefixes?.some(prefix => normLabel.startsWith(prefix)) && !out.includes(spec)) {
        out.push(spec)
      }
    }
    return out
  }

  /**
   * Resolve any vulnerability label, CWE, claim kind, or composite terminal to the single
   * canonical **strongest** `OracleSpec` (highest `strictnessRank`, NEVER weakest).
   */
  resolve(input: string | LabelToOracleQuery): OracleSpec | null {
    const query: LabelToOracleQuery = typeof input === 'string' ? { label: input } : input
    const scope = query.scope ?? 'all'
    const rawLabels = [
      ...(query.label ? [query.label] : []),
      ...(query.vulnClass ? [query.vulnClass] : []),
      ...(query.terminalVulnClass ? [query.terminalVulnClass] : []),
      ...(query.labels ?? []),
    ]
    const rawCwes = [
      ...(query.cwe ? [query.cwe] : []),
      ...(query.cwes ?? []),
    ]

    const normLabels: string[] = []
    const normCwes: string[] = []
    for (const raw of rawLabels) {
      const trimmed = raw.trim()
      if (!trimmed) continue
      const asCwe = normalizeOracleCwe(trimmed)
      if (asCwe) normCwes.push(asCwe)
      else normLabels.push(trimmed.toLowerCase())
    }
    for (const raw of rawCwes) {
      const c = normalizeOracleCwe(raw)
      if (c) normCwes.push(c)
    }

    const inScope = (spec: OracleSpec): boolean =>
      scope === 'all' || (scope === 'single_hop' ? spec.kind === 'single_hop' : spec.kind === 'v8_family')

    const exactMatches = new Set<OracleSpec>()
    const candidates = new Set<OracleSpec>()

    for (const label of normLabels) {
      // Webhook forgery selects inline signature differential (`webhook`) ONLY when the receipt
      // explicitly carries zero OOB events and no CWE/stronger label promotes it.
      if (label === 'webhook_forgery' && query.oobEventIds !== undefined && query.oobEventIds.length === 0 && normLabels.length === 1 && normCwes.length === 0 && !query.canonical) {
        const wh = this.byId.get('webhook')
        if (wh && inScope(wh)) {
          exactMatches.add(wh)
          candidates.add(wh)
          continue
        }
      }
      for (const spec of this.specsForLabel(label)) {
        if (!inScope(spec)) continue
        exactMatches.add(spec)
        candidates.add(spec)
        if (query.canonical && spec.cwes[0]) {
          for (const sibling of this.byCwe.get(spec.cwes[0]) ?? []) {
            if (inScope(sibling)) candidates.add(sibling)
          }
        }
      }
    }

    for (const cwe of normCwes) {
      for (const spec of this.byCwe.get(cwe) ?? []) {
        if (inScope(spec)) candidates.add(spec)
      }
    }

    if (candidates.size === 0 && query.claimKind) {
      for (const spec of this.byId.values()) {
        if (inScope(spec) && spec.claimKinds.includes(query.claimKind)) {
          candidates.add(spec)
        }
      }
    }

    if (candidates.size === 0) return null

    let best: OracleSpec | null = null
    for (const cand of candidates) {
      if (!best) {
        best = cand
        continue
      }
      if (cand.strictnessRank !== best.strictnessRank) {
        if (cand.strictnessRank > best.strictnessRank) best = cand
        continue
      }
      const candExact = exactMatches.has(cand) ? 1 : 0
      const bestExact = exactMatches.has(best) ? 1 : 0
      if (candExact !== bestExact) {
        if (candExact > bestExact) best = cand
        continue
      }
      const candPrimaryCwe = cand.cwes[0] && normCwes.includes(cand.cwes[0]) ? 1 : 0
      const bestPrimaryCwe = best.cwes[0] && normCwes.includes(best.cwes[0]) ? 1 : 0
      if (candPrimaryCwe !== bestPrimaryCwe) {
        if (candPrimaryCwe > bestPrimaryCwe) best = cand
        continue
      }
      if (cand.id.localeCompare(best.id) < 0) best = cand
    }
    return best
  }

  /** Return all sibling labels sharing at least one CWE with the given label or CWE. */
  sameCweSiblingLabels(labelOrCwe: string, scope: 'all' | 'single_hop' | 'v8_family' = 'single_hop'): readonly string[] {
    const asCwe = normalizeOracleCwe(labelOrCwe)
    const cwes = new Set<string>()
    if (asCwe) {
      cwes.add(asCwe)
    } else {
      const matched = this.resolve({ label: labelOrCwe, scope })
      if (matched) {
        for (const c of matched.cwes) cwes.add(c)
      }
    }
    const labels = new Set<string>()
    for (const cwe of cwes) {
      for (const spec of this.byCwe.get(cwe) ?? []) {
        if (scope !== 'all' && ((scope === 'single_hop') !== (spec.kind === 'single_hop'))) continue
        for (const label of spec.labels) labels.add(label)
      }
    }
    return [...labels].sort()
  }
}

export function createOracleSpecRegistry(): OracleSpecRegistry {
  return new OracleSpecRegistry()
}

export function registerOracle(spec: OracleSpec, registry: OracleSpecRegistry = DEFAULT_ORACLE_SPEC_REGISTRY): OracleSpec {
  return registry.register(spec)
}

const BUILTIN_ORACLE_SPECS: readonly OracleSpec[] = [
  // ---- Single-hop Impact sub-oracles (rule: 'impact') ----
  {
    id: 'impact:authorization',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'authorization',
    canonicalVulnClass: 'bola',
    cwes: ['CWE-639', 'CWE-284', 'CWE-862', 'CWE-863', 'CWE-566', 'CWE-1220'],
    labels: [
      'bola',
      'idor',
      'authorization',
      'broken-access-control',
      'broken_access_control',
      'access_control',
      'authz_bypass',
      'authorization_bypass',
      'authz_escalation',
      'cross_tenant',
      'cross_tenant_read',
      'cross_tenant_write',
      'cross_tenant_export',
      'cross_tenant_document_read',
      'cross_tenant_exfiltration',
      'cross_tenant_repo_theft',
      'cross_tenant_secret_read',
      'cross_tenant_partner_export',
      'cross_tenant_admin_takeover',
      'cross_tenant_chain',
      'cache_tenant_bleed',
      'graphql_bola',
    ],
    terminalContract: 'access_control',
    boundaryClass: 'access',
    descriptorImpactClass: 'authorization',
    evidenceAlignment: {
      key: 'bola',
      vulnClass: 'bola',
      cwe: 'CWE-639',
      category: 'broken-access-control',
      cweNumbers: [639],
    },
    claimKinds: ['impact', 'boundary'],
    strictnessRank: 80,
    inputs: [
      { name: 'host_exchanges', provenance: 'host_observed', required: true },
      { name: 'persona_identities', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'owner_or_anon_baseline', description: 'Same-route entitled owner control plus unauthenticated publicness probe.' },
    ],
    bindingKind: 'persona_tenant',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'impact:signed_url_mint',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'authorization',
    canonicalVulnClass: 'signed_url_mint',
    cwes: ['CWE-639', 'CWE-284', 'CWE-863'],
    labels: [
      'signed_url_mint',
      'presigned_url_mint',
      'signed_url_traversal',
      'storage_signed_url',
      'gcs_signed_url',
      's3_presigned_url',
      'azure_sas_mint',
    ],
    terminalContract: 'access_control',
    boundaryClass: 'access',
    descriptorImpactClass: 'authorization',
    claimKinds: ['impact', 'composite_receipt'],
    strictnessRank: 90,
    inputs: [
      { name: 'control_and_probe_exchanges', provenance: 'host_observed', required: true },
      { name: 'wire_credential_provenance', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'same_tenant_mint_control', description: 'Authorized own-scope signed URL mint paired against foreign-scope mint.' },
    ],
    bindingKind: 'crypto_signature',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'impact:bfla',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'bfla',
    canonicalVulnClass: 'bfla',
    cwes: ['CWE-285', 'CWE-269', 'CWE-862', 'CWE-863'],
    labels: ['bfla', 'privilege_escalation'],
    terminalContract: 'access_control',
    boundaryClass: 'access',
    descriptorImpactClass: 'bfla',
    claimKinds: ['impact', 'boundary'],
    strictnessRank: 85,
    inputs: [
      { name: 'role_differential_exchanges', provenance: 'host_observed', required: true },
      { name: 'actor_privileges', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'higher_role_control', description: 'Higher-role control on the same privileged function surface with read/write boundary check.' },
    ],
    bindingKind: 'persona_tenant',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'impact:mass_assignment',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'mass_assignment',
    canonicalVulnClass: 'mass_assignment',
    cwes: ['CWE-915'],
    labels: ['mass_assignment'],
    terminalContract: 'access_control',
    boundaryClass: 'other',
    descriptorImpactClass: 'mass_assignment',
    evidenceAlignment: {
      key: 'mass_assignment',
      vulnClass: 'mass_assignment',
      cwe: 'CWE-915',
      category: 'mass-assignment',
      cweNumbers: [915],
    },
    claimKinds: ['impact'],
    strictnessRank: 85,
    inputs: [
      { name: 'before_mutate_after_exchanges', provenance: 'host_observed', required: true },
      { name: 'raw_request_payload', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'pre_post_readback_pair', description: 'Pre-mutation readback showing original field value and persisted post-mutation readback.' },
    ],
    bindingKind: 'state_ledger',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'impact:csrf',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'csrf',
    canonicalVulnClass: 'csrf',
    cwes: ['CWE-352'],
    labels: ['csrf'],
    terminalContract: 'access_control',
    boundaryClass: 'other',
    descriptorImpactClass: 'csrf',
    evidenceAlignment: {
      key: 'csrf',
      vulnClass: 'csrf',
      cwe: 'CWE-352',
      category: 'csrf',
      cweNumbers: [352],
    },
    claimKinds: ['impact'],
    strictnessRank: 85,
    inputs: [
      { name: 'ambient_cookie_and_samesite', provenance: 'host_observed', required: true },
      { name: 'before_mutate_after_exchanges', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'pre_post_state_and_cross_site_sendability', description: 'Ambient-cookie cross-site sendable mutation with persisted before/after delta.' },
    ],
    bindingKind: 'state_ledger',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'impact:business_logic',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'business_logic',
    canonicalVulnClass: 'business_logic',
    cwes: ['CWE-840', 'CWE-841', 'CWE-472'],
    labels: [
      'business_logic',
      'invariant_violation',
      'workflow_skip',
      'workflow_bypass',
      'price_tampering',
      'maker_checker_bypass',
      'self_approved_payout',
      'unapproved_prod_release',
      'unauthorized_prod_release',
      'forged_settlement',
      'ledger_overcredit',
      'stale_privilege_use',
      'internal_token_exfiltration',
      'delegated_billing_rebate',
      'split_refund_ledger_break',
    ],
    terminalContract: 'auth_or_logic',
    boundaryClass: 'other',
    descriptorImpactClass: 'business_logic',
    evidenceAlignment: {
      key: 'business_logic',
      vulnClass: 'business_logic',
      cwe: 'CWE-840',
      category: 'business-logic',
      cweNumbers: [840, 841, 472],
    },
    claimKinds: ['impact'],
    strictnessRank: 80,
    inputs: [
      { name: 'state_transition_exchanges', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'legitimate_state_baseline', description: 'Baseline pre-action state readback distinguishing legitimate accumulation from invariant break.' },
    ],
    bindingKind: 'state_ledger',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'impact:markup',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'markup',
    canonicalVulnClass: 'xss_stored',
    cwes: ['CWE-79', 'CWE-80', 'CWE-83'],
    labels: ['xss', 'xss_stored', 'xss_reflected', 'markup', 'html_injection'],
    terminalContract: 'browser',
    boundaryClass: 'other',
    descriptorImpactClass: 'markup',
    evidenceAlignment: {
      key: 'markup',
      vulnClass: 'xss_stored',
      cwe: 'CWE-79',
      category: 'xss',
      cweNumbers: [79, 80, 83],
    },
    claimKinds: ['impact'],
    strictnessRank: 85,
    inputs: [
      { name: 'html_response_and_content_type', provenance: 'host_observed', required: true },
      { name: 'probe_nonce', provenance: 'host_minted', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'benign_control_absent_nonce', description: 'Same-route benign control response lacking the executable nonce context.' },
    ],
    bindingKind: 'nonce',
    reflectionPolicy: 'executable_context_only',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'impact:disclosure',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'disclosure',
    canonicalVulnClass: 'info_disclosure',
    cwes: ['CWE-200', 'CWE-359', 'CWE-522', 'CWE-532'],
    labels: [
      'disclosure',
      'info_disclosure',
      'information_disclosure',
      'secret_disclosed',
      'secret_disclosure',
      'data_exposure',
      'sensitive_data_exposure',
    ],
    terminalContract: 'access_control',
    boundaryClass: 'other',
    descriptorImpactClass: 'disclosure',
    evidenceAlignment: {
      key: 'disclosure',
      vulnClass: 'info_disclosure',
      cwe: 'CWE-200',
      category: 'information-disclosure',
      cweNumbers: [200, 359, 522, 532],
    },
    claimKinds: ['impact'],
    strictnessRank: 75,
    inputs: [
      { name: 'control_and_probe_bodies', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'entitled_or_public_control', description: 'Control arm proving disclosed record is non-public and unreflected.' },
    ],
    bindingKind: 'persona_tenant',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'impact:injection',
    kind: 'single_hop',
    singleHopRule: 'impact',
    impactClass: 'injection',
    canonicalVulnClass: 'sqli_error',
    cwes: ['CWE-74', 'CWE-89', 'CWE-564', 'CWE-943', 'CWE-78', 'CWE-1336', 'CWE-22'],
    labels: [
      'injection',
      'injection-input',
      'injection_input',
      'sqli_error',
      'nosqli',
      'nosql_injection',
      'ssti',
      'template_injection',
      'command_injection',
      'cmdi',
      'rce',
      'path_traversal',
      'directory_traversal',
      'lfi',
    ],
    terminalContract: 'injection_or_redirect',
    boundaryClass: 'other',
    descriptorImpactClass: 'injection',
    descriptorImpactLabelOverrides: {
      path_traversal: 'other',
      directory_traversal: 'other',
      lfi: 'other',
    },
    evidenceAlignment: {
      key: 'injection',
      vulnClass: 'sqli',
      cwe: 'CWE-89',
      category: 'injection',
      cweNumbers: [89, 564, 943],
    },
    claimKinds: ['impact', 'host_evaluated_expression'],
    strictnessRank: 75,
    inputs: [
      { name: 'control_and_probe_exchanges', provenance: 'host_observed', required: true },
      { name: 'host_expression_challenge', provenance: 'host_minted', required: false },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'same_shape_benign_control', description: 'Same-route benign control lacking the engine/dialect error fingerprint or evaluated output.' },
    ],
    bindingKind: 'host_challenge',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },

  // ---- Non-impact Single-Hop Oracles ----
  {
    id: 'oob',
    kind: 'single_hop',
    singleHopRule: 'oob',
    canonicalVulnClass: 'ssrf',
    cwes: ['CWE-918', 'CWE-611'],
    labels: ['ssrf', 'xxe', 'blind_ssrf', 'blind_xxe', 'oob', 'webhook_forgery'],
    terminalContract: 'oob',
    boundaryClass: 'other',
    descriptorImpactClass: 'other',
    claimKinds: ['oob'],
    strictnessRank: 95,
    inputs: [
      { name: 'signed_oob_callback', provenance: 'host_observed', required: true },
      { name: 'minted_canary_token', provenance: 'host_minted', required: true },
      { name: 'carrier_exchange_citation', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'unique_request_carrier_and_timestamp', description: 'Unique request-side carrier with startedAt <= receivedAtMs and host-signed callback.' },
    ],
    bindingKind: 'canary',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'timing',
    kind: 'single_hop',
    singleHopRule: 'timing',
    canonicalVulnClass: 'blind_sqli',
    cwes: ['CWE-89', 'CWE-78', 'CWE-943'],
    labels: ['blind_sqli', 'sqli_time', 'sql_time', 'timing'],
    terminalContract: 'injection_or_redirect',
    boundaryClass: 'other',
    descriptorImpactClass: 'injection',
    claimKinds: ['timing'],
    strictnessRank: 80,
    inputs: [
      { name: 'interleaved_arm_durations', provenance: 'host_observed', required: true },
      { name: 'host_timing_challenge', provenance: 'host_minted', required: true },
      { name: 'arm_exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'interleaved_benign_control_arms', description: 'At least 5 interleaved same-shape benign control exchanges with Mann-Whitney U separation.' },
    ],
    bindingKind: 'host_challenge',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'boolean',
    kind: 'single_hop',
    singleHopRule: 'boolean',
    canonicalVulnClass: 'sqli',
    cwes: ['CWE-89', 'CWE-564', 'CWE-943'],
    labels: ['sqli', 'sql_injection', 'sql_boolean', 'sql_boolean_diff', 'boolean_sqli', 'boolean_differential'],
    terminalContract: 'injection_or_redirect',
    boundaryClass: 'other',
    descriptorImpactClass: 'injection',
    claimKinds: ['structural_diff'],
    strictnessRank: 95,
    inputs: [
      { name: 'three_arm_responses', provenance: 'host_observed', required: true },
      { name: 'host_boolean_pair_stamps', provenance: 'host_minted', required: true },
      { name: 'round_exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'benign_baseline_and_tautology_arms', description: 'Multi-round 3-arm triangle (benign baseline == tautology != contradiction) with host stamps.' },
    ],
    bindingKind: 'host_challenge',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'status_differential',
    kind: 'single_hop',
    singleHopRule: 'status_differential',
    canonicalVulnClass: 'sqli_status',
    cwes: ['CWE-89'],
    labels: ['sqli_status', 'sql_status', 'sql_status_diff', 'status_sqli', 'status_boolean'],
    terminalContract: 'injection_or_redirect',
    boundaryClass: 'other',
    descriptorImpactClass: 'injection',
    claimKinds: ['structural_diff'],
    strictnessRank: 60,
    inputs: [
      { name: 'status_triangle_exchanges', provenance: 'host_observed', required: true },
      { name: 'host_boolean_pair_stamps', provenance: 'host_minted', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'benign_2xx_and_tautology_2xx_controls', description: 'Paired 2xx benign baseline + 2xx tautology + <500 contradiction on identical request shape.' },
    ],
    bindingKind: 'host_challenge',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'browser',
    kind: 'single_hop',
    singleHopRule: 'browser',
    canonicalVulnClass: 'dom_xss',
    cwes: ['CWE-79', 'CWE-80', 'CWE-345'],
    labels: ['dom_xss', 'browser_xss', 'postmessage'],
    labelPrefixes: ['browser_', 'dom_', 'postmessage'],
    terminalContract: 'browser',
    boundaryClass: 'other',
    descriptorImpactClass: 'markup',
    claimKinds: ['dom_sentinel'],
    strictnessRank: 95,
    inputs: [
      { name: 'host_browser_trace', provenance: 'host_observed', required: true },
      { name: 'execution_sentinel_nonce', provenance: 'host_minted', required: true },
      { name: 'trace_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'clean_navigation_control', description: 'Host-recorded browser trace proving live sink execution of minted sentinel.' },
    ],
    bindingKind: 'nonce',
    reflectionPolicy: 'executable_context_only',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'redirect',
    kind: 'single_hop',
    singleHopRule: 'redirect',
    canonicalVulnClass: 'open_redirect',
    cwes: ['CWE-601'],
    labels: ['open_redirect', 'redirect', 'url_redirect', 'unvalidated_redirect'],
    terminalContract: 'injection_or_redirect',
    boundaryClass: 'other',
    descriptorImpactClass: 'other',
    claimKinds: ['impact'],
    strictnessRank: 90,
    inputs: [
      { name: 'redirect_location_header', provenance: 'host_observed', required: true },
      { name: 'host_redirect_canary_host', provenance: 'host_minted', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'same_origin_redirect_control', description: 'Same-route control verifying external Location destination matches host-minted redirect canary.' },
    ],
    bindingKind: 'canary',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'conserved_balance',
    kind: 'single_hop',
    singleHopRule: 'conserved_balance',
    canonicalVulnClass: 'conserved_balance',
    cwes: ['CWE-362', 'CWE-840'],
    labels: [
      'race',
      'race_double_spend',
      'race_condition',
      'race_burst',
      'double_spend',
      'oversell',
      'inventory_oversell',
      'conserved_balance',
      'toctou',
    ],
    terminalContract: 'auth_or_logic',
    boundaryClass: 'other',
    descriptorImpactClass: null,
    claimKinds: ['race'],
    strictnessRank: 92,
    inputs: [
      { name: 'burst_and_serial_exchanges', provenance: 'host_observed', required: true },
      { name: 'baseline_and_post_readbacks', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'serial_control_arm', description: 'Disjoint serial control execution proving invariant holds serially and breaks only under concurrency.' },
    ],
    bindingKind: 'state_ledger',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'auth_bypass',
    kind: 'single_hop',
    singleHopRule: 'auth_bypass',
    canonicalVulnClass: 'auth_bypass',
    cwes: [
      'CWE-287',
      'CWE-288',
      'CWE-290',
      'CWE-294',
      'CWE-302',
      'CWE-303',
      'CWE-305',
      'CWE-306',
      'CWE-346',
      'CWE-347',
      'CWE-384',
      'CWE-620',
      'CWE-798',
    ],
    labels: [
      'auth_bypass',
      'jwt_forgery',
      'broken_auth',
      'auth_protocol',
      'token_forgery',
      'authentication_bypass',
      'jwt',
      'oauth',
      'sso',
      'session_fixation',
    ],
    terminalContract: 'auth_or_logic',
    boundaryClass: 'auth',
    descriptorImpactClass: 'other',
    claimKinds: ['boundary', 'mfa'],
    strictnessRank: 92,
    inputs: [
      { name: 'denied_control_and_bypass_probe', provenance: 'host_observed', required: true },
      { name: 'wire_credential_provenance', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'denied_unauthenticated_control', description: 'Denied 401/403 or login-challenge control on the same protected route.' },
    ],
    bindingKind: 'persona_tenant',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'webhook',
    kind: 'single_hop',
    singleHopRule: 'webhook',
    canonicalVulnClass: 'webhook_forgery',
    cwes: ['CWE-345', 'CWE-347'],
    labels: ['webhook', 'webhook_forgery'],
    terminalContract: 'oob',
    boundaryClass: 'other',
    descriptorImpactClass: 'other',
    claimKinds: ['impact'],
    strictnessRank: 85,
    inputs: [
      { name: 'signed_vs_forged_delivery_exchanges', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'invalid_signature_rejected_control', description: 'Bad/missing webhook signature control rejected while forged/replayed delivery succeeds.' },
    ],
    bindingKind: 'crypto_signature',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },

  // ---- V8 Multi-Hop Extended Oracle Families ----
  {
    id: 'v8:dual_tenant_abac',
    kind: 'v8_family',
    v8Family: 'dual_tenant_abac',
    canonicalVulnClass: 'dual_tenant_abac',
    cwes: ['CWE-639', 'CWE-284', 'CWE-285', 'CWE-862', 'CWE-863'],
    labels: ['dual_tenant_abac'],
    terminalContract: 'v8_dual_tenant',
    boundaryClass: 'access',
    descriptorImpactClass: 'authorization',
    claimKinds: ['composite_receipt'],
    strictnessRank: 98,
    inputs: [
      { name: 'host_signed_tenant_matrix', provenance: 'host_observed', required: true },
      { name: 'composite_hop_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'same_tenant_owner_and_anon_controls', description: 'Host-signed entitled owner read and unauthenticated/foreign controls across tenants.' },
    ],
    bindingKind: 'persona_tenant',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'v8:temporal_revocation',
    kind: 'v8_family',
    v8Family: 'temporal_revocation',
    canonicalVulnClass: 'temporal_revocation',
    cwes: ['CWE-613', 'CWE-384', 'CWE-287'],
    labels: ['temporal_revocation'],
    terminalContract: 'v8_temporal',
    boundaryClass: 'auth',
    descriptorImpactClass: 'other',
    claimKinds: ['composite_receipt'],
    strictnessRank: 98,
    inputs: [
      { name: 'host_monotonic_timestamps', provenance: 'host_observed', required: true },
      { name: 'revocation_and_reuse_exchanges', provenance: 'host_observed', required: true },
      { name: 'composite_hop_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'pre_revocation_and_revocation_confirmation', description: 'Verified revocation event strictly preceding post-revocation protected access.' },
    ],
    bindingKind: 'persona_tenant',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'v8:economic_conservation',
    kind: 'v8_family',
    v8Family: 'economic_conservation',
    canonicalVulnClass: 'economic_conservation',
    cwes: ['CWE-840', 'CWE-362', 'CWE-472'],
    labels: ['economic_conservation'],
    terminalContract: 'v8_economic',
    boundaryClass: 'other',
    descriptorImpactClass: 'business_logic',
    claimKinds: ['composite_receipt'],
    strictnessRank: 98,
    inputs: [
      { name: 'pre_action_post_ledger_readbacks', provenance: 'host_observed', required: true },
      { name: 'composite_hop_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'conservation_equation_baseline', description: 'Host-signed initial and final ledger balances proving strict value conservation violation.' },
    ],
    bindingKind: 'state_ledger',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'v8:cryptographic_scope_replay',
    kind: 'v8_family',
    v8Family: 'cryptographic_scope_replay',
    canonicalVulnClass: 'cryptographic_scope_replay',
    cwes: ['CWE-294', 'CWE-347', 'CWE-345'],
    labels: ['cryptographic_scope_replay'],
    terminalContract: 'v8_crypto',
    boundaryClass: 'auth',
    descriptorImpactClass: 'other',
    claimKinds: ['composite_receipt'],
    strictnessRank: 98,
    inputs: [
      { name: 'capability_lineage_and_artifacts', provenance: 'host_observed', required: true },
      { name: 'composite_hop_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'in_scope_issuance_and_denied_control', description: 'Signed token/artifact issued for scope A rejected without artifact and accepted out-of-scope.' },
    ],
    bindingKind: 'crypto_signature',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
  {
    id: 'v8:parser_cache_differential',
    kind: 'v8_family',
    v8Family: 'parser_cache_differential',
    canonicalVulnClass: 'parser_cache_differential',
    cwes: ['CWE-444', 'CWE-525', 'CWE-524'],
    labels: ['parser_cache_differential', 'cache_poisoning', 'cache_deception'],
    terminalContract: 'v8_parser_cache',
    boundaryClass: 'other',
    descriptorImpactClass: 'other',
    claimKinds: ['composite_receipt'],
    strictnessRank: 98,
    inputs: [
      { name: 'poison_and_victim_exchanges', provenance: 'host_observed', required: true },
      { name: 'host_cache_buster_nonce', provenance: 'host_minted', required: true },
      { name: 'composite_hop_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'clean_victim_baseline', description: 'Pre-poison clean victim response compared against poisoned cache hit for a distinct session.' },
    ],
    bindingKind: 'nonce',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
  },
  {
    id: 'v8:cross_surface_pivot',
    kind: 'v8_family',
    v8Family: 'cross_surface_pivot',
    canonicalVulnClass: 'cross_surface_pivot',
    cwes: ['CWE-284', 'CWE-639', 'CWE-918'],
    labels: ['cross_surface_pivot'],
    terminalContract: 'v8_pivot',
    boundaryClass: 'access',
    descriptorImpactClass: 'other',
    claimKinds: ['composite_receipt'],
    strictnessRank: 98,
    inputs: [
      { name: 'multi_surface_signed_hops', provenance: 'host_observed', required: true },
      { name: 'composite_hop_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'terminal_surface_denied_control', description: 'Direct terminal-surface control proving pivot causality across distinct surfaces.' },
    ],
    bindingKind: 'state_ledger',
    reflectionPolicy: 'anti_reflection_required',
    publicnessPolicy: 'non_public_required',
    archetypeExemptions: [],
  },
]

export const DEFAULT_ORACLE_SPEC_REGISTRY: OracleSpecRegistry = (() => {
  const reg = createOracleSpecRegistry()
  for (const spec of BUILTIN_ORACLE_SPECS) {
    registerOracle(spec, reg)
  }
  return reg.seal()
})()

export const REGISTERED_SINGLE_HOP_RULES: readonly OracleRuleId[] = Object.freeze(
  DEFAULT_ORACLE_SPEC_REGISTRY.listSingleHopRules(),
)

export const REGISTERED_V8_FAMILIES: readonly V8OracleFamilyId[] = Object.freeze(
  DEFAULT_ORACLE_SPEC_REGISTRY.listV8Families(),
)

export const REGISTERED_IMPACT_CLASSES: ReadonlySet<string> = new Set(
  DEFAULT_ORACLE_SPEC_REGISTRY.list()
    .map(s => s.impactClass)
    .filter((v): v is Exclude<OracleImpactClass, 'other'> => Boolean(v)),
)

export function isRegisteredImpactClass(value: string): boolean {
  return REGISTERED_IMPACT_CLASSES.has(value)
}

/**
 * Single authoritative label/CWE/claim-kind resolver.
 * ALWAYS returns the strongest matching `OracleSpec` (highest `strictnessRank`), never a weaker sibling.
 */
export function labelToOracle(
  input: string | LabelToOracleQuery,
  registry: OracleSpecRegistry = DEFAULT_ORACLE_SPEC_REGISTRY,
): OracleSpec | null {
  return registry.resolve(input)
}

/** Authoritative reported CWE derived strictly from `spec.cwes[0]`. */
export function canonicalCweForOracle(
  input: string | LabelToOracleQuery,
  registry: OracleSpecRegistry = DEFAULT_ORACLE_SPEC_REGISTRY,
): string | null {
  return labelToOracle(input, registry)?.cwes[0] ?? null
}

/** Derived single-hop receipt rule resolver (replaces `proof-receipt.ts` regex ladders). */
export function resolveReceiptRule(
  vulnClass: string,
  receipt?: { readonly oobEventIds: readonly string[] },
): { rule: OracleRuleId | 'none'; impactClass?: Exclude<OracleImpactClass, 'other'>; spec?: OracleSpec } {
  const norm = vulnClass.trim().toLowerCase()
  if (!norm) return { rule: 'none' }
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.resolve({
    vulnClass: norm,
    ...(receipt ? { oobEventIds: receipt.oobEventIds } : {}),
    scope: 'single_hop',
  })
  if (!spec || !spec.singleHopRule) return { rule: 'none' }
  return {
    rule: spec.singleHopRule,
    ...(spec.impactClass ? { impactClass: spec.impactClass } : {}),
    spec,
  }
}

export function isSignedUrlMintLabel(vulnClass: string): boolean {
  return DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ vulnClass, scope: 'single_hop' })?.id === 'impact:signed_url_mint'
}

export function isAuthBypassLabel(vulnClass: string): boolean {
  return DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ vulnClass, scope: 'single_hop' })?.id === 'auth_bypass'
}

export function isConservedBalanceLabel(vulnClass: string): boolean {
  return DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ vulnClass, scope: 'single_hop' })?.id === 'conserved_balance'
}

export function isOobLabel(vulnClass: string): boolean {
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ vulnClass, scope: 'single_hop' })
  return spec?.id === 'oob' && vulnClass.trim().toLowerCase() !== 'webhook_forgery'
}

export function resolveImpactClassForLabel(vulnClass: string): Exclude<OracleImpactClass, 'other'> | undefined {
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ vulnClass, scope: 'single_hop' })
  return spec?.singleHopRule === 'impact' ? spec.impactClass : undefined
}

export function canonicalVulnClassForImpact(impactClass: string): string | undefined {
  if (!REGISTERED_IMPACT_CLASSES.has(impactClass)) return undefined
  return impactClass
}

/** Derived `TERMINAL_CLASS_CONTRACT` map for `v8-oracle-hydrate.ts`. */
export function buildTerminalClassContractMap(): Readonly<Record<string, OracleTerminalContractKind>> {
  const entries: Array<[string, OracleTerminalContractKind]> = []
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    for (const label of spec.labels) {
      entries.push([label, spec.terminalContract])
    }
  }
  return Object.freeze(Object.fromEntries(entries))
}

export function resolveTerminalContractKind(cls: string): OracleTerminalContractKind | null {
  const norm = cls.trim().toLowerCase()
  if (!norm) return null
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ terminalVulnClass: norm, scope: 'all' })
  return spec ? spec.terminalContract : null
}

/** Derived `IMPACT_CLASS_LABELS` for `oracle-invariants.ts`. */
export function buildImpactClassLabels(): Record<string, { vulnClass: string; cwe: string; category: string }> {
  const out: Record<string, { vulnClass: string; cwe: string; category: string }> = {}
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    if (!spec.evidenceAlignment) continue
    out[spec.evidenceAlignment.key] = {
      vulnClass: spec.evidenceAlignment.vulnClass,
      cwe: spec.evidenceAlignment.cwe,
      category: spec.evidenceAlignment.category,
    }
  }
  return out
}

/** Derived `IMPACT_CLASS_CWES` for `oracle-invariants.ts`. */
export function buildImpactClassCwes(): Record<string, number[]> {
  const out: Record<string, number[]> = {}
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    if (!spec.evidenceAlignment) continue
    out[spec.evidenceAlignment.key] = [...spec.evidenceAlignment.cweNumbers]
  }
  return out
}

/** Derived typed-vulnClass descriptor impact resolver for `oracle-invariants.ts`. */
export function resolveDescriptorImpactClass(vulnClass: string): OracleImpactClass | null {
  const norm = vulnClass.trim().toLowerCase()
  if (!norm) return null
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ vulnClass: norm, scope: 'all' })
  if (!spec) return null
  if (spec.descriptorImpactLabelOverrides && norm in spec.descriptorImpactLabelOverrides) {
    return spec.descriptorImpactLabelOverrides[norm]!
  }
  return spec.descriptorImpactClass
}

const MFA_TYPED_LABELS = new Set(['mfa', '2fa', 'mfa_bypass', 'otp_bypass', 'totp_bypass'])
const AUTH_BOUNDARY_EXTRA_CWES = new Set(['CWE-522'])
const ACCESS_BOUNDARY_EXTRA_CWES = new Set(['CWE-1021'])

const AUTH_BOUNDARY_CWE_SET: ReadonlySet<string> = (() => {
  const set = new Set<string>(AUTH_BOUNDARY_EXTRA_CWES)
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    if (spec.kind === 'single_hop' && spec.boundaryClass === 'auth') {
      for (const cwe of spec.cwes) set.add(cwe)
    }
  }
  return set
})()

const ACCESS_BOUNDARY_CWE_SET: ReadonlySet<string> = (() => {
  const set = new Set<string>(ACCESS_BOUNDARY_EXTRA_CWES)
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    if (spec.kind === 'single_hop' && spec.boundaryClass === 'access') {
      for (const cwe of spec.cwes) set.add(cwe)
    }
  }
  return set
})()

/** Derived typed-label boundary classifier for `oracle-invariants.ts`. */
export function resolveBoundaryClassForLabel(vulnClass: string): OracleBoundaryClass | null {
  const norm = vulnClass.trim().toLowerCase()
  if (!norm) return null
  if (MFA_TYPED_LABELS.has(norm)) return 'mfa'
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.resolve({ vulnClass: norm, scope: 'all' })
  return spec ? spec.boundaryClass : null
}

/** Derived typed-CWE boundary classifier for `oracle-invariants.ts`. */
export function resolveBoundaryClassForCwe(cwe: string): 'auth' | 'access' | null {
  const norm = normalizeOracleCwe(cwe)
  if (!norm) return null
  if (AUTH_BOUNDARY_CWE_SET.has(norm)) return 'auth'
  if (ACCESS_BOUNDARY_CWE_SET.has(norm)) return 'access'
  return null
}

// ---------------------------------------------------------------------------
// Registered Claim Evaluator Dispatch (verify-claims.ts -> OracleSpec)
// ---------------------------------------------------------------------------

export type OracleClaimEvaluator<TStore = unknown, TClaim = unknown, TContext = unknown, TResult = unknown> = (
  store: TStore,
  claim: TClaim,
  context: TContext,
  spec: OracleSpec,
) => TResult

interface RegisteredClaimDispatchEntry {
  readonly specId: string
  readonly evaluator: OracleClaimEvaluator
}

const CLAIM_EVALUATOR_REGISTRY = new Map<OracleClaimKind, RegisteredClaimDispatchEntry>()

/**
 * Bind a claim-kind evaluator in `verify-claims.ts` to a registered `OracleSpec`.
 * Rejects unknown specs or undeclared claim kinds at registration time.
 */
export function registerOracleClaimEvaluator<TStore, TClaim, TContext, TResult>(
  specId: string,
  claimKind: OracleClaimKind,
  evaluator: OracleClaimEvaluator<TStore, TClaim, TContext, TResult>,
): void {
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.get(specId)
  if (!spec) {
    throw new Error(`Cannot register claim evaluator for unknown OracleSpec "${specId}".`)
  }
  if (!spec.claimKinds.includes(claimKind)) {
    throw new Error(`OracleSpec "${specId}" does not declare claimKind "${claimKind}".`)
  }
  CLAIM_EVALUATOR_REGISTRY.set(claimKind, {
    specId,
    evaluator: evaluator as OracleClaimEvaluator,
  })
}

export function listRegisteredClaimEvaluatorKinds(): readonly OracleClaimKind[] {
  return [...CLAIM_EVALUATOR_REGISTRY.keys()]
}

export function evaluateRegisteredOracleClaim<TStore, TClaim extends { readonly kind: string }, TContext, TResult>(
  store: TStore,
  claim: TClaim,
  context: TContext,
): TResult | null {
  const entry = CLAIM_EVALUATOR_REGISTRY.get(claim.kind as OracleClaimKind)
  if (!entry) return null
  const spec = DEFAULT_ORACLE_SPEC_REGISTRY.get(entry.specId)
  if (!spec) return null
  return entry.evaluator(store, claim, context, spec) as TResult
}
