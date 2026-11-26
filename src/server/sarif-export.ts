import { createHash } from 'node:crypto'
import { and, desc, eq } from 'drizzle-orm'
import type { Finding, OwaspCategory } from '../domain.ts'
import { normalizeFindingSeverity, projectRunFindings } from '../findings-view.ts'
import type { OperatorTriageOverlay } from '../findings-view.ts'
import { owaspCategoryTitles } from '../report-summary.ts'
import { computeFindingFingerprint } from './dedupe.ts'
import type { CompositeProofReceipt } from './composite-receipt.ts'
import { FindingCodec } from './finding-codec.ts'
import { privateModelProfiles } from './model-settings.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import {
  buildPortableCompositeReceiptRecord,
  extractStoreCompositeReceipts,
  isPortableCompositeReceiptRecord,
} from './receipt-export.ts'
import type {
  CompositeReceiptExportInput,
  PortableCompositeReceiptRecord,
} from './receipt-export.ts'
import { redact, redactPii } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { brokerExchanges, facts as factsTable, findings as findingsTable, replaySpecs, reports, retestRuns } from './schema.ts'
import type { Store } from './store.ts'
import { parseUnifiedDiff } from './unified-diff.ts'

export interface SarifCodeLocation {
  repo?: string
  file: string
  startLine: number
  endLine?: number
  snippet?: string
  label?: string
}

export type SarifCompositeReceiptInput =
  | CompositeProofReceipt
  | PortableCompositeReceiptRecord
  | CompositeReceiptExportInput

export interface SarifCodeFlowOptions {
  secrets?: readonly NamedSecret[]
  zdr?: boolean
}

export interface SarifFindingInput extends Omit<Finding, 'status' | 'codeLocations' | 'verificationTier' | 'fingerprintHash' | 'counterevidence' | 'confidenceRationale' | 'severityChangeConditions' | 'runtimeProofGap'> {
  status: Finding['status'] | 'static_verified'
  verificationTier?: 'runtime_confirmed' | 'static_verified' | 'baseline_confirmed'
  verificationStatus?: string | null
  provenance?: string | null
  sourceOrigins?: string[] | null
  assetId?: string | null
  operatorTriage?: OperatorTriageOverlay | null
  hasReceipt?: boolean
  hasCompositeReceipt?: boolean
  hasOobBacking?: boolean
  replaySpecKind?: string | null
  runtimeProofGap?: string | null
  fingerprintHash?: string | null
  counterevidence?: string | null
  confidenceRationale?: string | null
  severityChangeConditions?: string | null
  codeLocations?: SarifCodeLocation[] | null
  endpoint?: string | null
  compositeReceipt?: SarifCompositeReceiptInput | null
}

export interface SarifPatchInput {
  id: string
  findingId: string
  repo: string
  status: 'draft' | 'approved' | 'rejected' | 'withheld'
  callerCompatibility?: 'attacker_only' | 'needs_operator_step' | 'breaks_callers'
  diff: string
  fixBefore?: string
  fixAfter?: string
  codeLocations?: SarifCodeLocation[] | null
  reviewNotes?: string | null
  dynamicRetestVerdict?: 'fixed' | 'reproduced' | 'skipped'
}

export interface SarifCoverageInput {
  origin: string
  category: OwaspCategory | string
  status: 'reported' | 'no_issue_found' | 'ruled_out' | 'not_applicable' | 'needs_follow_up'
  summary: string
  enforcingControl?: string | null
  proofGapReason?: string | null
  linkedFindingId?: string | null
}

export interface SarifReportingDescriptor {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription: { text: string }
  help: { text: string; markdown: string }
  defaultConfiguration: { level: 'error' | 'warning' | 'note' | 'none' }
  properties: {
    'security-severity'?: string
    tags: string[]
    precision?: 'very-high' | 'high' | 'medium' | 'low'
  }
}

export interface SarifArtifactLocation {
  uri: string
}

export interface SarifRegion {
  startLine: number
  endLine?: number
  snippet?: { text: string }
}

export interface SarifLocation {
  physicalLocation?: {
    artifactLocation: SarifArtifactLocation
    region: SarifRegion
  }
  logicalLocations?: Array<{
    name: string
    fullyQualifiedName: string
    kind: string
  }>
  message?: { text: string }
}

export interface SarifThreadFlowLocation {
  executionOrder: number
  location: SarifLocation
  kinds?: string[]
  importance?: 'essential' | 'important' | 'unimportant'
  properties?: {
    kovo: Record<string, unknown>
  }
}

export interface SarifThreadFlow {
  id: string
  message?: { text: string }
  locations: SarifThreadFlowLocation[]
}

export interface SarifCodeFlow {
  message?: { text: string }
  threadFlows: SarifThreadFlow[]
}

export interface SarifArtifactChange {
  artifactLocation: SarifArtifactLocation
  replacements: Array<{
    deletedRegion: { startLine: number; startColumn?: number; endLine?: number; endColumn?: number }
    insertedContent: { text: string }
  }>
}

export interface SarifFix {
  description: { text: string }
  artifactChanges: SarifArtifactChange[]
}

export interface SarifSuppression {
  kind: 'inSource' | 'external'
  status?: 'accepted' | 'underReview' | 'rejected'
  justification?: string
  properties?: Record<string, unknown>
}

export interface SarifResult {
  ruleId: string
  ruleIndex: number
  kind: 'fail' | 'pass' | 'notApplicable' | 'open' | 'informational' | 'review'
  level: 'error' | 'warning' | 'note' | 'none'
  message: { text: string }
  locations: SarifLocation[]
  codeFlows?: SarifCodeFlow[]
  partialFingerprints?: Record<string, string>
  fixes?: SarifFix[]
  suppressions?: SarifSuppression[]
  properties: {
    kovo: Record<string, unknown>
  }
}

export interface SarifRun {
  tool: {
    driver: {
      name: string
      fullName: string
      semanticVersion: string
      informationUri: string
      rules: SarifReportingDescriptor[]
    }
  }
  invocations: Array<{
    executionSuccessful: boolean
    endTimeUtc: string
  }>
  results: SarifResult[]
  properties: Record<string, unknown>
}

export interface SarifLog {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json'
  version: '2.1.0'
  runs: SarifRun[]
}

export interface SarifBuildInput {
  runId: string
  reportVersion: number
  goal: string
  capabilityTier: number
  scopeRevision: number
  goalRevision: number
  approvedOrigins: readonly string[]
  provenanceAllowedOrigins?: readonly string[]
  taintedFactIds?: readonly string[] | ReadonlySet<string>
  findings: readonly SarifFindingInput[]
  coverageEntries?: readonly SarifCoverageInput[]
  patches?: readonly SarifPatchInput[]
  compositeReceipts?: readonly SarifCompositeReceiptInput[]
  replaySpecShaById?: ReadonlyMap<string, string>
  approvedExchangeIds?: ReadonlySet<string>
  executionSuccessful?: boolean
  generatedAtIso?: string
  secrets?: readonly NamedSecret[]
  zdr?: boolean
}

export interface ExportReportSarifOptions {
  compositeReceipts?: readonly SarifCompositeReceiptInput[]
  zdr?: boolean
}

const CHECK_ID_TO_CWE: Record<string, { cwe: string; name: string }> = {
  hsts: { cwe: 'CWE-319', name: 'Cleartext Transmission of Sensitive Information (Missing HSTS)' },
  nosniff: { cwe: 'CWE-693', name: 'Protection Mechanism Failure (Missing X-Content-Type-Options)' },
  'referrer-policy': { cwe: 'CWE-200', name: 'Exposure of Sensitive Information (Weak Referrer-Policy)' },
  'content-security-policy': { cwe: 'CWE-693', name: 'Protection Mechanism Failure (Missing or Weak CSP)' },
  'frame-protection': { cwe: 'CWE-1021', name: 'Improper Restriction of Rendered UI Layers (Clickjacking)' },
  'server-disclosure': { cwe: 'CWE-200', name: 'Exposure of Sensitive Information (Server Banner Disclosure)' },
  'cors-policy': { cwe: 'CWE-942', name: 'Permissive Cross-domain Policy with Untrusted Domains' },
  'error-exposure': { cwe: 'CWE-209', name: 'Generation of Error Message Containing Sensitive Information' },
  'session-cookie': { cwe: 'CWE-614', name: 'Sensitive Cookie in HTTPS Session Without Secure/HttpOnly Attribute' },
  'access-policy': { cwe: 'CWE-284', name: 'Improper Access Control' },
}

const CATEGORY_TO_CWE: Record<string, { cwe: string; name: string }> = {
  'broken-access-control': { cwe: 'CWE-284', name: 'Improper Access Control' },
  'auth-identity': { cwe: 'CWE-287', name: 'Improper Authentication' },
  'injection-input': { cwe: 'CWE-74', name: 'Improper Neutralization of Special Elements (Injection)' },
  'cors-client-side': { cwe: 'CWE-942', name: 'Permissive Cross-domain Policy / Client-Side Security' },
  'ssrf-redirects': { cwe: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)' },
  'crypto-tls-transport': { cwe: 'CWE-295', name: 'Improper Certificate Validation / Transport Security' },
  'misconfig-exposure': { cwe: 'CWE-16', name: 'Security Misconfiguration' },
  'upload-storage': { cwe: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type' },
  'business-logic-race': { cwe: 'CWE-362', name: 'Concurrent Execution Using Shared Resource (Race Condition)' },
  'dns-takeover-infra': { cwe: 'CWE-350', name: 'Reliance on Reverse DNS / Subdomain Takeover' },
  'llm-ai-security': { cwe: 'CWE-77', name: 'Prompt / AI Tool Injection' },
}

const SEVERITY_TO_SCORE: Record<Finding['severity'], string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  informational: '1.0',
}

function severityToSarifLevel(severity: Finding['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error'
  if (severity === 'medium') return 'warning'
  return 'note'
}

function canonicalRuleId(finding: SarifFindingInput): { id: string; name: string; cweNumber?: string } {
  const rawCwe = finding.cwe?.trim().toUpperCase()
  if (rawCwe && /^CWE-\d{1,5}$/.test(rawCwe)) {
    const num = rawCwe.slice(4)
    return {
      id: rawCwe,
      name: finding.category ? `${rawCwe} (${owaspCategoryTitles[finding.category as OwaspCategory] ?? finding.category})` : rawCwe,
      cweNumber: num,
    }
  }
  if (finding.check?.id && CHECK_ID_TO_CWE[finding.check.id]) {
    const mapped = CHECK_ID_TO_CWE[finding.check.id]
    return { id: mapped.cwe, name: mapped.name, cweNumber: mapped.cwe.slice(4) }
  }
  if (finding.category && CATEGORY_TO_CWE[finding.category]) {
    const mapped = CATEGORY_TO_CWE[finding.category]
    return { id: mapped.cwe, name: mapped.name, cweNumber: mapped.cwe.slice(4) }
  }
  return { id: 'CWE-693', name: 'Protection Mechanism Failure', cweNumber: '693' }
}

function parseArtifactChangesFromPatch(patch: SarifPatchInput, secrets: readonly NamedSecret[]): SarifArtifactChange[] {
  const changes: SarifArtifactChange[] = []

  // M-24: Parse unified diff hunks strictly by declared line counts via shared parser,
  // emitting zero-width deletedRegion for insertion-only hunks (`oldCount === 0`).
  try {
    const filePatches = parseUnifiedDiff(patch.diff, { allowEmpty: true })
    for (const filePatch of filePatches) {
      if (filePatch.isDelete) continue
      const replacements: SarifArtifactChange['replacements'] = []
      for (const hunk of filePatch.hunks) {
        const inserted = hunk.entries
          .filter(entry => entry.kind === 'context' || entry.kind === 'add')
          .map(entry => entry.text)
        const deletedRegion = hunk.oldCount === 0
          ? (() => {
              const insertLine = Math.max(1, hunk.oldStart === 0 ? 1 : hunk.oldStart + 1)
              return { startLine: insertLine, startColumn: 1, endLine: insertLine, endColumn: 1 }
            })()
          : {
              startLine: Math.max(1, hunk.oldStart),
              endLine: Math.max(1, hunk.oldStart + hunk.oldCount - 1),
            }
        replacements.push({
          deletedRegion,
          insertedContent: {
            text: redact(inserted.join('\n') + (inserted.length ? '\n' : ''), secrets),
          },
        })
      }
      if (replacements.length > 0) {
        changes.push({
          artifactLocation: { uri: filePatch.normalizedPath },
          replacements,
        })
      }
    }
  } catch {
    // Fall through to explicit codeLocations + fixAfter fallback when diff is unparseable.
  }

  // Fallback to explicit codeLocations + fixAfter if diff had no parseable hunks.
  if (changes.length === 0 && patch.codeLocations?.length && patch.fixAfter !== undefined) {
    const loc = patch.codeLocations[0]
    changes.push({
      artifactLocation: { uri: loc.file },
      replacements: [
        {
          deletedRegion: {
            startLine: Math.max(1, loc.startLine),
            endLine: Math.max(loc.startLine, loc.endLine ?? loc.startLine),
          },
          insertedContent: { text: redact(patch.fixAfter, secrets) },
        },
      ],
    })
  }

  return changes
}

function scrubSarifText(value: string, secrets: readonly NamedSecret[], zdr: boolean): string {
  return zdr ? redactPii(value, { secrets }) : redact(value, secrets)
}

function redactDeep<T>(value: T, secrets: readonly NamedSecret[], zdr = false): T {
  if (typeof value === 'string') {
    return scrubSarifText(value, secrets, zdr) as unknown as T
  }
  if (Array.isArray(value)) {
    return value.map(item => redactDeep(item, secrets, zdr)) as unknown as T
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v !== undefined) out[k] = redactDeep(v, secrets, zdr)
    }
    return out as T
  }
  return value
}

function normalizeCompositeForSarif(
  item: SarifCompositeReceiptInput,
  secrets: readonly NamedSecret[],
  zdr: boolean,
): PortableCompositeReceiptRecord {
  if (isPortableCompositeReceiptRecord(item)) {
    return item
  }
  const input: CompositeReceiptExportInput = 'receipt' in item && 'hops' in item.receipt
    ? item
    : { receipt: item as CompositeProofReceipt }
  return buildPortableCompositeReceiptRecord(input, { secrets, zdr })
}

/**
 * Convert one or more `CompositeProofReceipt` DAGs into OASIS SARIF 2.1.0 `codeFlows` /
 * `threadFlows` with topologically ordered hop locations (surface + route + causal binding kind)
 * and zero secret leakage.
 */
export function compositeReceiptsToSarifCodeFlows(
  receiptOrReceipts: SarifCompositeReceiptInput | readonly SarifCompositeReceiptInput[],
  options: SarifCodeFlowOptions = {},
): SarifCodeFlow[] {
  const items = Array.isArray(receiptOrReceipts)
    ? receiptOrReceipts as readonly SarifCompositeReceiptInput[]
    : [receiptOrReceipts as SarifCompositeReceiptInput]
  if (items.length === 0) return []

  const secrets = options.secrets ?? []
  const zdr = options.zdr === true
  const codeFlows: SarifCodeFlow[] = []

  for (const raw of items) {
    const record = normalizeCompositeForSarif(raw, secrets, zdr)
    const incomingByHop = new Map<string, Array<{ fromHopId: string; kind: string }>>()
    const outgoingByHop = new Map<string, Array<{ toHopId: string; kind: string }>>()
    for (const edge of record.causalEdges) {
      const inc = incomingByHop.get(edge.toHopId) ?? []
      inc.push({ fromHopId: edge.fromHopId, kind: edge.kind })
      incomingByHop.set(edge.toHopId, inc)
      const out = outgoingByHop.get(edge.fromHopId) ?? []
      out.push({ toHopId: edge.toHopId, kind: edge.kind })
      outgoingByHop.set(edge.fromHopId, out)
    }

    const threadFlowLocations: SarifThreadFlowLocation[] = record.hops.map(hop => {
      const incoming = incomingByHop.get(hop.hopId) ?? []
      const outgoing = outgoingByHop.get(hop.hopId) ?? []
      const incomingBindingKinds = incoming.map(e => e.kind)
      const outgoingBindingKinds = outgoing.map(e => e.kind)
      const route = hop.pathAndQuery || '/'
      const methodPrefix = hop.method ? `${hop.method} ` : ''
      const isTerminal = hop.hopId === record.terminalImpact.terminalHopId
      const patchBrokeHere = record.patchBrokeHopId === hop.hopId

      const bindingClause = incoming.length > 0
        ? ` via ${incoming.map(e => `${e.kind} from ${e.fromHopId}`).join(', ')}`
        : ' (root hop)'
      const actorClause = hop.actor ? ` [actor: ${hop.actor}]` : ''
      const suffixFlags = [
        ...(isTerminal ? ['[Terminal Impact]'] : []),
        ...(patchBrokeHere ? [`[Patch broke chain at ${hop.hopId}]`] : []),
      ].join(' ')

      const locationText = [
        `Hop ${hop.order}/${record.hops.length} (${hop.hopId}) [${hop.surface}] ${methodPrefix}${hop.origin}${route}${bindingClause}${actorClause}: ${hop.claimedDelta}`,
        ...(suffixFlags ? [suffixFlags] : []),
      ].join(' ')

      const kinds = [
        hop.surface,
        ...(incomingBindingKinds.length > 0 ? incomingBindingKinds : ['entry']),
        ...(isTerminal ? ['terminal_impact'] : []),
      ]

      return {
        executionOrder: hop.order,
        location: {
          logicalLocations: [
            {
              name: `${hop.surface}:${methodPrefix}${route}`,
              fullyQualifiedName: `${hop.origin}::${hop.surface}::${route}::${hop.hopId}`,
              kind: hop.surface,
            },
          ],
          message: { text: locationText },
        },
        kinds,
        importance: hop.order === 1 || isTerminal ? 'essential' : 'important',
        properties: {
          kovo: {
            chainId: record.chainId,
            hopId: hop.hopId,
            hopIndex: hop.order,
            surface: hop.surface,
            origin: hop.origin,
            method: hop.method,
            route,
            actor: hop.actor,
            incomingBindingKinds,
            outgoingBindingKinds,
            isTerminal,
            ...(patchBrokeHere ? { patchBrokeHopId: hop.hopId } : {}),
          },
        },
      }
    })

    const modeLabel = record.replayMode === 'fresh_clean_replay' ? 'Mode-A fresh_clean_replay' : 'Mode-B one_shot_transcript'
    const patchClause = record.patchBrokeHopId ? `; patchBrokeHopId=${record.patchBrokeHopId}` : ''
    const flowMsg = `Multi-hop causal chain ${record.chainId} (${record.hops.length} hops, ${record.terminalVulnClass}, ${modeLabel}${patchClause}): ${record.terminalImpact.claimedImpact}`

    codeFlows.push({
      message: { text: flowMsg },
      threadFlows: [
        {
          id: record.chainId,
          message: {
            text: `${record.hops.map(h => `${h.hopId}[${h.surface}]`).join(' -> ')} -> Terminal Impact`,
          },
          locations: threadFlowLocations,
        },
      ],
    })
  }

  return redactDeep(codeFlows, secrets, zdr)
}

export function buildSarifLog(input: SarifBuildInput): SarifLog {
  const secrets = input.secrets ?? []
  const zdr = input.zdr === true
  const approved = new Set(input.approvedOrigins)
  const rules: SarifReportingDescriptor[] = []
  const ruleIndexById = new Map<string, number>()

  function ensureRule(
    id: string,
    factory: () => SarifReportingDescriptor,
  ): number {
    const existing = ruleIndexById.get(id)
    if (existing !== undefined) return existing
    const idx = rules.length
    rules.push(factory())
    ruleIndexById.set(id, idx)
    return idx
  }

  const patchesByFinding = new Map<string, SarifPatchInput[]>()
  for (const patch of input.patches ?? []) {
    if (patch.status !== 'approved') continue
    const arr = patchesByFinding.get(patch.findingId) ?? []
    arr.push(patch)
    patchesByFinding.set(patch.findingId, arr)
  }

  const compositeByFinding = new Map<string, PortableCompositeReceiptRecord[]>()
  for (const rawComp of input.compositeReceipts ?? []) {
    const normalized = normalizeCompositeForSarif(rawComp, secrets, zdr)
    if (normalized.hops.some(h => !approved.has(h.origin))) continue
    if (!normalized.findingId) continue
    const arr = compositeByFinding.get(normalized.findingId) ?? []
    if (!arr.some(existing => existing.chainId === normalized.chainId)) {
      arr.push(normalized)
      compositeByFinding.set(normalized.findingId, arr)
    }
  }

  const results: SarifResult[] = []

  // Single terminal findings projection shared across headline, report, Markdown, SARIF & receipts.
  const view = projectRunFindings(input.findings, {
    approvedOrigins: approved,
    ...(input.provenanceAllowedOrigins ? { provenanceAllowedOrigins: input.provenanceAllowedOrigins } : {}),
    ...(input.taintedFactIds ? { taintedFactIds: input.taintedFactIds } : {}),
  })
  const supersededExcludedCount = view.counts.byExclusion.superseded ?? 0

  let confirmedCount = 0
  let staticAdvisoryCount = 0
  let suppressedCount = 0

  const emitEntries = [
    ...view.reportable.map(projected => ({ projected, suppressed: false })),
    ...view.suppressedReportable.map(projected => ({ projected, suppressed: true })),
  ]

  for (const { projected, suppressed } of emitEntries) {
    const finding = projected.finding
    const isStaticVerified = projected.preSuppressionDisposition === 'advisory'
    if (suppressed) {
      suppressedCount += 1
    } else if (isStaticVerified) {
      staticAdvisoryCount += 1
    } else {
      confirmedCount += 1
    }

    const effectiveSeverity = projected.effectiveSeverity
    const machineSeverity = normalizeFindingSeverity(finding.severity)
    const backingKind = projected.backingKind
    const disposition = projected.disposition
    const ruleMeta = canonicalRuleId(finding)
    const level = severityToSarifLevel(effectiveSeverity)
    const secScore = SEVERITY_TO_SCORE[effectiveSeverity] ?? '5.5'

    const ruleIndex = ensureRule(ruleMeta.id, () => ({
      id: ruleMeta.id,
      name: ruleMeta.name,
      shortDescription: { text: redact(ruleMeta.name, secrets) },
      fullDescription: {
        text: redact(
          finding.impact || finding.reason || `Security vulnerability classified under ${ruleMeta.id}.`,
          secrets,
        ),
      },
      help: {
        text: redact(finding.remediation || 'Apply defense-in-depth remediation and re-verify.', secrets),
        markdown: redact(
          `**Remediation:** ${finding.remediation}\n\n${finding.recheck ? `**Recheck:** ${finding.recheck}` : ''}`.trim(),
          secrets,
        ),
      },
      defaultConfiguration: { level },
      properties: {
        'security-severity': secScore,
        tags: [
          'security',
          ...(ruleMeta.cweNumber ? [`external/cwe/cwe-${ruleMeta.cweNumber}`] : []),
          ...(finding.category ? [`kovo/category/${finding.category}`] : []),
        ],
        precision: isStaticVerified ? 'high' : 'very-high',
      },
    }))

    // Keep rule security-severity at the highest observed severity for this CWE.
    const ruleObj = rules[ruleIndex]
    if (ruleObj.properties['security-severity'] && Number(secScore) > Number(ruleObj.properties['security-severity'])) {
      ruleObj.properties['security-severity'] = secScore
    }

    const endpoint = finding.endpoint || '/'
    const logicalName = `${finding.origin}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`
    const logicalLoc = {
      name: redact(logicalName, secrets),
      fullyQualifiedName: redact(`${finding.origin}::${finding.category ?? ruleMeta.id}::${endpoint}`, secrets),
      kind: 'endpoint',
    }

    const locations: SarifLocation[] = []
    const codeLocs = finding.codeLocations ?? []
    if (codeLocs.length > 0) {
      for (const loc of codeLocs) {
        const uri = loc.repo && !loc.file.startsWith(loc.repo + '/')
          ? `${loc.repo}/${loc.file}`.replace(/^\/+/, '')
          : loc.file.replace(/^\/+/, '')
        locations.push({
          physicalLocation: {
            artifactLocation: { uri: redact(uri, secrets) },
            region: {
              startLine: Math.max(1, loc.startLine),
              ...(loc.endLine && loc.endLine >= loc.startLine ? { endLine: loc.endLine } : {}),
              ...(loc.snippet ? { snippet: { text: redact(loc.snippet, secrets) } } : {}),
            },
          },
          logicalLocations: [logicalLoc],
        })
      }
    } else {
      locations.push({ logicalLocations: [logicalLoc] })
    }

    const fp = finding.fingerprintHash
      || computeFindingFingerprint({
        origin: finding.origin,
        cwe: ruleMeta.id,
        category: finding.category,
        endpoint,
      }).hash

    const approvedExchanges = (finding.exchangeIds ?? []).filter(id =>
      !input.approvedExchangeIds || input.approvedExchangeIds.has(id),
    )
    const replaySpecSha256 = finding.replaySpecId ? input.replaySpecShaById?.get(finding.replaySpecId) : undefined

    const verificationTier = isStaticVerified
      ? 'static_verified'
      : (finding.verificationTier === 'baseline_confirmed' || finding.findingKind === 'baseline_check'
          ? 'baseline_confirmed'
          : 'runtime_confirmed')
    const runtimeProofGap = isStaticVerified
      ? (finding.runtimeProofGap || 'Verified deterministically via air-gapped static AST/SAST re-execution; runtime exploitation was not executed.')
      : undefined

    const approvedPatches = patchesByFinding.get(finding.id) ?? []
    const fixes: SarifFix[] = []
    for (const patch of approvedPatches) {
      const artifactChanges = parseArtifactChangesFromPatch(patch, secrets)
      if (!artifactChanges.length) continue
      fixes.push({
        description: {
          text: redact(
            `Kovo Hunter verified patch (${patch.id.slice(0, 8)})${patch.dynamicRetestVerdict === 'fixed' ? ' [dynamically retested: reproduced -> fixed]' : ''}: ${patch.reviewNotes?.split('\n')[0] || finding.remediation}`,
            secrets,
          ),
        },
        artifactChanges,
      })
    }

    const messageText = redact(
      `[${verificationTier === 'static_verified' ? 'Static Advisory' : verificationTier === 'baseline_confirmed' ? 'Baseline Confirmed' : 'Runtime Confirmed'}] ${finding.title} (${finding.origin}): ${finding.reason}`,
      secrets,
    )

    const matchedComposites: PortableCompositeReceiptRecord[] = []
    const seenChainIds = new Set<string>()
    for (const comp of compositeByFinding.get(finding.id) ?? []) {
      if (!seenChainIds.has(comp.chainId)) {
        seenChainIds.add(comp.chainId)
        matchedComposites.push(comp)
      }
    }
    if (finding.compositeReceipt) {
      const normalized = normalizeCompositeForSarif(finding.compositeReceipt, secrets, zdr)
      if (!normalized.hops.some(h => !approved.has(h.origin)) && !seenChainIds.has(normalized.chainId)) {
        seenChainIds.add(normalized.chainId)
        matchedComposites.push(normalized)
      }
    }
    const codeFlows = matchedComposites.length > 0
      ? compositeReceiptsToSarifCodeFlows(matchedComposites, { secrets, zdr })
      : []

    const triage = finding.operatorTriage
    const suppressedBy = projected?.suppressedBy ?? (
      triage?.status === 'false_positive' || triage?.status === 'accepted_risk' ? triage.status : undefined
    )
    const suppressions: SarifSuppression[] | undefined = suppressed && suppressedBy
      ? [{
          kind: 'external',
          status: 'accepted',
          justification: redact(
            triage?.notes?.trim()
              ? `[${suppressedBy}] ${triage.notes.trim()}`
              : suppressedBy === 'false_positive'
                ? 'Marked false positive via operator triage.'
                : 'Marked accepted risk via operator triage.',
            secrets,
          ),
          properties: {
            triageStatus: suppressedBy,
            ...(triage?.updatedAt ? { updatedAt: new Date(triage.updatedAt).toISOString() } : {}),
          },
        }]
      : undefined

    results.push({
      ruleId: ruleMeta.id,
      ruleIndex,
      kind: 'fail',
      level,
      message: { text: messageText },
      locations,
      ...(codeFlows.length > 0 ? { codeFlows } : {}),
      partialFingerprints: {
        'kovo/v3/fingerprint': fp,
        'primaryLocationLineHash': createHash('sha256').update(`${finding.id}:${fp}`).digest('hex').slice(0, 32),
      },
      ...(fixes.length > 0 ? { fixes } : {}),
      ...(suppressions ? { suppressions } : {}),
      properties: {
        kovo: {
          findingId: finding.id,
          origin: finding.origin,
          severity: effectiveSeverity,
          effectiveSeverity,
          machineSeverity,
          status: finding.status,
          disposition,
          backingKind,
          ...(suppressedBy ? { triageStatus: suppressedBy } : {}),
          category: finding.category ?? null,
          cwe: ruleMeta.id,
          verificationTier,
          runtimeConfirmed: !isStaticVerified,
          tierSection: suppressed ? 'suppressed' : isStaticVerified ? 'static_advisory' : 'confirmed',
          ...(runtimeProofGap ? { runtimeProofGap } : {}),
          exchangeIds: approvedExchanges,
          ...(replaySpecSha256 ? { replaySpecSha256 } : {}),
          ...(matchedComposites.length > 0
            ? {
                compositeChains: matchedComposites.map(c => ({
                  chainId: c.chainId,
                  hopCount: c.hopCount,
                  replayMode: c.replayMode,
                  ...(c.patchBrokeHopId ? { patchBrokeHopId: c.patchBrokeHopId } : {}),
                })),
              }
            : {}),
          ...(finding.counterevidence ? { counterevidence: finding.counterevidence } : {}),
          ...(finding.confidenceRationale ? { confidenceRationale: finding.confidenceRationale } : {}),
          ...(finding.severityChangeConditions ? { severityChangeConditions: finding.severityChangeConditions } : {}),
          remediation: finding.remediation,
        },
      },
    })
  }

  // Emit coverage_entries as non-failing SARIF rows (pass / notApplicable / open for needs_follow_up).
  for (const cov of input.coverageEntries ?? []) {
    if (!approved.has(cov.origin)) continue
    const cleanCat = String(cov.category).replace(/[^a-zA-Z0-9_-]/g, '-')
    const covRuleId = `KOVO-COVERAGE-${cleanCat}`
    const catTitle = owaspCategoryTitles[cov.category as OwaspCategory] ?? cov.category

    const ruleIndex = ensureRule(covRuleId, () => ({
      id: covRuleId,
      name: `Coverage: ${catTitle}`,
      shortDescription: { text: `Kovo Hunter coverage ledger for ${catTitle}` },
      fullDescription: { text: `Tracks defensive review coverage, ruled-out controls, and open proof gaps for ${catTitle}.` },
      help: {
        text: 'Non-failing coverage record documenting verified controls or open follow-up proof gaps.',
        markdown: 'Non-failing coverage record documenting verified controls or open follow-up proof gaps.',
      },
      defaultConfiguration: { level: 'none' },
      properties: {
        tags: ['security', 'kovo/coverage', `kovo/category/${cleanCat}`],
      },
    }))

    const kind: SarifResult['kind'] = cov.status === 'not_applicable'
      ? 'notApplicable'
      : cov.status === 'needs_follow_up'
        ? 'open'
        : 'pass'
    // OASIS SARIF 2.1.0 §3.27.10: When kind is anything other than "fail", level SHALL be "none".
    const level: SarifResult['level'] = 'none'

    const msgParts = [
      `[${cov.status}] ${catTitle} on ${cov.origin}: ${cov.summary}`,
      ...(cov.enforcingControl ? [`Enforcing control: ${cov.enforcingControl}`] : []),
      ...(cov.proofGapReason ? [`Proof gap: ${cov.proofGapReason}`] : []),
    ]

    results.push({
      ruleId: covRuleId,
      ruleIndex,
      kind,
      level,
      message: { text: redact(msgParts.join(' — '), secrets) },
      locations: [
        {
          logicalLocations: [
            {
              name: redact(cov.origin, secrets),
              fullyQualifiedName: redact(`${cov.origin}::coverage::${cleanCat}`, secrets),
              kind: 'origin',
            },
          ],
        },
      ],
      properties: {
        kovo: {
          recordType: 'coverage_entry',
          origin: cov.origin,
          category: cov.category,
          coverageStatus: cov.status,
          ...(cov.enforcingControl ? { enforcingControl: cov.enforcingControl } : {}),
          ...(cov.proofGapReason ? { proofGapReason: cov.proofGapReason } : {}),
          ...(cov.linkedFindingId ? { linkedFindingId: cov.linkedFindingId } : {}),
        },
      },
    })
  }

  const log: SarifLog = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Kovo Hunter',
            fullName: 'Kovo Hunter v3 Defensive Security Platform',
            semanticVersion: '3.0.0',
            informationUri: 'https://github.com/kovo-sec/kovo',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: input.executionSuccessful ?? true,
            endTimeUtc: input.generatedAtIso ?? new Date().toISOString(),
          },
        ],
        results,
        properties: {
          runId: input.runId,
          reportVersion: input.reportVersion,
          goal: input.goal,
          capabilityTier: input.capabilityTier,
          scopeRevision: input.scopeRevision,
          goalRevision: input.goalRevision,
          approvedScope: [...approved],
          confirmedCount,
          staticAdvisoryCount,
          reportableCount: confirmedCount + staticAdvisoryCount,
          suppressedCount,
          supersededExcludedCount,
          excludedCount: view.counts.excluded,
        },
      },
    ],
  }

  return redactDeep(log, secrets, zdr)
}

function hydrateFindingsForSarif(
  storage: Store,
  runId: string,
  baseFindings: readonly Finding[],
  specRows: ReadonlyArray<typeof replaySpecs.$inferSelect>,
): SarifFindingInput[] {
  const rowsById = new Map(
    storage.db.select().from(findingsTable).where(eq(findingsTable.runId, runId)).all().map(row => [row.id, row]),
  )
  const specsById = new Map(specRows.map(s => [s.id, s]))
  const specsByFindingId = new Map(specRows.map(s => [s.findingId, s]))
  return baseFindings.map(f => {
    const row = rowsById.get(f.id)
    const decoded = row ? FindingCodec.fromRow(row) : undefined
    const specRow = ((f.replaySpecId ?? row?.replaySpecId)
      ? specsById.get((f.replaySpecId ?? row?.replaySpecId)!)
      : undefined) ?? specsByFindingId.get(f.id)
    const rawProof = specRow?.proofReceipt as Record<string, unknown> | null | undefined
    const hasCompositeReceipt = Boolean(rawProof && (rawProof.compositeReceipt || (Array.isArray(rawProof.hops) && typeof rawProof.chainId === 'string')))
    const hasReceipt = Boolean(rawProof && 'receipt' in rawProof && rawProof.receipt)
    const hasOobBacking = Boolean(hasReceipt && ((specRow?.proofReceipt?.receipt?.oobEventIds?.length ?? 0) > 0))
    const replaySpecKind = specRow?.spec && typeof specRow.spec === 'object'
      ? String((specRow.spec as { kind?: unknown }).kind ?? '')
      : null
    return {
      ...f,
      verificationTier: f.verificationTier ?? row?.verificationTier ?? undefined,
      verificationStatus: decoded?.verificationStatus ?? row?.verificationClass ?? undefined,
      provenance: decoded?.provenance ?? row?.provenance ?? undefined,
      sourceOrigins: row?.sourceOrigins ?? undefined,
      assetId: row?.assetId ?? undefined,
      operatorTriage: (f as { operatorTriage?: OperatorTriageOverlay | null }).operatorTriage ?? decoded?.operatorTriage ?? undefined,
      hasReceipt,
      hasCompositeReceipt,
      hasOobBacking,
      replaySpecKind,
      fingerprintHash: f.fingerprintHash ?? row?.fingerprintHash ?? undefined,
      supersededByFindingId: f.supersededByFindingId ?? row?.supersededByFindingId ?? undefined,
      counterevidence: f.counterevidence ?? row?.counterevidence ?? undefined,
      confidenceRationale: f.confidenceRationale ?? row?.confidenceRationale ?? undefined,
      severityChangeConditions: f.severityChangeConditions ?? row?.severityChangeConditions ?? undefined,
      codeLocations: f.codeLocations ?? row?.codeLocations ?? undefined,
    }
  })
}

function readPatchProposalsFromStore(storage: Store, runId: string): SarifPatchInput[] {
  return storage.listPatchProposals(runId).map(row => ({
    id: row.id,
    findingId: row.findingId,
    repo: row.repo,
    status: row.status,
    callerCompatibility: row.callerCompatibility,
    diff: row.diff,
    codeLocations: row.codeLocations,
    reviewNotes: row.reviewNotes,
    dynamicRetestVerdict: row.dynamicRetestVerdict,
  }))
}

function readCoverageEntriesFromStore(storage: Store, runId: string, goalRevision: number): SarifCoverageInput[] {
  return storage.listCoverageEntries(runId, goalRevision).map(row => ({
    origin: row.origin,
    category: row.category,
    status: row.status,
    summary: row.summary,
    enforcingControl: row.enforcingControl,
    proofGapReason: row.proofGapReason,
    linkedFindingId: row.linkedFindingId,
  }))
}

export function exportReportSarif(
  storage: Store,
  runId: string,
  reportId?: string,
  extraSecrets: readonly NamedSecret[] = [],
  options: ExportReportSarifOptions = {},
): { filename: string; content: string; log: SarifLog } {
  const run = storage.run(runId)
  const report = reportId
    ? storage.db.select().from(reports).where(and(eq(reports.runId, run.id), eq(reports.id, reportId))).get()
    : storage.db.select().from(reports).where(eq(reports.runId, run.id)).orderBy(desc(reports.version)).limit(1).get()

  if (reportId && !report) {
    throw new Error('Report version not found.')
  }

  // Gather ALL registered secrets (personas + model provider API keys + extraSecrets) so zero secrets leak!
  const allSecrets: NamedSecret[] = [...extraSecrets]
  try {
    allSecrets.push(...personaSecrets(resolveRunPersonas(storage, run.projectId, run.approvedPersonaIds)))
  } catch {
    // Ignore missing persona files during offline export
  }
  try {
    for (const profile of privateModelProfiles(storage)) {
      if (profile.key) {
        allSecrets.push({ value: profile.key, placeholder: '[redacted:model-key]' })
      }
    }
  } catch {
    // Ignore when no model profiles exist
  }

  const approvedOrigins = report
    ? report.body.scope.map(asset => asset.origin)
    : run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin)
  const approvedSet = new Set(approvedOrigins)

  const goalRevision = report ? report.body.goalRevision : run.goalRevision
  const scopeRevision = report ? report.body.scopeRevision : run.scopeRevision
  const reportVersion = report ? report.version : 0

  const baseFindings: Finding[] = report
    ? report.body.findings
    : storage.db
      .select()
      .from(findingsTable)
      .where(and(eq(findingsTable.runId, run.id), eq(findingsTable.goalRevision, goalRevision)))
      .all()
      .map(row => row.finding)

  const specRows = storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, run.id)).all()
  const enrichedFindings = hydrateFindingsForSarif(storage, run.id, baseFindings, specRows)
  const taintedFactIds = (!report || scopeRevision === run.scopeRevision)
    ? storage.db
        .select({ id: factsTable.id })
        .from(factsTable)
        .where(and(eq(factsTable.runId, run.id), eq(factsTable.tainted, true)))
        .all()
        .map(f => f.id)
    : []
  const provenanceAllowedOrigins = [...(run.authOrigins ?? []), ...(run.assetOrigins ?? [])]
  const retestRows = storage.db.select().from(retestRuns)
    .where(eq(retestRuns.runId, run.id))
    .orderBy(desc(retestRuns.createdAt))
    .all()
  const replaySpecShaById = new Map<string, string>()
  for (const specRow of specRows) {
    replaySpecShaById.set(specRow.id, specRow.specSha256)
  }

  const findingsMetaById = new Map(
    enrichedFindings.map(f => [f.id, { title: f.title, severity: f.severity, cwe: f.cwe ?? null }]),
  )
  const compositeReceipts: SarifCompositeReceiptInput[] = [
    ...extractStoreCompositeReceipts(specRows, retestRows, findingsMetaById),
    ...(options.compositeReceipts ?? []),
  ]

  const approvedExchangeIds = new Set<string>()
  for (const ex of storage.db.select().from(brokerExchanges).where(eq(brokerExchanges.runId, run.id)).all()) {
    if (ex.scopeRevision > scopeRevision) continue
    const allOrigins = [ex.origin, ex.finalOrigin, ...ex.redirectOrigins]
    if (allOrigins.every(o => approvedSet.has(o))) {
      approvedExchangeIds.add(ex.id)
    }
  }

  const covEntries = readCoverageEntriesFromStore(storage, run.id, goalRevision)
  const patches = readPatchProposalsFromStore(storage, run.id)

  const log = buildSarifLog({
    runId: run.id,
    reportVersion,
    goal: report ? report.body.goal : run.goal,
    capabilityTier: report ? report.body.capabilityTier : run.capabilityTier,
    scopeRevision,
    goalRevision,
    approvedOrigins,
    ...(provenanceAllowedOrigins.length > 0 ? { provenanceAllowedOrigins } : {}),
    ...(taintedFactIds.length > 0 ? { taintedFactIds } : {}),
    findings: enrichedFindings,
    coverageEntries: covEntries,
    patches,
    ...(compositeReceipts.length > 0 ? { compositeReceipts } : {}),
    replaySpecShaById,
    approvedExchangeIds,
    executionSuccessful: run.status !== 'failed',
    generatedAtIso: new Date(report ? report.createdAt : Date.now()).toISOString(),
    secrets: allSecrets,
    ...(options.zdr !== undefined ? { zdr: options.zdr } : {}),
  })

  // Final defense-in-depth redaction pass on the serialized SARIF JSON string.
  const serialized = JSON.stringify(log, null, 2)
  const content = (options.zdr ? redactPii(serialized, { secrets: allSecrets }) : redact(serialized, allSecrets)) + '\n'
  const finalLog = JSON.parse(content) as SarifLog
  return {
    filename: `kovo-report-${run.id.slice(0, 8)}-v${reportVersion}.sarif.json`,
    content,
    log: finalLog,
  }
}
