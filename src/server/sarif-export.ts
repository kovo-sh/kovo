import { createHash } from 'node:crypto'
import { and, desc, eq } from 'drizzle-orm'
import type { Finding, OwaspCategory } from '../domain.ts'
import { deduplicateChainFindings, owaspCategoryTitles } from '../report-summary.ts'
import { computeFindingFingerprint } from './dedupe.ts'
import { privateModelProfiles } from './model-settings.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { brokerExchanges, findings as findingsTable, replaySpecs, reports } from './schema.ts'
import type { Store } from './store.ts'

export interface SarifCodeLocation {
  repo?: string
  file: string
  startLine: number
  endLine?: number
  snippet?: string
  label?: string
}

export interface SarifFindingInput extends Omit<Finding, 'status' | 'codeLocations' | 'verificationTier' | 'fingerprintHash' | 'counterevidence' | 'confidenceRationale' | 'severityChangeConditions' | 'runtimeProofGap'> {
  status: Finding['status'] | 'static_verified'
  verificationTier?: 'runtime_confirmed' | 'static_verified' | 'baseline_confirmed'
  runtimeProofGap?: string | null
  fingerprintHash?: string | null
  counterevidence?: string | null
  confidenceRationale?: string | null
  severityChangeConditions?: string | null
  codeLocations?: SarifCodeLocation[] | null
  endpoint?: string | null
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
}

export interface SarifArtifactChange {
  artifactLocation: SarifArtifactLocation
  replacements: Array<{
    deletedRegion: { startLine: number; endLine?: number }
    insertedContent: { text: string }
  }>
}

export interface SarifFix {
  description: { text: string }
  artifactChanges: SarifArtifactChange[]
}

export interface SarifResult {
  ruleId: string
  ruleIndex: number
  kind: 'fail' | 'pass' | 'notApplicable' | 'open' | 'informational' | 'review'
  level: 'error' | 'warning' | 'note' | 'none'
  message: { text: string }
  locations: SarifLocation[]
  partialFingerprints?: Record<string, string>
  fixes?: SarifFix[]
  properties: {
    guardian: Record<string, unknown>
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
  findings: readonly SarifFindingInput[]
  coverageEntries?: readonly SarifCoverageInput[]
  patches?: readonly SarifPatchInput[]
  replaySpecShaById?: ReadonlyMap<string, string>
  approvedExchangeIds?: ReadonlySet<string>
  executionSuccessful?: boolean
  generatedAtIso?: string
  secrets?: readonly NamedSecret[]
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

  // Parse unified diff hunks into standard OASIS SARIF 2.1.0 artifactChanges.
  const lines = patch.diff.replace(/\r\n/g, '\n').split('\n')
  let currentUri: string | null = null
  let currentReplacements: SarifArtifactChange['replacements'] = []

  const flush = () => {
    if (currentUri && currentReplacements.length > 0) {
      changes.push({
        artifactLocation: { uri: currentUri },
        replacements: currentReplacements,
      })
    }
    currentUri = null
    currentReplacements = []
  }

  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (line.startsWith('+++ ')) {
      flush()
      const rawPath = line.slice(4).split('\t')[0].trim().replace(/^[ab]\//, '')
      currentUri = rawPath === '/dev/null' ? null : rawPath
      i++
      continue
    }
    const hunkMatch = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/)
    if (hunkMatch && currentUri) {
      const oldStart = Number(hunkMatch[1])
      const oldCount = hunkMatch[2] !== undefined ? Number(hunkMatch[2]) : 1
      i++
      const inserted: string[] = []
      let seenOld = 0
      const newCount = hunkMatch[4] !== undefined ? Number(hunkMatch[4]) : 1
      let seenNew = 0
      while (i < lines.length) {
        const l = lines[i]
        if (l.startsWith('@@ ') || l.startsWith('--- ') || l.startsWith('+++ ') || l.startsWith('diff --git ')) break
        if (l.startsWith('\\ No newline')) {
          i++
          continue
        }
        if (seenOld >= oldCount && seenNew >= newCount && l === '') {
          i++
          break
        }
        if (l.startsWith(' ')) {
          inserted.push(l.slice(1))
          seenOld++
          seenNew++
          i++
        } else if (l.startsWith('-')) {
          seenOld++
          i++
        } else if (l.startsWith('+')) {
          inserted.push(l.slice(1))
          seenNew++
          i++
        } else {
          break
        }
      }
      currentReplacements.push({
        deletedRegion: {
          startLine: Math.max(1, oldStart),
          endLine: Math.max(1, oldStart + Math.max(oldCount, 1) - 1),
        },
        insertedContent: {
          text: redact(inserted.join('\n') + (inserted.length ? '\n' : ''), secrets),
        },
      })
      continue
    }
    i++
  }
  flush()

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

function redactDeep<T>(value: T, secrets: readonly NamedSecret[]): T {
  if (typeof value === 'string') {
    return redact(value, secrets) as unknown as T
  }
  if (Array.isArray(value)) {
    return value.map(item => redactDeep(item, secrets)) as unknown as T
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v !== undefined) out[k] = redactDeep(v, secrets)
    }
    return out as T
  }
  return value
}

export function buildSarifLog(input: SarifBuildInput): SarifLog {
  const secrets = input.secrets ?? []
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

  const results: SarifResult[] = []

  // Deduplicate chain findings while preserving all distinct findings inside approved scope.
  const scopedFindings = input.findings.filter(f => approved.has(f.origin))
  const deduped = deduplicateChainFindings(scopedFindings as unknown as Finding[]) as unknown as SarifFindingInput[]

  for (const finding of deduped) {
    const isStaticVerified = finding.status === 'static_verified' || finding.verificationTier === 'static_verified'
    const isConfirmed = finding.status === 'confirmed'
    if (!isConfirmed && !isStaticVerified) continue

    const ruleMeta = canonicalRuleId(finding)
    const level = severityToSarifLevel(finding.severity)
    const secScore = SEVERITY_TO_SCORE[finding.severity] ?? '5.5'

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
          ...(finding.category ? [`guardian/category/${finding.category}`] : []),
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

    const verificationTier = isStaticVerified ? 'static_verified' : 'runtime_confirmed'
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
            `Guardian verified patch (${patch.id.slice(0, 8)})${patch.dynamicRetestVerdict === 'fixed' ? ' [dynamically retested: reproduced -> fixed]' : ''}: ${patch.reviewNotes?.split('\n')[0] || finding.remediation}`,
            secrets,
          ),
        },
        artifactChanges,
      })
    }

    const messageText = redact(
      `[${verificationTier === 'static_verified' ? 'Static Verified' : 'Runtime Confirmed'}] ${finding.title} (${finding.origin}): ${finding.reason}`,
      secrets,
    )

    results.push({
      ruleId: ruleMeta.id,
      ruleIndex,
      kind: 'fail',
      level,
      message: { text: messageText },
      locations,
      partialFingerprints: {
        'guardian/v3/fingerprint': fp,
        'primaryLocationLineHash': createHash('sha256').update(`${finding.id}:${fp}`).digest('hex').slice(0, 32),
      },
      ...(fixes.length > 0 ? { fixes } : {}),
      properties: {
        guardian: {
          findingId: finding.id,
          origin: finding.origin,
          severity: finding.severity,
          status: finding.status,
          category: finding.category ?? null,
          cwe: ruleMeta.id,
          verificationTier,
          ...(runtimeProofGap ? { runtimeProofGap } : {}),
          exchangeIds: approvedExchanges,
          ...(replaySpecSha256 ? { replaySpecSha256 } : {}),
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
    const covRuleId = `GUARDIAN-COVERAGE-${cleanCat}`
    const catTitle = owaspCategoryTitles[cov.category as OwaspCategory] ?? cov.category

    const ruleIndex = ensureRule(covRuleId, () => ({
      id: covRuleId,
      name: `Coverage: ${catTitle}`,
      shortDescription: { text: `Guardian coverage ledger for ${catTitle}` },
      fullDescription: { text: `Tracks defensive review coverage, ruled-out controls, and open proof gaps for ${catTitle}.` },
      help: {
        text: 'Non-failing coverage record documenting verified controls or open follow-up proof gaps.',
        markdown: 'Non-failing coverage record documenting verified controls or open follow-up proof gaps.',
      },
      defaultConfiguration: { level: 'none' },
      properties: {
        tags: ['security', 'guardian/coverage', `guardian/category/${cleanCat}`],
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
        guardian: {
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
            name: 'Guardian',
            fullName: 'Guardian v3 Defensive Security Platform',
            semanticVersion: '3.0.0',
            informationUri: 'https://github.com/guardian-sec/guardian',
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
        },
      },
    ],
  }

  return redactDeep(log, secrets)
}

function hydrateFindingsForSarif(storage: Store, runId: string, baseFindings: readonly Finding[]): SarifFindingInput[] {
  const rowsById = new Map(
    storage.db.select().from(findingsTable).where(eq(findingsTable.runId, runId)).all().map(row => [row.id, row]),
  )
  return baseFindings.map(f => {
    const row = rowsById.get(f.id)
    return {
      ...f,
      verificationTier: f.verificationTier ?? row?.verificationTier ?? undefined,
      fingerprintHash: f.fingerprintHash ?? row?.fingerprintHash ?? undefined,
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

  const enrichedFindings = hydrateFindingsForSarif(storage, run.id, baseFindings)

  const replaySpecShaById = new Map<string, string>()
  for (const specRow of storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, run.id)).all()) {
    replaySpecShaById.set(specRow.id, specRow.specSha256)
  }

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
    findings: enrichedFindings,
    coverageEntries: covEntries,
    patches,
    replaySpecShaById,
    approvedExchangeIds,
    executionSuccessful: run.status !== 'failed',
    generatedAtIso: new Date(report ? report.createdAt : Date.now()).toISOString(),
    secrets: allSecrets,
  })

  // Final defense-in-depth redaction pass on the serialized SARIF JSON string.
  const content = redact(JSON.stringify(log, null, 2), allSecrets) + '\n'
  const finalLog = JSON.parse(content) as SarifLog
  return {
    filename: `guardian-report-${run.id.slice(0, 8)}-v${reportVersion}.sarif.json`,
    content,
    log: finalLog,
  }
}
