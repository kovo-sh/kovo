// Strict manifest safety/schema validator and pure external impact oracle evaluator.
// Zero container or shell execution — purely declarative validation and evidence evaluation.

import { createHash } from 'node:crypto'
import type {
  BuildPinSpec,
  CausalEdgeBindingKind,
  CleanNegativeControlSpec,
  ComposeServiceRole,
  ExternalImpactOracleSpec,
  ExternalOracleObservation,
  IsolatedComposeSchema,
  ManifestBundle,
  OracleProbeInput,
  OssAnchorManifest,
  SyntheticPersonaSpec,
  ValidationIssue,
  ValidationResult,
} from './types.ts'
import {
  containsForbiddenSecretPattern,
  isFloatingTag,
  isLoopbackBindSpec,
  isLoopbackUrl,
  isPinnedCommitSha,
  isPinnedImageDigest,
  isSyntheticCredentialRef,
} from './safety.ts'

const VALID_EDGE_KINDS = new Set<CausalEdgeBindingKind>([
  'value_binding',
  'derived_crypto_binding',
  'state_transition_binding',
  'async_pivot_binding',
])

const PORT_ALLOWED_ROLES = new Set<ComposeServiceRole>(['app', 'lab_proxy'])

const FORBIDDEN_CAPABILITIES = new Set<string>([
  'ALL',
  'NET_ADMIN',
  'NET_RAW',
  'SYS_ADMIN',
  'SYS_PTRACE',
  'SYS_MODULE',
  'DAC_OVERRIDE',
  'MKNOD',
])

const MUTATING_SQL_RE =
  /\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|REPLACE|EXEC|EXECUTE|GRANT|REVOKE|MERGE|COPY)\b/i

function pushIssue(issues: ValidationIssue[], path: string, code: string, message: string): void {
  issues.push({ path, code, message })
}

export function validateBuildPin(pin: BuildPinSpec | undefined, label: string): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  if (!pin || typeof pin !== 'object') {
    pushIssue(issues, label, 'MISSING_BUILD_PIN', `${label} build pin is required.`)
    return issues
  }
  if (!pin.repoUrl || !/^https:\/\/[^\s]+$/.test(pin.repoUrl)) {
    pushIssue(issues, `${label}.repoUrl`, 'INVALID_REPO_URL', `${label}.repoUrl must be an HTTPS repository URL.`)
  }
  if (!pin.versionTag || isFloatingTag(pin.versionTag)) {
    pushIssue(
      issues,
      `${label}.versionTag`,
      'FLOATING_OR_MISSING_TAG',
      `${label}.versionTag must be an explicit release tag (never floating like 'latest' or 'main').`,
    )
  }
  if (!pin.commitSha || !isPinnedCommitSha(pin.commitSha)) {
    pushIssue(
      issues,
      `${label}.commitSha`,
      'UNPINNED_COMMIT_SHA',
      `${label}.commitSha must be a pinned 40-character lowercase hex commit SHA.`,
    )
  }
  if (!pin.imageRef || pin.imageRef.trim().length === 0 || /:latest$/i.test(pin.imageRef.trim())) {
    pushIssue(
      issues,
      `${label}.imageRef`,
      'UNPINNED_IMAGE_REF',
      `${label}.imageRef must specify a concrete versioned image reference (never ':latest').`,
    )
  }
  if (!pin.imageDigest || !isPinnedImageDigest(pin.imageDigest)) {
    pushIssue(
      issues,
      `${label}.imageDigest`,
      'UNPINNED_IMAGE_DIGEST',
      `${label}.imageDigest must be a pinned OCI digest ('sha256:<64-hex>').`,
    )
  }
  if (pin.pinVerification !== 'pending_docker_lock' && pin.pinVerification !== 'locked') {
    pushIssue(
      issues,
      `${label}.pinVerification`,
      'INVALID_PIN_VERIFICATION',
      `${label}.pinVerification must be 'pending_docker_lock' or 'locked'.`,
    )
  }
  return issues
}

export function validateComposeTemplate(
  compose: IsolatedComposeSchema | undefined,
  label: string,
): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  if (!compose || typeof compose !== 'object') {
    pushIssue(issues, label, 'MISSING_COMPOSE_TEMPLATE', `${label} composeTemplate is required.`)
    return issues
  }
  if (compose.version !== '3.9') {
    pushIssue(issues, `${label}.version`, 'INVALID_COMPOSE_VERSION', `composeTemplate.version must be '3.9'.`)
  }
  if (compose.egressPolicy !== 'deny_all_internal_only') {
    pushIssue(
      issues,
      `${label}.egressPolicy`,
      'INVALID_EGRESS_POLICY',
      `composeTemplate.egressPolicy must be 'deny_all_internal_only'.`,
    )
  }
  if (compose.labProxyMode !== 'loopback_port_publish' && compose.labProxyMode !== 'isolated_lab_proxy') {
    pushIssue(
      issues,
      `${label}.labProxyMode`,
      'INVALID_LAB_PROXY_MODE',
      `composeTemplate.labProxyMode must be 'loopback_port_publish' or 'isolated_lab_proxy'.`,
    )
  }

  const networkEntries = Object.entries(compose.networks ?? {})
  if (networkEntries.length === 0) {
    pushIssue(
      issues,
      `${label}.networks`,
      'MISSING_INTERNAL_NETWORK',
      'At least one --internal Docker lab network must be declared.',
    )
  }
  for (const [netName, net] of networkEntries) {
    if (net.driver !== 'bridge') {
      pushIssue(
        issues,
        `${label}.networks.${netName}.driver`,
        'INVALID_NETWORK_DRIVER',
        `Network '${netName}' must use driver 'bridge'.`,
      )
    }
    if (net.internal !== true) {
      pushIssue(
        issues,
        `${label}.networks.${netName}.internal`,
        'NON_INTERNAL_NETWORK',
        `Network '${netName}' MUST set internal: true (--internal Docker lab isolation).`,
      )
    }
  }

  const serviceEntries = Object.entries(compose.services ?? {})
  if (serviceEntries.length === 0) {
    pushIssue(issues, `${label}.services`, 'MISSING_SERVICES', 'Compose template must define at least one service.')
  }

  for (const [svcName, svc] of serviceEntries) {
    const svcPath = `${label}.services.${svcName}`
    if (svc.networkMode !== undefined) {
      const mode = svc.networkMode.trim().toLowerCase()
      if (mode === 'host' || mode.startsWith('container:') || mode === 'bridge') {
        pushIssue(
          issues,
          `${svcPath}.networkMode`,
          'FORBIDDEN_NETWORK_MODE',
          `Service '${svcName}' uses forbidden networkMode '${svc.networkMode}'; only --internal networks are permitted.`,
        )
      }
    }
    if (svc.privileged === true) {
      pushIssue(
        issues,
        `${svcPath}.privileged`,
        'PRIVILEGED_CONTAINER',
        `Service '${svcName}' must not run with privileged: true.`,
      )
    }
    for (const cap of svc.capAdd ?? []) {
      if (FORBIDDEN_CAPABILITIES.has(cap.toUpperCase())) {
        pushIssue(
          issues,
          `${svcPath}.capAdd`,
          'FORBIDDEN_CAPABILITY',
          `Service '${svcName}' requests forbidden Linux capability '${cap}'.`,
        )
      }
    }
    if (!svc.imageRef || /:latest$/i.test(svc.imageRef.trim())) {
      pushIssue(
        issues,
        `${svcPath}.imageRef`,
        'UNPINNED_SERVICE_IMAGE_REF',
        `Service '${svcName}' imageRef must not be empty or ':latest'.`,
      )
    }
    if (!svc.imageDigest || !isPinnedImageDigest(svc.imageDigest)) {
      pushIssue(
        issues,
        `${svcPath}.imageDigest`,
        'UNPINNED_SERVICE_IMAGE_DIGEST',
        `Service '${svcName}' imageDigest must be a pinned 'sha256:<64-hex>' digest.`,
      )
    }
    if (!Array.isArray(svc.networks) || svc.networks.length === 0) {
      pushIssue(
        issues,
        `${svcPath}.networks`,
        'UNATTACHED_SERVICE_NETWORK',
        `Service '${svcName}' must attach to at least one declared --internal network.`,
      )
    } else {
      for (const netRef of svc.networks) {
        const net = compose.networks?.[netRef]
        if (!net) {
          pushIssue(
            issues,
            `${svcPath}.networks`,
            'UNKNOWN_NETWORK_REF',
            `Service '${svcName}' references undeclared network '${netRef}'.`,
          )
        } else if (net.internal !== true) {
          pushIssue(
            issues,
            `${svcPath}.networks`,
            'NON_INTERNAL_NETWORK_REF',
            `Service '${svcName}' references non-internal network '${netRef}'.`,
          )
        }
      }
    }

    if (svc.ports && svc.ports.length > 0) {
      if (!PORT_ALLOWED_ROLES.has(svc.role)) {
        pushIssue(
          issues,
          `${svcPath}.ports`,
          'INTERNAL_SERVICE_PORT_EXPOSED',
          `Internal service '${svcName}' (role '${svc.role}') must not publish host ports.`,
        )
      }
      for (const bind of svc.ports) {
        if (!isLoopbackBindSpec(bind)) {
          pushIssue(
            issues,
            `${svcPath}.ports`,
            'NON_LOOPBACK_PORT_BIND',
            `Service '${svcName}' port '${bind}' must bind strictly to 127.0.0.1:<hostPort>:<containerPort>.`,
          )
        }
      }
    }

    for (const [envKey, envVal] of Object.entries(svc.environment ?? {})) {
      if (containsForbiddenSecretPattern(envVal)) {
        pushIssue(
          issues,
          `${svcPath}.environment.${envKey}`,
          'REAL_SECRET_DETECTED',
          `Service '${svcName}' environment variable '${envKey}' matches a real secret pattern; use synthetic credentials only.`,
        )
      }
    }
  }

  return issues
}

export function validateExternalImpactOracle(
  oracle: ExternalImpactOracleSpec | undefined,
  label: string,
  serviceNames?: ReadonlySet<string>,
): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  if (!oracle || typeof oracle !== 'object') {
    pushIssue(issues, label, 'MISSING_IMPACT_ORACLE', `${label} impactOracle is required.`)
    return issues
  }
  if (!oracle.oracleId || oracle.oracleId.trim().length === 0) {
    pushIssue(issues, `${label}.oracleId`, 'MISSING_ORACLE_ID', 'oracleId is required.')
  }
  if (!oracle.targetService || oracle.targetService.trim().length === 0) {
    pushIssue(issues, `${label}.targetService`, 'MISSING_TARGET_SERVICE', 'targetService is required.')
  } else if (serviceNames && !serviceNames.has(oracle.targetService)) {
    pushIssue(
      issues,
      `${label}.targetService`,
      'UNKNOWN_ORACLE_TARGET_SERVICE',
      `targetService '${oracle.targetService}' is not defined in composeTemplate.services.`,
    )
  }
  if (!Number.isInteger(oracle.pollTimeoutMs) || oracle.pollTimeoutMs < 100 || oracle.pollTimeoutMs > 60_000) {
    pushIssue(
      issues,
      `${label}.pollTimeoutMs`,
      'INVALID_POLL_TIMEOUT',
      'pollTimeoutMs must be an integer between 100 and 60000 ms.',
    )
  }
  if (!oracle.runScopedCanaryPrefix || !oracle.runScopedCanaryPrefix.startsWith('oss_canary_')) {
    pushIssue(
      issues,
      `${label}.runScopedCanaryPrefix`,
      'INVALID_CANARY_PREFIX',
      `runScopedCanaryPrefix must start with 'oss_canary_'.`,
    )
  }

  switch (oracle.kind) {
    case 'db_query': {
      const q = (oracle.readOnlyQuery ?? '').trim()
      if (!/^SELECT\s+/i.test(q) || MUTATING_SQL_RE.test(q)) {
        pushIssue(
          issues,
          `${label}.readOnlyQuery`,
          'NON_READONLY_ORACLE_QUERY',
          'db_query oracle readOnlyQuery must be a strictly read-only SELECT statement.',
        )
      }
      if (!oracle.expectedPredicate?.column) {
        pushIssue(issues, `${label}.expectedPredicate`, 'MISSING_DB_PREDICATE', 'expectedPredicate.column is required.')
      }
      break
    }
    case 'container_log': {
      if (!oracle.expectedPattern || oracle.expectedPattern.trim().length === 0) {
        pushIssue(issues, `${label}.expectedPattern`, 'MISSING_LOG_PATTERN', 'expectedPattern is required.')
      } else {
        try {
          // Validate regular expression syntax statically
          new RegExp(oracle.expectedPattern)
        } catch {
          pushIssue(issues, `${label}.expectedPattern`, 'INVALID_LOG_REGEX', 'expectedPattern must be a valid RegExp.')
        }
      }
      if (oracle.forbidPattern) {
        try {
          new RegExp(oracle.forbidPattern)
        } catch {
          pushIssue(issues, `${label}.forbidPattern`, 'INVALID_LOG_REGEX', 'forbidPattern must be a valid RegExp.')
        }
      }
      break
    }
    case 'loopback_oob_collector': {
      if (!oracle.collectorUrl || !isLoopbackUrl(oracle.collectorUrl)) {
        pushIssue(
          issues,
          `${label}.collectorUrl`,
          'NON_LOOPBACK_OOB_URL',
          `loopback_oob_collector collectorUrl '${oracle.collectorUrl}' must target 127.0.0.1 or [::1].`,
        )
      }
      if (!oracle.expectedPathPrefix || !oracle.expectedPathPrefix.startsWith('/')) {
        pushIssue(
          issues,
          `${label}.expectedPathPrefix`,
          'INVALID_OOB_PATH_PREFIX',
          'expectedPathPrefix must start with "/".',
        )
      }
      break
    }
    case 'file_integrity': {
      if (!oracle.watchPath || !oracle.watchPath.startsWith('/') || oracle.watchPath.includes('..')) {
        pushIssue(
          issues,
          `${label}.watchPath`,
          'INVALID_WATCH_PATH',
          'file_integrity watchPath must be a normalized absolute path without "..".',
        )
      }
      break
    }
    default: {
      pushIssue(issues, `${label}.kind`, 'UNKNOWN_ORACLE_KIND', 'Unsupported ExternalImpactOracleSpec kind.')
    }
  }

  return issues
}

function validatePersonas(
  personas: SyntheticPersonaSpec[] | undefined,
  label: string,
  requireAttackerOrigin: boolean,
): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  if (!Array.isArray(personas) || personas.length === 0) {
    pushIssue(issues, label, 'MISSING_PERSONAS', 'At least one synthetic persona is required.')
    return issues
  }
  const seen = new Set<string>()
  let attackerOrigins = 0
  for (const [idx, p] of personas.entries()) {
    const pPath = `${label}[${idx}]`
    if (!p.personaId || seen.has(p.personaId)) {
      pushIssue(issues, `${pPath}.personaId`, 'INVALID_OR_DUPLICATE_PERSONA', `Duplicate or empty personaId '${p.personaId}'.`)
    }
    seen.add(p.personaId)
    if (!isSyntheticCredentialRef(p.credentialRef)) {
      pushIssue(
        issues,
        `${pPath}.credentialRef`,
        'NON_SYNTHETIC_CREDENTIAL_REF',
        `Persona '${p.personaId}' credentialRef must match 'oss_lab_*'.`,
      )
    }
    if (containsForbiddenSecretPattern(p.username) || containsForbiddenSecretPattern(p.credentialRef)) {
      pushIssue(issues, pPath, 'REAL_SECRET_DETECTED', `Persona '${p.personaId}' contains forbidden secret pattern.`)
    }
    if (p.allowedAsChainOrigin) {
      attackerOrigins += 1
    }
  }
  if (requireAttackerOrigin && attackerOrigins === 0) {
    pushIssue(
      issues,
      label,
      'NO_ATTACKER_ORIGIN_PERSONA',
      'At least one persona must set allowedAsChainOrigin: true.',
    )
  }
  return issues
}

export function validateOssAnchorManifest(anchor: OssAnchorManifest): ValidationResult {
  const issues: ValidationIssue[] = []
  const label = anchor.anchorId || 'anchor'

  if (anchor.schemaVersion !== '1.0') {
    pushIssue(issues, `${label}.schemaVersion`, 'INVALID_SCHEMA_VERSION', `schemaVersion must be '1.0'.`)
  }
  if (!anchor.anchorId || anchor.anchorId.trim().length === 0) {
    pushIssue(issues, `${label}.anchorId`, 'MISSING_ANCHOR_ID', 'anchorId is required.')
  }
  if (!anchor.project || anchor.project.trim().length === 0) {
    pushIssue(issues, `${label}.project`, 'MISSING_PROJECT', 'project is required.')
  }
  if (anchor.split !== 'dev' && anchor.split !== 'sealed') {
    pushIssue(issues, `${label}.split`, 'INVALID_SPLIT', `split must be 'dev' or 'sealed'.`)
  }
  if (!Number.isInteger(anchor.hopCount) || anchor.hopCount < 3 || anchor.hopCount > 6) {
    pushIssue(issues, `${label}.hopCount`, 'INVALID_HOP_COUNT', 'Multi-hop OSS anchors must have hopCount in 3..6.')
  }
  if (!Array.isArray(anchor.hops) || anchor.hops.length !== anchor.hopCount) {
    pushIssue(
      issues,
      `${label}.hops`,
      'HOP_COUNT_MISMATCH',
      `hops.length (${anchor.hops?.length ?? 0}) must equal hopCount (${anchor.hopCount}).`,
    )
  }

  const hopIds = new Set<string>()
  for (const [idx, hop] of (anchor.hops ?? []).entries()) {
    const hPath = `${label}.hops[${idx}]`
    if (!hop.hopId || hopIds.has(hop.hopId)) {
      pushIssue(issues, `${hPath}.hopId`, 'INVALID_OR_DUPLICATE_HOP_ID', `Duplicate or empty hopId '${hop.hopId}'.`)
    }
    hopIds.add(hop.hopId)
    if (hop.order !== idx + 1) {
      pushIssue(issues, `${hPath}.order`, 'NON_SEQUENTIAL_HOP_ORDER', `Hop '${hop.hopId}' order must be ${idx + 1}.`)
    }
    if (hop.order > 1 && (!hop.incomingEdgeKind || !VALID_EDGE_KINDS.has(hop.incomingEdgeKind))) {
      pushIssue(
        issues,
        `${hPath}.incomingEdgeKind`,
        'INVALID_EDGE_BINDING_KIND',
        `Hop '${hop.hopId}' (order ${hop.order}) must declare a valid CausalEdgeBindingKind.`,
      )
    }
  }

  issues.push(...validateBuildPin(anchor.vulnerableBuild, `${label}.vulnerableBuild`))
  issues.push(...validateBuildPin(anchor.patchedBuild, `${label}.patchedBuild`))

  if (
    anchor.vulnerableBuild?.commitSha &&
    anchor.patchedBuild?.commitSha &&
    anchor.vulnerableBuild.commitSha === anchor.patchedBuild.commitSha
  ) {
    pushIssue(
      issues,
      `${label}.patchedBuild.commitSha`,
      'IDENTICAL_VULN_AND_PATCH_COMMIT',
      'patchedBuild.commitSha must differ from vulnerableBuild.commitSha.',
    )
  }

  if (!Array.isArray(anchor.expectedPatchBrokeHopIds) || anchor.expectedPatchBrokeHopIds.length === 0) {
    pushIssue(
      issues,
      `${label}.expectedPatchBrokeHopIds`,
      'MISSING_EXPECTED_PATCH_BROKE_HOPS',
      'expectedPatchBrokeHopIds must name at least one hop in hops.',
    )
  } else {
    for (const hid of anchor.expectedPatchBrokeHopIds) {
      if (!hopIds.has(hid)) {
        pushIssue(
          issues,
          `${label}.expectedPatchBrokeHopIds`,
          'UNKNOWN_PATCH_BROKE_HOP_ID',
          `expectedPatchBrokeHopIds entry '${hid}' is not in hops.`,
        )
      }
    }
  }

  issues.push(...validatePersonas(anchor.personas, `${label}.personas`, true))
  issues.push(...validateComposeTemplate(anchor.composeTemplate, `${label}.composeTemplate`))

  const serviceNames = new Set(Object.keys(anchor.composeTemplate?.services ?? {}))
  issues.push(...validateExternalImpactOracle(anchor.impactOracle, `${label}.impactOracle`, serviceNames))

  return { valid: issues.length === 0, issues }
}

export function validateCleanNegativeControl(control: CleanNegativeControlSpec): ValidationResult {
  const issues: ValidationIssue[] = []
  const label = control.controlId || 'clean_control'

  if (control.schemaVersion !== '1.0') {
    pushIssue(issues, `${label}.schemaVersion`, 'INVALID_SCHEMA_VERSION', `schemaVersion must be '1.0'.`)
  }
  if (!control.controlId || control.controlId.trim().length === 0) {
    pushIssue(issues, `${label}.controlId`, 'MISSING_CONTROL_ID', 'controlId is required.')
  }
  if (control.maxAllowedFindings !== 0) {
    pushIssue(
      issues,
      `${label}.maxAllowedFindings`,
      'NON_ZERO_CLEAN_CONTROL_LIMIT',
      'Clean negative controls MUST enforce maxAllowedFindings: 0.',
    )
  }

  issues.push(...validateBuildPin(control.patchedBuild, `${label}.patchedBuild`))
  issues.push(...validatePersonas(control.personas, `${label}.personas`, false))
  issues.push(...validateComposeTemplate(control.composeTemplate, `${label}.composeTemplate`))

  const serviceNames = new Set(Object.keys(control.composeTemplate?.services ?? {}))
  for (const [idx, oracle] of (control.impactOracles ?? []).entries()) {
    issues.push(...validateExternalImpactOracle(oracle, `${label}.impactOracles[${idx}]`, serviceNames))
  }

  return { valid: issues.length === 0, issues }
}

export function validateManifestBundle(bundle: ManifestBundle): ValidationResult {
  const issues: ValidationIssue[] = []
  if (!bundle || typeof bundle !== 'object') {
    pushIssue(issues, 'bundle', 'INVALID_BUNDLE', 'Manifest bundle must be an object.')
    return { valid: false, issues }
  }
  if (bundle.schemaVersion !== '1.0') {
    pushIssue(issues, 'bundle.schemaVersion', 'INVALID_SCHEMA_VERSION', `Bundle schemaVersion must be '1.0'.`)
  }

  const seenIds = new Set<string>()
  if (bundle.bundleKind === 'dev_anchors' || bundle.bundleKind === 'sealed_anchors') {
    const expectedSplit = bundle.bundleKind === 'dev_anchors' ? 'dev' : 'sealed'
    if (!Array.isArray(bundle.anchors) || bundle.anchors.length === 0) {
      pushIssue(issues, 'bundle.anchors', 'EMPTY_ANCHORS', 'Anchor bundle must contain at least one anchor.')
    } else {
      for (const anchor of bundle.anchors) {
        if (seenIds.has(anchor.anchorId)) {
          pushIssue(issues, `bundle.anchors.${anchor.anchorId}`, 'DUPLICATE_ANCHOR_ID', `Duplicate anchorId '${anchor.anchorId}'.`)
        }
        seenIds.add(anchor.anchorId)
        if (anchor.split !== expectedSplit) {
          pushIssue(
            issues,
            `bundle.anchors.${anchor.anchorId}.split`,
            'SPLIT_MISMATCH',
            `Anchor '${anchor.anchorId}' has split '${anchor.split}', expected '${expectedSplit}'.`,
          )
        }
        const res = validateOssAnchorManifest(anchor)
        issues.push(...res.issues)
      }
    }
  } else if (bundle.bundleKind === 'clean_controls') {
    if (!Array.isArray(bundle.cleanControls) || bundle.cleanControls.length === 0) {
      pushIssue(
        issues,
        'bundle.cleanControls',
        'EMPTY_CLEAN_CONTROLS',
        'Clean-control bundle must contain at least one CleanNegativeControlSpec.',
      )
    } else {
      for (const ctrl of bundle.cleanControls) {
        if (seenIds.has(ctrl.controlId)) {
          pushIssue(
            issues,
            `bundle.cleanControls.${ctrl.controlId}`,
            'DUPLICATE_CONTROL_ID',
            `Duplicate controlId '${ctrl.controlId}'.`,
          )
        }
        seenIds.add(ctrl.controlId)
        const res = validateCleanNegativeControl(ctrl)
        issues.push(...res.issues)
      }
    }
  } else {
    pushIssue(issues, 'bundle.bundleKind', 'INVALID_BUNDLE_KIND', 'Unknown manifest bundleKind.')
  }

  return { valid: issues.length === 0, issues }
}

// ---------------------------------------------------------------------------
// Pure External Impact Oracle Evaluator (no container execution)
// ---------------------------------------------------------------------------

function makeObservationId(targetId: string, oracleId: string, runId: string, buildTarget: string): string {
  const hash = createHash('sha256')
    .update(`${targetId}:${oracleId}:${runId}:${buildTarget}`)
    .digest('hex')
    .slice(0, 12)
  return `obs_${hash}`
}

export function evaluateOracleEvidence(
  spec: ExternalImpactOracleSpec,
  targetId: string,
  runId: string,
  buildTarget: 'vulnerable' | 'patched',
  probe: OracleProbeInput,
): ExternalOracleObservation {
  const observationId = makeObservationId(targetId, spec.oracleId, runId, buildTarget)
  if (probe.kind !== spec.kind) {
    return {
      observationId,
      targetId,
      oracleId: spec.oracleId,
      kind: spec.kind,
      buildTarget,
      observed: false,
      observedAtMs: probe.observedAtMs,
      runId,
      correlationId: probe.correlationId,
      detail: `Oracle kind mismatch: spec expects '${spec.kind}', probe provided '${probe.kind}'.`,
    }
  }

  switch (spec.kind) {
    case 'db_query': {
      const dbProbe = probe as Extract<OracleProbeInput, { kind: 'db_query' }>
      const pred = spec.expectedPredicate
      let matchedRows = 0
      let matchedValue: string | undefined
      for (const row of dbProbe.rows) {
        const val = row[pred.column]
        let rowMatches = false
        if (pred.matchMode === 'row_count_gt_zero') {
          rowMatches = val !== undefined && val !== null
        } else if (pred.matchMode === 'boolean_true') {
          rowMatches = val === true || val === 1 || val === 'true'
        } else if (pred.matchMode === 'equals') {
          rowMatches = val === pred.expectedValue
        } else if (pred.matchMode === 'contains') {
          const needle = String(pred.expectedValue ?? spec.runScopedCanaryPrefix)
          rowMatches = typeof val === 'string' && val.includes(needle)
        }
        if (rowMatches) {
          matchedRows += 1
          if (matchedValue === undefined && val !== undefined && val !== null) {
            matchedValue = String(val)
          }
        }
      }
      const observed = matchedRows > 0
      return {
        observationId,
        targetId,
        oracleId: spec.oracleId,
        kind: spec.kind,
        buildTarget,
        observed,
        observedAtMs: dbProbe.observedAtMs,
        runId,
        correlationId: dbProbe.correlationId,
        matchedRows,
        matchedValue,
        detail: observed
          ? `DB oracle '${spec.oracleId}' matched ${matchedRows} row(s) on column '${pred.column}'.`
          : `DB oracle '${spec.oracleId}' observed 0 matching rows.`,
      }
    }

    case 'container_log': {
      const logProbe = probe as Extract<OracleProbeInput, { kind: 'container_log' }>
      const pattern = new RegExp(spec.expectedPattern)
      const forbid = spec.forbidPattern ? new RegExp(spec.forbidPattern) : null
      const candidateLines = logProbe.lines.filter(
        (line) => spec.stream === 'both' || line.stream === spec.stream,
      )
      const matched = candidateLines.find(
        (line) => pattern.test(line.text) && !(forbid && forbid.test(line.text)),
      )
      const observed = matched !== undefined
      return {
        observationId,
        targetId,
        oracleId: spec.oracleId,
        kind: spec.kind,
        buildTarget,
        observed,
        observedAtMs: matched?.timestampMs ?? logProbe.observedAtMs,
        runId,
        correlationId: logProbe.correlationId,
        matchedValue: matched ? matched.text.slice(0, 160) : undefined,
        detail: observed
          ? `Container log oracle '${spec.oracleId}' matched structured event on ${matched.stream}.`
          : `Container log oracle '${spec.oracleId}' found no matching log event.`,
      }
    }

    case 'loopback_oob_collector': {
      const oobProbe = probe as Extract<OracleProbeInput, { kind: 'loopback_oob_collector' }>
      const matchedReq = oobProbe.requests.find((req) => {
        const methodOk =
          spec.expectedMethod === 'ANY' || req.method.toUpperCase() === spec.expectedMethod
        const pathOk = req.path.startsWith(spec.expectedPathPrefix)
        const canaryOk =
          !spec.requireCanaryToken ||
          (typeof req.canaryToken === 'string' && req.canaryToken.startsWith(spec.runScopedCanaryPrefix))
        return methodOk && pathOk && canaryOk
      })
      const observed = matchedReq !== undefined
      return {
        observationId,
        targetId,
        oracleId: spec.oracleId,
        kind: spec.kind,
        buildTarget,
        observed,
        observedAtMs: matchedReq?.receivedAtMs ?? oobProbe.observedAtMs,
        runId,
        correlationId: matchedReq?.correlationId ?? oobProbe.correlationId,
        matchedValue: matchedReq ? `${matchedReq.method.toUpperCase()} ${matchedReq.path}` : undefined,
        detail: observed
          ? `Loopback OOB collector oracle '${spec.oracleId}' observed callback on '${matchedReq.path}'.`
          : `Loopback OOB collector oracle '${spec.oracleId}' observed no matching callback.`,
      }
    }

    case 'file_integrity': {
      const fiProbe = probe as Extract<OracleProbeInput, { kind: 'file_integrity' }>
      let observed = false
      let matchedValue: string | undefined
      if (spec.checkMode === 'marker_created') {
        observed = fiProbe.exists
        matchedValue = observed ? spec.watchPath : undefined
      } else if (spec.checkMode === 'checksum_changed') {
        observed =
          fiProbe.exists &&
          typeof fiProbe.sha256 === 'string' &&
          fiProbe.sha256.length > 0 &&
          fiProbe.sha256 !== spec.baselineSha256
        matchedValue = observed ? fiProbe.sha256 : undefined
      } else if (spec.checkMode === 'canary_written') {
        observed =
          fiProbe.exists &&
          typeof fiProbe.contentPreview === 'string' &&
          fiProbe.contentPreview.includes(spec.runScopedCanaryPrefix)
        matchedValue = observed ? spec.runScopedCanaryPrefix : undefined
      }
      return {
        observationId,
        targetId,
        oracleId: spec.oracleId,
        kind: spec.kind,
        buildTarget,
        observed,
        observedAtMs: fiProbe.observedAtMs,
        runId,
        correlationId: fiProbe.correlationId,
        matchedValue,
        detail: observed
          ? `File integrity oracle '${spec.oracleId}' verified '${spec.checkMode}' on '${spec.watchPath}'.`
          : `File integrity oracle '${spec.oracleId}' observed no unauthorized file modification.`,
      }
    }
  }
}
