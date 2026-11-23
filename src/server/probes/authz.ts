// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import type { BrokerExchangeResult } from '.././broker.ts'
import type { HttpMethod } from '../../domain.ts'
import { bolaWriteFields, extractCreatedIdFromJson, jsonRecord, randToken, responseSimilarity, scalarMatches, stateValueCandidate } from './context.ts'
import type { DiffContext, DiffOutcome } from './context.ts'
import type { ProbeModule } from './registry.ts'



/**
 * Write-path BOLA proof: a non-owner patches a benign field, the owner reads the object back, and
 * the original value is restored. Only a confirmed owner-visible mutation is reported.
 */
export async function proveWritePathBola(
  ctx: DiffContext,
  opts: { method: 'PUT' | 'PATCH'; id: string; ownerPersona?: string; otherPersona?: string },
): Promise<Record<string, unknown> | null> {
  const { req, runner } = ctx
  if (!opts.ownerPersona || !opts.otherPersona) return null
  const target = req.pathAndQuery.replaceAll('{{id}}', encodeURIComponent(opts.id))
  const readBefore = await runner.send({
    origin: ctx.origin, method: 'GET', pathAndQuery: target, persona: opts.ownerPersona,
    ...(req.session ? { session: req.session } : {}),
  })
  if (!readBefore.ok) return null
  runner.stage(readBefore.ex)
  const beforeJson = jsonRecord(readBefore.ex.body)
  if (!beforeJson) return null
  const candidates = bolaWriteFields
    .filter(f => f in beforeJson && /^(?:string|number|boolean)$/.test(typeof beforeJson[f]))
    .slice(0, 3)
  if (candidates.length === 0) return null
  const bodyShapes = (field: string, value: unknown): Array<Record<string, unknown>> => {
    const direct = { [field]: value }
    const wrapped = { field, value }
    return [wrapped, direct]
  }
  for (const field of candidates) {
    const original = beforeJson[field]
    const expected = stateValueCandidate(original, field)
    for (const writeBody of bodyShapes(field, expected)) {
      const write = await runner.send({
        origin: ctx.origin, method: opts.method, pathAndQuery: target, persona: opts.otherPersona,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(writeBody),
        ...(req.session ? { session: req.session } : {}),
      })
      if (!write.ok) return null
      runner.stage(write.ex)
      if (write.ex.status < 200 || write.ex.status >= 300) continue
      const readAfter = await runner.send({
        origin: ctx.origin, method: 'GET', pathAndQuery: target, persona: opts.ownerPersona,
        ...(req.session ? { session: req.session } : {}),
      })
      if (!readAfter.ok) return null
      runner.stage(readAfter.ex)
      const afterJson = jsonRecord(readAfter.ex.body)
      if (!afterJson) continue
      if (!scalarMatches(afterJson[field], expected)) {
        // A rejected shape may still have written a different value; restore the field before moving on.
        if (!scalarMatches(afterJson[field], original)) {
          for (const restoreBody of bodyShapes(field, original)) {
            const restore = await runner.send({
              origin: ctx.origin, method: opts.method, pathAndQuery: target, persona: opts.ownerPersona,
              headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(restoreBody),
              ...(req.session ? { session: req.session } : {}),
            })
            if (restore.ok) runner.stage(restore.ex)
          }
        }
        continue
      }
      // Best-effort restore by the legitimate owner with the shape that worked.
      const restoreBody = 'field' in writeBody ? { field: writeBody.field, value: original } : { [field]: original }
      const cleanup = await runner.send({
        origin: ctx.origin, method: opts.method, pathAndQuery: target, persona: opts.ownerPersona,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(restoreBody),
        ...(req.session ? { session: req.session } : {}),
      })
      if (cleanup.ok) runner.stage(cleanup.ex)
      return {
        type: 'write_path_bola',
        resourceId: opts.id,
        path: req.pathAndQuery,
        method: opts.method,
        writeBody,
        readPath: req.pathAndQuery,
        stateField: field,
        expectedValue: expected,
        controlValue: original,
        cleanupBody: restoreBody,
        cleanupStatus: cleanup.ok ? cleanup.ex.status : null,
      }
    }
  }
  return null
}



export async function diffAuthorizationMatrix(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, runner, notes, anomalies } = ctx
  const method: HttpMethod = (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE')
    ? req.method
    : 'GET'
  const ids = [...(req.resourceIds ?? [])].filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i)).slice(0, 10)

  // Optional producer-consumer lifecycle creation step as ownerPersona
  if (req.producerPath && req.ownerPersona) {
    const prodRes = await runner.send({
      origin: ctx.origin,
      method: 'POST',
      pathAndQuery: req.producerPath,
      persona: req.ownerPersona,
      headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
      body: JSON.stringify(req.producerBody ?? {}),
      ...(req.session ? { session: req.session } : {}),
    })
    if (prodRes.ok) {
      runner.stage(prodRes.ex)
      const createdId = extractCreatedIdFromJson(prodRes.ex.body)
      if (createdId && !ids.includes(createdId)) ids.unshift(createdId)
    } else {
      notes.push(`producer ${req.producerPath}: ${prodRes.kind}`)
    }
  }

  // Function-level mode: no object placeholder means the same privileged function is invoked by
  // every actor (BFLA). Object-level mode substitutes each harvested resource id.
  const functionLevel = !req.pathAndQuery.includes('{{id}}')
  if (functionLevel && ids.length === 0) ids.push('')
  if (!functionLevel && ids.length === 0) {
    return { verdict: 'inconclusive', summary: 'authz_matrix needs a {{id}} placeholder or resourceIds.', details: {} }
  }

  // Require at least 2 distinct actors (owner+other, or anonymous, or explicit header bypass)
  const hasTwoPersonas = Boolean(req.ownerPersona && req.otherPersona && req.ownerPersona !== req.otherPersona)
  const wantAnonymous = req.includeAnonymous !== false
  const wantHeaderBypass = req.includeHeaderBypass === true || (req.includeHeaderBypass !== false && (hasTwoPersonas || wantAnonymous))
  if (!hasTwoPersonas && !wantAnonymous && !wantHeaderBypass) {
    return {
      verdict: 'inconclusive',
      summary: 'Cross-tenant authz_matrix requires at least 2 personas (ownerPersona + otherPersona) or includeAnonymous/includeHeaderBypass.',
      details: {},
    }
  }

  const actors: Array<{ actor: string; persona?: string; headers?: Record<string, string> }> = []
  if (req.ownerPersona) actors.push({ actor: 'owner', persona: req.ownerPersona })
  if (req.otherPersona) actors.push({ actor: 'other_persona', persona: req.otherPersona })
  if (wantAnonymous) actors.push({ actor: 'anonymous' })
  if (wantHeaderBypass) {
    actors.push({ actor: 'header_bypass', headers: { 'X-Original-URL': '/', 'X-Rewrite-URL': '/', 'X-Middleware-Subrequest': 'middleware:middleware:middleware:middleware:middleware' } })
  }
  if (req.secretScan && req.viewerPersona && !actors.some(a => a.persona === req.viewerPersona)) {
    actors.push({ actor: 'viewer_persona', persona: req.viewerPersona })
  }
  const secretPattern = /rb[s]_[a-z0-9]+_[0-9a-f]{12}/

  const matrix: Array<Record<string, unknown>> = []
  const orderedIds = ids.slice(0, 6)
  let writeProof: Record<string, unknown> | null = null
  /** Last anonymous exchange per concrete path, used as the denied control for disclosure proofs. */
  const anonymousByPath = new Map<string, BrokerExchangeResult>()
  for (const id of orderedIds) {
    const path = functionLevel ? req.pathAndQuery : req.pathAndQuery.replaceAll('{{id}}', encodeURIComponent(id))
    let ownerEx: BrokerExchangeResult | null = null
    if (!functionLevel) {
      // Id-selectivity gate: a value only identifies a resource when it differs from a random
      // nonexistent value. This keeps public/list pages and arbitrary query fields out of the matrix.
      const probeValue = `guardian-none-${randToken(8)}`
      const missingEx = await runner.send({
        origin: ctx.origin, method, pathAndQuery: req.pathAndQuery.replaceAll('{{id}}', encodeURIComponent(probeValue)),
        headers: req.headers, persona: req.ownerPersona,
        ...(req.session ? { session: req.session } : {}),
      })
      if (missingEx.ok) runner.stage(missingEx.ex)
      const refPath = path
      const refEx = req.ownerPersona
        ? await runner.send({ origin: ctx.origin, method, pathAndQuery: refPath, headers: req.headers, persona: req.ownerPersona, ...(req.session ? { session: req.session } : {}) })
        : null
      if (refEx?.ok) {
        runner.stage(refEx.ex)
        ownerEx = refEx.ex
        const missing = missingEx.ok ? missingEx.ex : null
        const nonSelective = method === 'GET' && Boolean(missing) &&
          missing!.status === refEx.ex.status && responseSimilarity(missing!.body, refEx.ex.body) >= 0.98
        if (nonSelective) {
          matrix.push({ resourceId: id, actor: 'owner', status: refEx.ex.status, nonSelective: true })
          continue
        }
      } else if (refEx && !refEx.ok) {
        notes.push(`owner ${id}: ${refEx.kind}`)
      }
      if (ownerEx && ownerEx.status >= 400) {
        matrix.push({ resourceId: id, actor: 'owner', status: ownerEx.status, inaccessible: true })
        continue
      }
      // Safe cross-tenant write proof: PATCH/PUT a benign field, verify with an owner read-back,
      // then restore. Runs once per endpoint on the first owner-readable identifier.
      if (req.writePathRead && !writeProof && !functionLevel && (method === 'PATCH' || method === 'PUT') && req.otherPersona && req.ownerPersona) {
        writeProof = await proveWritePathBola(ctx, { method, id, ownerPersona: req.ownerPersona, otherPersona: req.otherPersona })
        if (writeProof) anomalies.push(writeProof)
      }
    }
    for (const a of actors) {
      // A function-level finding needs a healthy privileged control; otherwise a 2xx from the probe
      // actor only means the endpoint ignores invalid input.
      if (functionLevel && a.actor !== 'owner' && ownerEx && (ownerEx.status < 200 || ownerEx.status >= 300)) continue
      if (a.actor === 'owner' && ownerEx) {
        matrix.push({
          resourceId: id, actor: 'owner', status: ownerEx.status, bodyBytes: ownerEx.bodyBytes,
          bodySha256: ownerEx.bodySha256, accessible: ownerEx.status >= 200 && ownerEx.status < 300,
        })
        continue
      }
      const isMutating = method === 'POST' || method === 'PUT' || method === 'PATCH'
      const bodyPayload = isMutating
        ? JSON.stringify(functionLevel && req.functionBody !== undefined ? req.functionBody : (req.jsonBody ?? {}))
        : undefined
      const res = await runner.send({
        origin: ctx.origin, method, pathAndQuery: path,
        headers: {
          ...(bodyPayload ? { 'Content-Type': 'application/json' } : {}),
          ...(req.headers ?? {}),
          ...(a.headers ?? {}),
          ...(a.actor === 'header_bypass' ? { 'X-Original-URL': path, 'X-Rewrite-URL': path } : {}),
        },
        persona: a.persona,
        ...(bodyPayload ? { body: bodyPayload } : {}),
        ...(req.session ? { session: req.session } : {}),
      })
      if (!res.ok) {
        notes.push(`${a.actor} ${id}: ${res.kind}`)
        matrix.push({ resourceId: id, actor: a.actor, status: null, outcome: res.kind })
        if (res.kind === 'approval') runner.stop('approval_required')
        continue
      }
      runner.stage(res.ex)
      if (a.actor === 'owner') ownerEx = res.ex
      if (a.actor === 'anonymous') anonymousByPath.set(path, res.ex)
      const sim = ownerEx && a.actor !== 'owner' ? responseSimilarity(ownerEx.body, res.ex.body) : null
      const ok2xx = res.ex.status >= 200 && res.ex.status < 300
      const hasSecretFingerprint = (res.ex.secretMatches?.length ?? 0) > 0
      const secretSeen = secretPattern.test(res.ex.body) || /\[redacted\]/i.test(res.ex.body) || hasSecretFingerprint
      matrix.push({
        resourceId: id, actor: a.actor, status: res.ex.status, bodyBytes: res.ex.bodyBytes,
        bodySha256: res.ex.bodySha256, similarityToOwner: sim, accessible: ok2xx,
      })
      if (req.secretScan && a.actor === 'viewer_persona' && secretSeen &&
          !anomalies.some(x => x.type === 'secret_disclosed')) {
        // Prefer an explicit masked-preview control for the same actor; otherwise the endpoint is
        // proven guarded by the anonymous denial already collected in this matrix.
        let controlPath = path
        let controlPersona: string | undefined = a.persona
        let maskedControl: BrokerExchangeResult | null = null
        if (/(?:keys?|tokens?|apikeys?|credentials?|secrets?)/i.test(path)) {
          const maskedPath = `${path}${path.includes('?') ? '&' : '?'}reveal=0`
          const masked = await runner.send({
            origin: ctx.origin, method, pathAndQuery: maskedPath,
            headers: { ...(req.headers ?? {}) },
            persona: a.persona,
            ...(req.session ? { session: req.session } : {}),
          })
          if (masked.ok && masked.ex.status >= 200 && masked.ex.status < 300 &&
              masked.ex.body !== res.ex.body &&
              !secretPattern.test(masked.ex.body) && !/\[redacted\]/i.test(masked.ex.body) &&
              (masked.ex.secretMatches?.length ?? 0) === 0) {
            runner.stage(masked.ex)
            controlPath = maskedPath
            maskedControl = masked.ex
          }
        }
        if (!maskedControl) {
          controlPath = path
          controlPersona = undefined
        }
        const anonymousEx = anonymousByPath.get(path)
        // Entitled baseline: many credential APIs reveal in full only when the caller asks
        // (`reveal=1`) and holds the role. Fetch that view so a masked value served to everyone
        // cannot masquerade as the owner's secret (same mask fingerprint for owner and viewer).
        let entitledEx: BrokerExchangeResult | null = ownerEx
        if (req.ownerPersona && /(?:keys?|tokens?|apikeys?|credentials?|secrets?|integrations?)/i.test(path) && !path.includes('?')) {
          const entitled = await runner.send({
            origin: ctx.origin, method, pathAndQuery: `${path}?reveal=1`,
            headers: { ...(req.headers ?? {}) },
            persona: req.ownerPersona,
            ...(req.session ? { session: req.session } : {}),
          })
          if (entitled.ok && entitled.ex.status >= 200 && entitled.ex.status < 300) entitledEx = entitled.ex
        }
        const relevant = (m: NonNullable<BrokerExchangeResult['secretMatches']>[number]): boolean =>
          !/^(?:jwt|bearer|credential_header)$/.test(m.kind) &&
          !/csrf|xsrf|session/i.test(m.fieldPath ?? '')
        const viewerMatches = (res.ex.secretMatches ?? []).filter(relevant)
        const ownerMatches = (entitledEx?.secretMatches ?? []).filter(relevant)
        const intersect = viewerMatches.some(v => ownerMatches.some(o => o.sha256Prefix === v.sha256Prefix))
        const markerBoth = Boolean(entitledEx) && secretPattern.test(res.ex.body) && secretPattern.test(entitledEx!.body) &&
          responseSimilarity(entitledEx!.body, res.ex.body) >= 0.8
        // A masked control that actually differs proves the unentitled view is the *unmasked* one.
        // Without it, require the exact same pre-redaction secret fingerprint as the entitled view;
        // a masked/own view has a different (short mask) fingerprint and must not confirm.
        if (!maskedControl && !intersect && !markerBoth) continue
        const fingerprints = viewerMatches
          .map(m => m.sha256Prefix)
          .filter((v, i, all) => typeof v === 'string' && /^[0-9a-f]{8,64}$/i.test(v) && all.indexOf(v) === i)
          .slice(0, 8)
        const fieldPaths = viewerMatches
          .map(m => m.fieldPath)
          .filter((v): v is string => typeof v === 'string' && /^[A-Za-z0-9_.\[\]<>-]{1,120}$/.test(v))
          .slice(0, 8)
        anomalies.push({
          type: 'secret_disclosed',
          path,
          method,
          persona: a.persona,
          controlPath,
          ...(controlPersona ? { controlPersona } : {}),
          ...(!controlPersona ? { controlActor: 'anonymous' } : {}),
          ...(anonymousEx ? { controlStatus: anonymousEx.status } : {}),
          ...(maskedControl ? { controlBodyBytes: maskedControl.bodyBytes } : {}),
          secretPattern: secretPattern.source,
          ...(fingerprints.length > 0 ? { secretFingerprints: fingerprints, secretEvidence: 'fingerprint' } : { secretEvidence: 'marker' }),
          ...(fieldPaths.length > 0 ? { secretFieldPaths: fieldPaths } : {}),
          secretMatchSource: maskedControl ? 'masked-control' : intersect ? 'owner-fingerprint' : 'marker-similarity',
          ...(ownerMatches.length > 0 ? { ownerSecretFingerprints: ownerMatches.map(m => m.sha256Prefix).slice(0, 8) } : {}),
          bodyBytes: res.ex.bodyBytes,
          actor: a.actor,
        })
      }
      if (!req.secretScan && a.actor !== 'owner' && ok2xx && (method !== 'GET' || sim === null || sim >= 0.70)) {
        anomalies.push({
          type: 'unauthorized_access', resourceId: id, actor: a.actor, method, status: res.ex.status, similarityToOwner: sim,
          functionLevel,
          ...(method !== 'GET' ? { bodyTemplate: functionLevel && req.functionBody !== undefined ? req.functionBody : (req.jsonBody ?? {}) } : {}),
        })
      }
    }
  }

  if (req.storage && req.dependencyId) {
    try {
      req.storage.markApiDependencyTestedBola(req.dependencyId)
    } catch { /* ignore if dependency row missing */ }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? 'A non-owner actor received an owner-equivalent or mutating 2xx response; build an http_chain Replay Spec from this matrix.'
      : 'Non-owner actors were denied or received different responses.',
    details: { matrix, suggestedReplayKind: 'http_chain' },
  }
}

export const authzProbe: ProbeModule = {
  family: 'authz',
  classes: ['authz_matrix'],
  run: (ctx) => diffAuthorizationMatrix(ctx),
}
