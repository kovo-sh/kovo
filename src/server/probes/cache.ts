// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { randomUUID } from 'node:crypto'
import { appendCacheBuster, randToken, responseSimilarity } from './context.ts'
import type { DiffContext, DiffOutcome } from './context.ts'
import type { ProbeModule } from './registry.ts'



export async function diffCachePoisonDeception(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, runner, send, anomalies, notes } = ctx
  const crossActor: Array<Record<string, unknown>> = []
  // Header-less cache inference: warm the entry as one actor, then prove a different actor receives
  // the warmed body while its own fresh (cache-busted) response differs. This needs no Age/X-Cache.
  if (req.ownerPersona && req.otherPersona && req.ownerPersona !== req.otherPersona) {
    const warmPaths: string[] = [req.pathAndQuery]
    for (const path of warmPaths.slice(0, 1)) {
      const warmPath = appendCacheBuster(path, randomUUID())
      const warm = await runner.send({ origin: ctx.origin, method: 'GET', pathAndQuery: warmPath, persona: req.ownerPersona, probeClass: 'cache_poison_deception' })
      if (!warm.ok || warm.ex.status < 200 || warm.ex.status >= 300) {
        crossActor.push({ path, skipped: 'warm' })
        continue
      }
      runner.stage(warm.ex)
      const repeat = await runner.send({ origin: ctx.origin, method: 'GET', pathAndQuery: warmPath, persona: req.otherPersona, probeClass: 'cache_differential', cacheVerify: true })
      if (!repeat.ok) { crossActor.push({ path, skipped: 'repeat' }); continue }
      runner.stage(repeat.ex)
      const freshPath = appendCacheBuster(req.crossControlPath ?? path, randomUUID())
      const fresh = await runner.send({ origin: ctx.origin, method: 'GET', pathAndQuery: freshPath, persona: req.otherPersona, probeClass: 'cache_differential' })
      if (!fresh.ok) { crossActor.push({ path, skipped: 'fresh' }); continue }
      runner.stage(fresh.ex)
      const simWarmRepeat = responseSimilarity(warm.ex.body, repeat.ex.body)
      const simFreshRepeat = responseSimilarity(fresh.ex.body, repeat.ex.body)
      const simWarmFresh = responseSimilarity(warm.ex.body, fresh.ex.body)
      // Fail closed unless an explicit caller-supplied owner marker (e.g. tenant/store/user handle)
      // proves the warming actor's body was served to the second actor and is absent from its fresh
      // response. Never fall back to fixture canary grammars or entropy regexes.
      const ownerMarker = typeof req.actorMarkers?.owner === 'string' && req.actorMarkers.owner.trim().length > 0
        ? req.actorMarkers.owner.trim()
        : null
      const markerInWarm = Boolean(ownerMarker && warm.ex.body.includes(ownerMarker))
      const markerInRepeat = Boolean(ownerMarker && repeat.ex.body.includes(ownerMarker))
      const markerAbsentInFresh = Boolean(ownerMarker && !fresh.ex.body.includes(ownerMarker))
      const ownerMarkerRepeated = markerInWarm && markerInRepeat && markerAbsentInFresh
      const cacheHitObserved = simWarmRepeat >= 0.9 && simFreshRepeat < 0.95 && simWarmFresh < 0.95 &&
        ownerMarkerRepeated
      crossActor.push({
        path,
        freshPath: req.crossControlPath ?? null,
        simWarmRepeat,
        simFreshRepeat,
        simWarmFresh,
        hasOwnerMarker: Boolean(ownerMarker),
        markerInWarm,
        markerInRepeat,
        markerAbsentInFresh,
        hit: cacheHitObserved,
      })
      notes.push(
        `cache cross-actor warm/repeat=${simWarmRepeat.toFixed(3)} fresh/repeat=${simFreshRepeat.toFixed(3)} `
        + `ownerMarker=${ownerMarker ? (ownerMarkerRepeated ? 'repeated' : 'mismatch') : 'missing_fail_closed'} hit=${cacheHitObserved}`,
      )
      if (cacheHitObserved) {
        const basePath = path.split('?')[0] + (path.includes('?') ? `?${path.split('?').slice(1).join('?')}` : '')
        const controlBase = req.crossControlPath ?? basePath
        anomalies.push({
          type: 'cache_poisoning',
          proof: 'body_repeat',
          path: basePath,
          controlPath: controlBase,
          poisonPersona: req.ownerPersona,
          verifyPersona: req.otherPersona,
          actorDifferential: true,
          cacheHit: false,
          similarity: simWarmRepeat,
          freshOtherSimilarity: simFreshRepeat,
          suggestedReplayKind: 'cache_differential',
        })
        anomalies.push({
          type: 'web_cache_deception',
          mode: 'cross_actor',
          deceptionUrl: basePath,
          similarity: simWarmRepeat,
          freshOtherSimilarity: simFreshRepeat,
          cacheHitObserved: true,
          ownerPersona: req.ownerPersona,
          otherPersona: req.otherPersona,
          suggestedReplayKind: 'cache_differential',
        })
        return {
          verdict: 'signal',
          summary: 'A response warmed by one actor was served to a different actor while its fresh response differed (cache hit inferred without headers).',
          details: { mode: 'cross_actor', simWarmRepeat, simFreshRepeat, simWarmFresh, cacheHitObserved },
        }
      }
    }
  }
  const ctrlGcb = randomUUID()
  const ctrlPath = appendCacheBuster(req.pathAndQuery, ctrlGcb)
  const ctrlEx = await send({
    method: 'GET',
    pathAndQuery: ctrlPath,
    headers: req.headers,
    probeClass: 'cache_poison_deception',
  })
  if (!ctrlEx) return { verdict: 'inconclusive', summary: 'Cache control baseline failed.', details: {} }

  const marker = `poison-${randToken(6)}.kovo.invalid`
  const headerVariants: Array<{ name: string; headers: Record<string, string>; checkMarker: string }> = [
    { name: 'X-Forwarded-Host', headers: { 'X-Forwarded-Host': marker }, checkMarker: marker },
    { name: 'X-Host', headers: { 'X-Host': marker }, checkMarker: marker },
    { name: 'X-Forwarded-Scheme', headers: { 'X-Forwarded-Scheme': 'http' }, checkMarker: '' },
    { name: 'X-Original-URL', headers: { 'X-Original-URL': `/kovo-cache-${randToken(4)}` }, checkMarker: 'kovo-cache-' },
    { name: 'X-Rewrite-URL', headers: { 'X-Rewrite-URL': `/kovo-cache-${randToken(4)}` }, checkMarker: 'kovo-cache-' },
  ]

  const variantsOut: Array<Record<string, unknown>> = []
  for (const hv of headerVariants) {
    const probeGcb = randomUUID()
    const probeUrl = appendCacheBuster(req.pathAndQuery, probeGcb)
    const poisonEx = await send({
      method: 'GET',
      pathAndQuery: probeUrl,
      headers: { ...(req.headers ?? {}), ...hv.headers },
      probeClass: 'cache_poison_deception',
    })
    if (!poisonEx) continue

    // Clean unauthenticated victim verify GET to exact same probeUrl with cacheVerify=true
    const verifyRes = await runner.send({
      origin: ctx.origin,
      method: 'GET',
      pathAndQuery: probeUrl,
      headers: req.headers,
      persona: undefined,
      probeClass: 'cache_differential',
      cacheVerify: true,
    })
    if (!verifyRes.ok) continue
    const verifyEx = verifyRes.ex
    runner.stage(verifyEx)

    const age = Number(verifyEx.respHeaders.age ?? NaN)
    const cacheHitHeader = [
      verifyEx.respHeaders['x-cache'],
      verifyEx.respHeaders['cf-cache-status'],
      verifyEx.respHeaders['x-cache-status'],
      verifyEx.respHeaders['x-proxy-cache'],
    ].some(v => typeof v === 'string' && /\bhit\b/i.test(v))
    const cacheHit = (Number.isFinite(age) && age > 0) || cacheHitHeader
    const markerPersisted = hv.checkMarker ? verifyEx.body.includes(hv.checkMarker) : false
    const simCtrlVerify = responseSimilarity(ctrlEx.body, verifyEx.body)
    const simPoisonVerify = responseSimilarity(poisonEx.body, verifyEx.body)
    const diffPersisted = simCtrlVerify < 0.95 && simPoisonVerify >= 0.85

    variantsOut.push({
      header: hv.name,
      probeGcb,
      cacheHit,
      markerPersisted,
      diffPersisted,
      verifyStatus: verifyEx.status,
    })

    if (markerPersisted || (cacheHit && diffPersisted)) {
      anomalies.push({
        type: 'cache_poisoning',
        header: hv.name,
        probeGcb,
        cacheHit,
        markerPersisted,
        suggestedReplayKind: 'cache_differential',
      })
    }
  }

  // Web Cache Deception variant when authenticated persona is provided
  if (req.persona) {
    const [rawPath, qs] = req.pathAndQuery.split('?')
    const deceptionBase = `${rawPath.replace(/\/+$/, '')}/nonexistent-${randToken(6)}.css${qs ? `?${qs}` : ''}`
    const deceptionGcb = randomUUID()
    const deceptionUrl = appendCacheBuster(deceptionBase, deceptionGcb)
    const authEx = await send({
      method: 'GET',
      pathAndQuery: deceptionUrl,
      headers: req.headers,
      persona: req.persona,
      probeClass: 'cache_poison_deception',
    })
    notes.push(`cache deception auth probe ${deceptionUrl.slice(0, 120)} -> ${authEx?.status ?? 'error'}`)
    if (authEx && authEx.status >= 200 && authEx.status < 300) {
      const verifyRes = await runner.send({
        origin: ctx.origin,
        method: 'GET',
        pathAndQuery: deceptionUrl,
        headers: req.headers,
        persona: undefined,
        probeClass: 'cache_differential',
        cacheVerify: true,
      })
      if (verifyRes.ok) {
        runner.stage(verifyRes.ex)
        const sim = responseSimilarity(authEx.body, verifyRes.ex.body)
        const age = Number(verifyRes.ex.respHeaders.age ?? NaN)
        const hitHdr = /\bhit\b/i.test(verifyRes.ex.respHeaders['x-cache'] ?? verifyRes.ex.respHeaders['cf-cache-status'] ?? '')
        const cached = hitHdr || (Number.isFinite(age) && age > 0)
        notes.push(`cache deception verify status=${verifyRes.ex.status} similarity=${sim.toFixed(3)} cacheHit=${hitHdr} age=${Number.isFinite(age) ? age : 'n/a'}`)
        // Token-set similarity under-weights tiny HTML bodies (a single cache-comment marker can cost
        // ~0.25), so require an explicit cache HIT/Age header and a moderate body match instead.
        if (verifyRes.ex.status === 200 && cached && sim >= 0.6) {
          anomalies.push({
            type: 'web_cache_deception',
            deceptionUrl,
            similarity: sim,
            cacheHit: hitHdr,
            suggestedReplayKind: 'cache_differential',
          })
        }
      }
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? 'Cache poisoning or cache deception differential persisted to a clean unauthenticated fetch; build a cache_differential Replay Spec.'
      : 'No cache poisoning or cache deception persistence observed.',
    details: { variants: variantsOut, crossActor, suggestedReplayKind: 'cache_differential' },
  }
}

export const cacheProbe: ProbeModule = {
  family: 'cache',
  classes: ['cache_poison_deception'],
  run: (ctx) => diffCachePoisonDeception(ctx),
}
