/** auth_protocol_proof / cache_differential spec synthesis. */
import { randomBytes } from 'node:crypto'
import { appendQuery, baseFields, is2xx, jqStr, sameAsControl, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { probePathFor } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

type Mutation = Record<string, unknown>

function mutationFor(name: string): Mutation | null {
  switch (name) {
    case 'alg_none': return { kind: 'alg_none' }
    case 'strip_signature': return { kind: 'strip_signature' }
    case 'expired_replay': return { kind: 'expired_replay', skewSeconds: 7200 }
    case 'kid_inject': return { kind: 'kid_inject', value: "1' OR '1'='1" }
    case 'rs256_to_hs256_jwks': return { kind: 'rs256_to_hs256_jwks' }
    case 'claim_swap': return { kind: 'claim_swap', claims: { role: 'admin' } }
    case 'jku_x5u_canary': return { kind: 'jku_x5u_canary', header: 'jku' }
    default: return null
  }
}

const AUTH_PROTO_BASE = 'Authentication protocol differential'

/**
 * Body-token JWT routes (e.g. refresh/assertion endpoints) never expose the credential as a bearer
 * header, so the broker's header-mutation primitive cannot reach them. Mint an unsigned token whose
 * subject is the real victim identity observed by the probe, plus a control token with an unknown
 * subject, and require a rejected control + an issued access token/session as the processed effect.
 */
function jwtBodySpecs(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const out: SynthesizedSpec[] = []
  for (const a of o.anomalies) {
    if (a.type !== 'jwt_body_token_bypass' && a.type !== 'jwt_body_token_forgery') continue
    if (a.tokenTransport !== undefined && a.tokenTransport !== 'json' && a.tokenTransport !== 'form') continue
    const path = String(a.path ?? o.hyp.endpoint.path)
    const field = String(a.tokenField ?? a.field ?? 'token')
    if (!path.startsWith('/') || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(field)) continue
    const subject = typeof a.subject === 'string' && /^[A-Za-z0-9@._:-]{1,128}$/.test(a.subject) ? a.subject : null
    if (!subject) continue
    const bogus = `guardian-no-such-subject-${randomBytes(4).toString('hex')}`
    const method = String(a.method ?? 'POST').toUpperCase() === 'POST' ? 'POST' : 'POST'
    const encoding = a.encoding === 'form' || a.bodyEncoding === 'form' ? 'form' : 'json'
    const extra = a.body && typeof a.body === 'object' && !Array.isArray(a.body) ? a.body as Record<string, unknown> : {}
    const body = (token: string) => {
      const all = { ...extra, [field]: token }
      if (encoding === 'form') {
        return {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          textBody: Object.entries(all).map(([k, v]) => {
            const raw = String(v)
            return `${encodeURIComponent(k)}=${raw.includes('{{') ? raw : encodeURIComponent(raw)}`
          }).join('&'),
        }
      }
      return { headers: { 'Content-Type': 'application/json' }, jsonBody: all }
    }
    const tokenMints = [
      { name: 'forged_body_token', header: { typ: 'JWT' }, payload: { sub: subject, iat: '{{now}}', exp: '{{now_plus_1h}}' }, signature: 'none' as const },
      { name: 'bogus_body_token', header: { typ: 'JWT' }, payload: { sub: bogus, iat: '{{now}}', exp: '{{now_plus_1h}}' }, signature: 'none' as const },
    ]
    const effectPath = typeof a.effectPath === 'string' && a.effectPath.startsWith('/') ? a.effectPath : null
    const steps: Array<Record<string, unknown>> = [
      stepOf(env, 'c1', 'control', 'Unsigned token for an unknown subject is rejected', {
        method, pathAndQuery: path, ...body('{{bogus_body_token}}'),
      }, null, {}, [400, 401, 403]),
      stepOf(env, 'p1', 'probe', 'Unsigned token for the victim subject is accepted', {
        method, pathAndQuery: path, ...body('{{forged_body_token}}'),
      }, null, {}, [200, 201, 202, 204]),
    ]
    if (effectPath) steps.push(stepOf(env, 'p2', 'probe', 'Read back the session bound by the forged token', { method: 'GET', pathAndQuery: effectPath }, null))
    const confirmed = effectPath
      ? `(${is2xx('p1')} and ${is2xx('p2')} and ((.steps.p2.body // "") | contains(${jqStr(subject)})))`
      : `(${is2xx('p1')} and ((.steps.p1.bodyBytes // 0) > 0))`
    const jq = `{ controlPassed: (.steps.c1.status >= 400 and .steps.c1.status < 500), ` +
      `confirmed: ${confirmed}, ` +
      `observed: ("forged status=" + (.steps.p1.status | tostring)), expected: "unsigned tokens are rejected regardless of subject" }`
    out.push({
      kind: 'auth_protocol_proof',
      spec: {
        ...baseFields(env, `${AUTH_PROTO_BASE}: unsigned JWT in the request body`, 'CWE-347', 'broken-authentication', 'high', jq),
        kind: 'auth_protocol_proof',
        protocol: 'jwt',
        tokenMints,
        steps,
      },
    })
  }
  return out
}

function jwtSpecs(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const persona = env.jwtPersona
  if (!persona) return []
  const path = o.hyp.endpoint.path
  const parts: RequestParts = { method: 'GET', pathAndQuery: path }
  const out: SynthesizedSpec[] = []
  for (const a of o.anomalies) {
    const isCanary = a.type === 'jwt_jku_x5u_oob_canary'
    if (a.type !== 'jwt_auth_mutation_bypass' && !isCanary) continue
    const mutation = mutationFor(String(a.mutation))
    if (!mutation) continue
    const jq = isCanary
      ? `{ controlPassed: ${is2xx('c1')}, confirmed: (.canaryProof.probeTriggered == true and .canaryProof.controlTriggered == false), observed: ("probeCallback=" + ((.canaryProof.probeTriggered // false) | tostring)), expected: "token header URL is never fetched" }`
      : `{ controlPassed: (${is2xx('c1')} and (.steps.c2.status == 401 or .steps.c2.status == 403)), confirmed: (${is2xx('p1')} and ${sameAsControl('p1', 'c1')}), observed: ("status=" + (.steps.p1.status | tostring)), expected: "tampered token rejected" }`
    out.push({
      kind: 'auth_protocol_proof',
      spec: {
        ...baseFields(env, `${AUTH_PROTO_BASE}: ${String(a.mutation)}`, 'CWE-347', 'broken-authentication', 'high', jq),
        kind: 'auth_protocol_proof',
        protocol: 'jwt',
        steps: [
          stepOf(env, 'c1', 'control', 'Valid persona token is accepted', parts, persona),
          ...(isCanary ? [] : [stepOf(env, 'c2', 'control', 'Anonymous caller is rejected', parts, null, {}, [401, 403])]),
          stepOf(env, 'p1', 'probe', `Request with ${String(a.mutation)} token mutation`, parts, persona, { authMutation: mutation }, isCanary ? [200, 401, 403] : undefined),
        ],
      },
    })
  }
  return out
}

function oauthSpecs(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const seed = o.ctx?.seedQuery
  const path = o.hyp.endpoint.path.split('?')[0]
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
  const withParams = (set: Record<string, string>) => {
    const u = new URL(seed ? `${path}?${seed}` : path, 'http://guardian.invalid')
    for (const [k, v] of Object.entries(set)) u.searchParams.set(k, v)
    return u.pathname + u.search
  }
  const orig = (() => { try { return new URL(new URL(`${path}?${seed ?? ''}`, 'http://guardian.invalid').searchParams.get('redirect_uri') ?? 'https://app.example.invalid/cb') } catch { return new URL('https://app.example.invalid/cb') } })()
  const seedVariants: Record<string, string> = {
    userinfo_at: `https://${orig.host}@evil.invalid/cb`,
    backslash_at: `https://${orig.host}\\@evil.invalid/cb`,
    subdomain_prefix: `https://${orig.hostname}.evil.invalid/cb`,
    suffix_match: `https://evil-${orig.hostname}/cb`,
  }
  const control: RequestParts = { method: 'GET', pathAndQuery: withParams({ redirect_uri: 'https://unrelated-control.invalid/cb', code_challenge_method: 'S256', code_challenge: challenge }) }

  // When no seed query was mined, reconstruct the accepted redirect value (and the registered
  // target) directly from the probe's observed Location header. Nothing here is target-specific.
  const evidenceFromAnomaly = (a: Record<string, unknown>): { probePath: string; registeredHref?: string } | null => {
    if (a.type !== 'oauth_redirect_differential') return null
    let loc: URL
    try { loc = new URL(String(a.location ?? '')) } catch { return null }
    const variant = String(a.variant ?? '')
    let value: string | null = null
    let registered: string | null = null
    if (variant === 'userinfo_at' && loc.username) {
      value = `https://${loc.username}@evil.invalid${loc.pathname}`
      registered = `https://${loc.username}${loc.pathname}`
    } else if (variant === 'backslash_at' && loc.pathname.startsWith('/@')) {
      const rest = loc.pathname.slice(1)
      value = `${loc.origin}\\${rest}`
      const tail = rest.split('/').slice(1).join('/')
      registered = `${loc.origin}/${tail}`
    } else if (variant === 'subdomain_prefix' && loc.hostname.endsWith('.evil.invalid')) {
      const host = loc.hostname.slice(0, -'.evil.invalid'.length)
      value = `https://${host}.evil.invalid${loc.pathname}`
      registered = `https://${host}${loc.pathname}`
    } else if (variant === 'suffix_match' && loc.hostname.startsWith('evil-')) {
      const host = loc.hostname.slice('evil-'.length)
      value = `https://evil-${host}${loc.pathname}`
      registered = `https://${host}${loc.pathname}`
    }
    if (!value) return null
    return { probePath: withParams({ redirect_uri: value, code_challenge_method: 'S256', code_challenge: challenge }), ...(registered ? { registeredHref: registered } : {}) }
  }

  const out: SynthesizedSpec[] = []
  const seen = new Set<string>()
  const push = (label: string, probePath: string) => {
    if (seen.has(probePath)) return
    seen.add(probePath)
    out.push({
      kind: 'auth_protocol_proof',
      spec: {
        ...baseFields(env, `OAuth authorization validation differential: ${label}`, 'CWE-601', 'broken-authentication', 'high',
          '{ controlPassed: (.steps.c1.status >= 400), confirmed: (.steps.p1.status < 400), observed: ("status=" + (.steps.p1.status | tostring)), expected: "authorize request rejected" }'),
        kind: 'auth_protocol_proof',
        protocol: 'oauth',
        steps: [
          stepOf(env, 'c1', 'control', 'Unrelated redirect_uri is rejected', control, null, {}, [400, 401, 403, 404, 422]),
          stepOf(env, 'p1', 'probe', 'Manipulated authorize request', { method: 'GET', pathAndQuery: probePath }, null),
        ],
      },
    })
  }

  const registeredHrefs: string[] = []
  for (const a of o.anomalies) {
    const derived = evidenceFromAnomaly(a)
    if (derived) push(String(a.variant ?? a.type), derived.probePath)
    if (derived?.registeredHref) registeredHrefs.push(derived.registeredHref)
    if (seed && a.type === 'oauth_redirect_differential' && seedVariants[String(a.variant)]) {
      push(String(a.variant), withParams({ redirect_uri: seedVariants[String(a.variant)], code_challenge_method: 'S256', code_challenge: challenge }))
    }
  }
  if (o.anomalies.some(a => a.type === 'pkce_downgrade')) {
    const target = registeredHrefs[0] ?? (seed ? orig.href : null)
    if (target) push('pkce_plain', withParams({ redirect_uri: target, code_challenge_method: 'plain', code_challenge: 'plain-challenge-token-123456' }))
  }
  return out
}

export function synthAuthProtocol(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  return [...jwtBodySpecs(o, env), ...jwtSpecs(o, env), ...oauthSpecs(o, env)]
}

export function synthCache(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const poison = o.anomalies.find(a => a.type === 'cache_poisoning')
  const deception = o.anomalies.find(a => a.type === 'web_cache_deception')
  if (!poison && !deception) return []
  const basePath = probePathFor(o.hyp)
  const path = basePath.replace(/\/+$/, '') || '/'
  const marker = 'guardian-cache-probe'
  const out: SynthesizedSpec[] = []

  // Header-free cache: the lab cache emits no Age/X-Cache, so persistence is proven from the body
  // differential across actors plus a repeat fetch. The probe supplies the warm route, the actor
  // handles and (when available) a tenant marker/canary observed in the personalised body.
  const bodyRepeat = Boolean(poison && (
    poison.proof === 'body_repeat' ||
    poison.actorDifferential === true ||
    (typeof poison.marker === 'string' && poison.cacheHit !== true)
  ))
  if (poison && bodyRepeat) {
    const warmRaw = typeof poison.path === 'string' && poison.path.startsWith('/')
      ? poison.path
      : typeof poison.probePath === 'string' && poison.probePath.startsWith('/') ? poison.probePath : path
    const warmPath = warmRaw.split('#')[0]
    const keyParam = typeof poison.cacheKeyParam === 'string' && /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(poison.cacheKeyParam)
      ? poison.cacheKeyParam : null
    const controlKey = typeof poison.controlKeyValue === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(poison.controlKeyValue)
      ? poison.controlKeyValue : null
    const explicitControl = typeof poison.controlPath === 'string' && poison.controlPath.startsWith('/') ? poison.controlPath : null
    let controlWarmPath = explicitControl ?? warmPath
    if (!explicitControl && keyParam && controlKey) {
      const url = new URL(warmPath, 'http://guardian.invalid')
      url.searchParams.set(keyParam, controlKey)
      controlWarmPath = url.pathname + url.search
    }
    const stripGcb = (p: string): string => {
      const url = new URL(p, 'http://guardian.invalid')
      url.searchParams.delete('_gcb')
      return url.pathname + (url.search || '')
    }
    const warmBase = stripGcb(warmPath)
    const controlBase = stripGcb(controlWarmPath)
    const suppliedMarker = typeof poison.marker === 'string' && poison.marker.length >= 4 && poison.marker.length <= 256 && !/[\r\n\0]/.test(poison.marker)
      ? poison.marker : undefined
    const asPersona = (v: unknown) => typeof v === 'string' && /^[a-z0-9_-]{1,32}$/.test(v) ? v : undefined
    const poisonPersona = asPersona(poison.poisonPersona ?? poison.warmPersona) ?? env.other ?? env.owner
    const verifyPersona = asPersona(poison.verifyPersona) ?? env.owner
    if (!poisonPersona || !verifyPersona || poisonPersona === verifyPersona) return []
    const jq = '{ controlPassed: ((.cacheProof.cacheHitObserved == true) and (.cacheProof.repeatBodyMatches == true)), ' +
      'confirmed: ((.cacheProof.cacheHitObserved == true) and (.cacheProof.poisonPersistedToVictim == true) and (.cacheProof.repeatBodyMatches == true) and (.cacheProof.timingSignal == true)), ' +
      'observed: ("verify=" + (.steps.verify.status | tostring) + " repeatMatch=" + ((.cacheProof.repeatBodyMatches // false) | tostring)), expected: "a personalised response is not served from the shared cache to another actor" }'
    out.push({
      kind: 'cache_differential',
      spec: {
        ...baseFields(env, 'Cross-actor cache serving of a personalised response', 'CWE-525', 'cache-poisoning', 'high', jq),
        kind: 'cache_differential', targetOrigin: env.origin, mode: 'poison', method: 'GET',
        proofMode: 'body_repeat',
        controlPath: appendQuery(controlBase, '_gcb', '{{control_gcb}}', false),
        probePath: appendQuery(warmBase, '_gcb', '{{probe_gcb}}', false),
        verifyPath: appendQuery(warmBase, '_gcb', '{{probe_gcb}}', false),
        repeatPath: appendQuery(warmBase, '_gcb', '{{repeat_gcb}}', false),
        ...(suppliedMarker ? { marker: suppliedMarker } : {}),
        poisonPersona,
        verifyPersona,
        controlPersona: verifyPersona,
        ...(poison.headers && typeof poison.headers === 'object' && !Array.isArray(poison.headers)
          ? { poisonHeaders: poison.headers as Record<string, string> } : {}),
      },
    })
    return out
  }

  if (poison) {
    const header = String(poison.header ?? '')
    if (!/^[A-Za-z0-9-]{1,64}$/.test(header) || /^(?:authorization|cookie|host)$/i.test(header)) return []
    const value = header === 'X-Forwarded-Scheme' ? 'http' : header.endsWith('URL') ? `/${marker}` : `${marker}.invalid`
    const markerCheck = header === 'X-Forwarded-Scheme' ? '' : ` and (.verify.body | contains(${jqStr(marker)}))`
    const jq = '{ controlPassed: (.cacheProof.cacheHitObserved == true), ' +
      `confirmed: ((.cacheProof.cacheHitObserved == true) and (.cacheProof.poisonPersistedToVictim == true)${markerCheck}), ` +
      'observed: ("hit=" + (.cacheProof.cacheHitObserved | tostring) + " age=" + ((.cacheProof.age // 0) | tostring)), expected: "poisoned response served from cache to a clean client" }'
    out.push({
      kind: 'cache_differential',
      spec: {
        ...baseFields(env, 'Web cache poisoning via unkeyed header', 'CWE-525', 'cache-poisoning', 'high', jq),
        kind: 'cache_differential', targetOrigin: env.origin, mode: 'poison', method: 'GET',
        controlPath: appendQuery(path, '_gcb', '{{control_gcb}}', false),
        probePath: appendQuery(path, '_gcb', '{{probe_gcb}}', false),
        poisonHeaders: { [header]: value },
        ...(env.owner ? { poisonPersona: env.owner } : {}),
      },
    })
  }

  if (deception) {
    const observedUrl = typeof deception.deceptionUrl === 'string' ? deception.deceptionUrl : ''
    let deceptionPath = `${path}/guardian-static.css`
    try {
      const parsed = new URL(observedUrl, 'http://guardian.invalid')
      if (parsed.pathname && parsed.pathname !== '/') deceptionPath = parsed.pathname
    } catch { /* keep generic static suffix */ }
    const jq = '{ controlPassed: (.cacheProof.cacheHitObserved == true), ' +
      'confirmed: ((.cacheProof.cacheHitObserved == true) and (.cacheProof.poisonPersistedToVictim == true) and (.steps.verify.status == 200) and (.steps.verify.body != .steps.control.body)), ' +
      'observed: ("verify status=" + (.steps.verify.status | tostring)), expected: "private response not cacheable by an anonymous client" }'
    out.push({
      kind: 'cache_differential',
      spec: {
        ...baseFields(env, 'Web cache deception of a private page', 'CWE-525', 'cache-deception', 'high', jq),
        kind: 'cache_differential', targetOrigin: env.origin, mode: 'deception', method: 'GET',
        // Control is the same deception route with a guaranteed cache miss; the clean verify then
        // replays the cached URL. This isolates "private body leaked to anonymous" from public content.
        controlPath: appendQuery(deceptionPath, '_gcb', '{{control_gcb}}', false),
        probePath: appendQuery(deceptionPath, '_gcb', '{{probe_gcb}}', false),
        verifyPath: appendQuery(deceptionPath, '_gcb', '{{probe_gcb}}', false),
        ...(env.owner ? { poisonPersona: env.owner } : {}),
      },
    })
  }
  return out
}
