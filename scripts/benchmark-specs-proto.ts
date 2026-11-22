/** auth_protocol_proof / cache_differential spec synthesis. */
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
  if (!seed) return []
  const path = o.hyp.endpoint.path.split('?')[0]
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
  const withParams = (set: Record<string, string>) => {
    const u = new URL(`${path}?${seed}`, 'http://guardian.invalid')
    for (const [k, v] of Object.entries(set)) u.searchParams.set(k, v)
    return u.pathname + u.search
  }
  const orig = (() => { try { return new URL(new URL(`${path}?${seed}`, 'http://guardian.invalid').searchParams.get('redirect_uri') ?? 'https://app.example.invalid/cb') } catch { return new URL('https://app.example.invalid/cb') } })()
  const variants: Record<string, string> = {
    userinfo_at: `https://${orig.host}@evil.invalid/cb`,
    backslash_at: `https://${orig.host}\\@evil.invalid/cb`,
    subdomain_prefix: `https://${orig.hostname}.evil.invalid/cb`,
    suffix_match: `https://evil-${orig.hostname}/cb`,
  }
  const control: RequestParts = { method: 'GET', pathAndQuery: withParams({ redirect_uri: 'https://unrelated-control.invalid/cb', code_challenge_method: 'S256', code_challenge: challenge }) }
  const out: SynthesizedSpec[] = []
  for (const a of o.anomalies) {
    let probePath: string | null = null
    if (a.type === 'oauth_redirect_differential' && variants[String(a.variant)]) {
      probePath = withParams({ redirect_uri: variants[String(a.variant)], code_challenge_method: 'S256', code_challenge: challenge })
    } else if (a.type === 'pkce_downgrade') {
      probePath = withParams({ redirect_uri: orig.href, code_challenge_method: 'plain', code_challenge: 'plain-challenge-token-123456' })
    }
    if (!probePath) continue
    out.push({
      kind: 'auth_protocol_proof',
      spec: {
        ...baseFields(env, `OAuth authorization validation differential: ${String(a.variant ?? a.type)}`, 'CWE-601', 'broken-authentication', 'high',
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
  return out
}

export function synthAuthProtocol(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  return [...jwtSpecs(o, env), ...oauthSpecs(o, env)]
}

export function synthCache(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const poison = o.anomalies.find(a => a.type === 'cache_poisoning')
  const deception = o.anomalies.find(a => a.type === 'web_cache_deception')
  if (!poison && !deception) return []
  const basePath = probePathFor(o.hyp)
  const path = basePath.replace(/\/+$/, '') || '/'
  const marker = 'guardian-cache-probe'
  const out: SynthesizedSpec[] = []

  if (poison) {
    const header = String(poison.header ?? '')
    if (!/^[A-Za-z0-9-]{1,64}$/.test(header) || /^(?:authorization|cookie|host)$/i.test(header)) return []
    const value = header === 'X-Forwarded-Scheme' ? 'http' : header.endsWith('URL') ? `/${marker}` : 'poison-guardian.guardian.invalid'
    const jq = '{ controlPassed: (.cacheProof.cacheHitObserved == true), ' +
      `confirmed: ((.cacheProof.cacheHitObserved == true) and (.cacheProof.poisonPersistedToVictim == true) and (.verify.body | contains(${jqStr(marker)}))), ` +
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
        controlPath: appendQuery(path, '_gcb', '{{control_gcb}}', false),
        probePath: appendQuery(deceptionPath, '_gcb', '{{probe_gcb}}', false),
        verifyPath: appendQuery(deceptionPath, '_gcb', '{{probe_gcb}}', false),
        ...(env.owner ? { poisonPersona: env.owner } : {}),
      },
    })
  }
  return out
}
