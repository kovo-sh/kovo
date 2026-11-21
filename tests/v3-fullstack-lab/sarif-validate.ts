/**
 * Structural OASIS SARIF 2.1.0 validator for Guardian v3 tests.
 * Enforces the normative constraints Guardian relies on (no network schema fetch needed):
 *  - §3.13 sarifLog: version "2.1.0", runs[] array, optional $schema URI
 *  - §3.14 run.tool.driver.name required; rules[] ids unique
 *  - §3.27 result: message.text required; ruleIndex ⇔ ruleId consistency (§3.27.6)
 *  - §3.27.9 kind enum; §3.27.10 level enum, and level MUST be "none" when kind != "fail"
 *  - §3.30 region.startLine >= 1, endLine >= startLine; §3.4 artifactLocation.uri relative (no leading "/")
 *  - §3.55 fix.artifactChanges[] non-empty with replacements[].deletedRegion
 */
const KINDS = new Set(['notApplicable', 'pass', 'fail', 'review', 'open', 'informational'])
const LEVELS = new Set(['none', 'note', 'warning', 'error'])

export function validateSarif21(log: unknown): string[] {
  const errors: string[] = []
  const err = (path: string, msg: string) => errors.push(`${path}: ${msg}`)
  if (!log || typeof log !== 'object') return ['root: not an object']
  const root = log as Record<string, unknown>
  if (root.version !== '2.1.0') err('version', `expected "2.1.0", got ${JSON.stringify(root.version)}`)
  if (root.$schema !== undefined && (typeof root.$schema !== 'string' || !/sarif-2\.1\.0/i.test(root.$schema))) {
    err('$schema', 'must reference the SARIF 2.1.0 schema')
  }
  if (!Array.isArray(root.runs)) { err('runs', 'must be an array'); return errors }
  root.runs.forEach((runRaw, ri) => {
    const run = runRaw as Record<string, unknown>
    const p = `runs[${ri}]`
    const driver = (run.tool as Record<string, unknown> | undefined)?.driver as Record<string, unknown> | undefined
    if (!driver || typeof driver.name !== 'string' || !driver.name) err(`${p}.tool.driver.name`, 'required')
    const rules = Array.isArray(driver?.rules) ? driver!.rules as Array<Record<string, unknown>> : []
    const ids = new Set<string>()
    rules.forEach((rule, i) => {
      if (typeof rule.id !== 'string' || !rule.id) err(`${p}.rules[${i}].id`, 'required')
      else if (ids.has(rule.id)) err(`${p}.rules[${i}].id`, `duplicate ${rule.id}`)
      else ids.add(rule.id)
      const sev = (rule.properties as Record<string, unknown> | undefined)?.['security-severity']
      if (sev !== undefined && (typeof sev !== 'string' || !Number.isFinite(Number(sev)) || Number(sev) < 0 || Number(sev) > 10)) {
        err(`${p}.rules[${i}].properties.security-severity`, `must be a numeric string 0..10, got ${JSON.stringify(sev)}`)
      }
      const lvl = (rule.defaultConfiguration as Record<string, unknown> | undefined)?.level
      if (lvl !== undefined && !LEVELS.has(String(lvl))) err(`${p}.rules[${i}].defaultConfiguration.level`, `invalid ${lvl}`)
    })
    if (run.results !== undefined && !Array.isArray(run.results)) { err(`${p}.results`, 'must be an array'); return }
    ;((run.results ?? []) as Array<Record<string, unknown>>).forEach((res, i) => {
      const rp = `${p}.results[${i}]`
      const msg = res.message as Record<string, unknown> | undefined
      if (!msg || (typeof msg.text !== 'string' && typeof msg.id !== 'string')) err(`${rp}.message`, 'text or id required')
      const kind = res.kind === undefined ? 'fail' : String(res.kind)
      if (!KINDS.has(kind)) err(`${rp}.kind`, `invalid ${kind}`)
      if (res.level !== undefined) {
        if (!LEVELS.has(String(res.level))) err(`${rp}.level`, `invalid ${res.level}`)
        if (kind !== 'fail' && res.level !== 'none') err(`${rp}.level`, `must be "none" when kind is "${kind}" (§3.27.10), got "${res.level}"`)
      }
      if (typeof res.ruleIndex === 'number') {
        const rule = rules[res.ruleIndex]
        if (!rule) err(`${rp}.ruleIndex`, `out of range ${res.ruleIndex}`)
        else if (res.ruleId !== undefined && rule.id !== res.ruleId) err(`${rp}.ruleId`, `ruleId ${res.ruleId} != rules[${res.ruleIndex}].id ${rule.id}`)
      }
      const locs = (res.locations ?? []) as Array<Record<string, unknown>>
      locs.forEach((loc, li) => {
        const phys = loc.physicalLocation as Record<string, unknown> | undefined
        if (!phys) return
        const uri = (phys.artifactLocation as Record<string, unknown> | undefined)?.uri
        if (typeof uri !== 'string' || !uri) err(`${rp}.locations[${li}].artifactLocation.uri`, 'required')
        else if (uri.startsWith('/') || uri.includes('..')) err(`${rp}.locations[${li}].artifactLocation.uri`, `must be a clean relative URI, got ${uri}`)
        const region = phys.region as Record<string, unknown> | undefined
        if (region) {
          if (typeof region.startLine !== 'number' || region.startLine < 1) err(`${rp}.locations[${li}].region.startLine`, 'must be >= 1')
          if (region.endLine !== undefined && (typeof region.endLine !== 'number' || region.endLine < (region.startLine as number))) {
            err(`${rp}.locations[${li}].region.endLine`, 'must be >= startLine')
          }
        }
      })
      const fixes = (res.fixes ?? []) as Array<Record<string, unknown>>
      fixes.forEach((fix, fi) => {
        const changes = fix.artifactChanges as Array<Record<string, unknown>> | undefined
        if (!Array.isArray(changes) || changes.length === 0) { err(`${rp}.fixes[${fi}].artifactChanges`, 'must be non-empty'); return }
        changes.forEach((ch, ci) => {
          const uri = (ch.artifactLocation as Record<string, unknown> | undefined)?.uri
          if (typeof uri !== 'string' || !uri) err(`${rp}.fixes[${fi}].artifactChanges[${ci}].artifactLocation.uri`, 'required')
          const reps = ch.replacements as Array<Record<string, unknown>> | undefined
          if (!Array.isArray(reps) || reps.length === 0) err(`${rp}.fixes[${fi}].artifactChanges[${ci}].replacements`, 'must be non-empty')
          else reps.forEach((r, k) => {
            const dr = r.deletedRegion as Record<string, unknown> | undefined
            if (!dr || typeof dr.startLine !== 'number' || dr.startLine < 1) err(`${rp}.fixes[${fi}].artifactChanges[${ci}].replacements[${k}].deletedRegion`, 'startLine >= 1 required')
          })
        })
      })
    })
  })
  return errors
}
