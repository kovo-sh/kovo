/**
 * Command-injection / nonce-output `rce_proof` synthesis.
 *
 * Only built from a probe anomaly that observed command execution. Template-engine arithmetic
 * (SSTI) is handled by `synthSsti`; this builder covers shell-style evidence in three proof modes:
 *  - dynamic_math: randomized integers multiplied by a shell expression,
 *  - split_echo:   two verifier-minted nonce halves concatenated only by command execution,
 *  - oob_canary:   an out-of-band callback to a verifier-minted canary.
 *
 * The observed delimiter/encoding/wrapper is preserved where the probe recorded it, so payloads
 * survive query encoding and common wrapper styles without target-specific hard-coding.
 */
import { containsDestructivePayload } from '../src/replay-spec.ts'
import { baseFields, requestParts, stepOf } from './benchmark-specs-common.ts'
import type { SynthesizedSpec } from './benchmark-specs-common.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

type ProofMode = 'dynamic_math' | 'split_echo' | 'oob_canary'
type Wrapper = 'semicolon' | 'and' | 'pipe' | 'newline' | 'subshell' | 'backtick'
type Encoding = 'plain' | 'url' | 'double_url'

const COMMAND_ANOMALIES = new Set([
  'command_injection_differential',
  'shell_injection_differential',
  'command_output_reflection',
  'rce_differential',
])

function anomalyProofMode(a: Record<string, unknown>): ProofMode | null {
  const explicit = String(a.proofMode ?? '')
  if (explicit === 'dynamic_math' || explicit === 'split_echo' || explicit === 'oob_canary') return explicit
  if (a.canaryTriggered === true || a.oobCanary === true) return 'oob_canary'
  if (a.splitEcho === true || a.outputMode === 'split') return 'split_echo'
  if (a.mathVerified === true || typeof a.product === 'string' || a.outputReflected === true) return 'dynamic_math'
  return null
}

function wrapperOf(a: Record<string, unknown>): Wrapper {
  const raw = String(a.wrapper ?? a.delimiter ?? 'semicolon')
  return (['semicolon', 'and', 'pipe', 'newline', 'subshell', 'backtick'].includes(raw) ? raw : 'semicolon') as Wrapper
}

function encodingOf(a: Record<string, unknown>): Encoding {
  const raw = String(a.encoding ?? 'plain')
  return (['plain', 'url', 'double_url'].includes(raw) ? raw : 'plain') as Encoding
}

function wrapCommand(command: string, wrapper: Wrapper): string {
  switch (wrapper) {
    case 'and': return ` && ${command}`
    case 'pipe': return ` | { ${command}; }`
    case 'newline': return `\n${command}`
    case 'subshell': return `$(${command})`
    case 'backtick': return `\`${command}\``
    default: return `; ${command}`
  }
}

function commandFor(mode: ProofMode, anomaly: Record<string, unknown>): string {
  if (mode === 'dynamic_math') return 'expr {{nonce_a}} \\* {{nonce_b}}'
  if (mode === 'split_echo') return "echo {{nonce_part1}}''{{nonce_part2}}"
  return anomaly.protocol === 'dns' ? 'nslookup {{canary_dns_host}}' : 'curl -s {{canary_url}}'
}

/** Percent-encode only the literal parts, keeping verifier placeholders intact. */
function encodePayload(payload: string, encoding: Encoding): string {
  if (encoding === 'plain') return payload
  return payload
    .split(/(\{\{[a-z_]+\}\})/g)
    .map(segment => {
      if (segment.startsWith('{{')) return segment
      return encoding === 'double_url' ? encodeURIComponent(encodeURIComponent(segment)) : encodeURIComponent(segment)
    })
    .join('')
}

function proofJq(mode: ProofMode): string {
  if (mode === 'dynamic_math') {
    return '{ controlPassed: (.control.status < 500), confirmed: (.proof.mathVerified == true), observed: ("mathVerified=" + ((.proof.mathVerified // false) | tostring)), expected: "input is not executed by a shell" }'
  }
  if (mode === 'split_echo') {
    return '{ controlPassed: (.control.status < 500), confirmed: (.proof.splitEchoVerified == true), observed: ("splitEchoVerified=" + ((.proof.splitEchoVerified // false) | tostring)), expected: "split nonces are never concatenated by the server" }'
  }
  return '{ controlPassed: (.control.status < 500), confirmed: (.proof.canaryProbeTriggered == true and .proof.canaryControlTriggered == false), observed: ("probeCallback=" + ((.proof.canaryProbeTriggered // false) | tostring)), expected: "no out-of-band command callback" }'
}

export function synthRce(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const anomalies = o.anomalies.filter(a => COMMAND_ANOMALIES.has(String(a.type)) ||
    (a.type === 'expression_evaluated' && /^(?:sh|bash|shell|command|cmd)$/i.test(String(a.engine ?? ''))))
  if (anomalies.length === 0) return []
  const out: SynthesizedSpec[] = []
  for (const anomaly of anomalies) {
    const mode = anomalyProofMode(anomaly)
    if (!mode) continue
    const oob = mode === 'oob_canary'
    const control = requestParts(o, env, o.ctx?.baseline ?? '127.0.0.1')
    if (!control) return []
    const payload = encodePayload(wrapCommand(commandFor(mode, anomaly), oob ? 'semicolon' : wrapperOf(anomaly)), encodingOf(anomaly))
    const probe = requestParts(o, env, payload)
    if (!probe) return []
    const probeStep = stepOf(env, 'p1', 'probe', `Verifier-minted ${mode} command payload`, probe)
    if (containsDestructivePayload(JSON.stringify(probeStep.request))) return []
    out.push({
      kind: 'rce_proof',
      spec: {
        ...baseFields(env, 'Operating-system command injection', 'CWE-78', 'injection-input', 'critical', proofJq(mode)),
        kind: 'rce_proof',
        proofMode: mode,
        requiresTier3Approval: true,
        controlStep: stepOf(env, 'c1', 'control', 'Benign value', control),
        probeStep,
      },
    })
    break
  }
  return out
}
