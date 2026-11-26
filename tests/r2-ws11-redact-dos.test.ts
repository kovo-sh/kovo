import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import { createEgressSanitizer, redactSecrets } from '../src/server/egress-sanitizer.ts'
import {
  DEFAULT_MAX_EXACT_SECRETS,
  buildSecretEncodingVariants,
  compileSecretMatcher,
  redact,
  redactExactValues,
  redactJsonValue,
  scanSecrets,
  sha256Prefix,
  type NamedSecret,
} from '../src/server/redact.ts'

describe('WS-11 R2-H-27: linear PEM private-key redaction and bounded scanning', () => {
  test('200 KB and 500 KB repeated unclosed BEGIN PRIVATE KEY markers finish linearly without ReDoS', () => {
    const chunk = '-----BEGIN RSA PRIVATE KEY-----\n'
    const payload200k = chunk.repeat(Math.ceil((200 * 1024) / chunk.length))
    const t200Start = performance.now()
    const redacted200 = redact(payload200k)
    const scanned200 = scanSecrets(payload200k)
    const t200Ms = performance.now() - t200Start
    assert.equal(redacted200, payload200k)
    assert.deepEqual(scanned200, [])
    assert.ok(t200Ms < 50, `200 KB unclosed PEM took ${t200Ms.toFixed(1)} ms (budget < 50 ms)`)

    const payload500k = '-----BEGIN PRIVATE KEY-----\n'.repeat(18_500)
    const t500Start = performance.now()
    const redacted500 = redact(payload500k)
    const scanned500 = scanSecrets(payload500k)
    const t500Ms = performance.now() - t500Start
    assert.equal(redacted500, payload500k)
    assert.deepEqual(scanned500, [])
    assert.ok(t500Ms < 50, `500 KB unclosed PEM took ${t500Ms.toFixed(1)} ms (budget < 50 ms)`)
  })

  test('4 MiB adversarial repeated BEGIN markers with decoy dashes/ENDs remain linear', () => {
    const decoy = '-----BEGIN RSA PRIVATE KEY-----\n-----END FOO-BAR PRIVATE KEY-----\n-----BEGIN -----\n'
    const payload4m = decoy.repeat(Math.floor((4 * 1024 * 1024) / decoy.length))
    const started = performance.now()
    const out = redact(payload4m)
    const elapsedMs = performance.now() - started
    assert.equal(out, payload4m)
    assert.ok(elapsedMs < 250, `4 MiB adversarial PEM payload took ${elapsedMs.toFixed(1)} ms (expected linear < 250 ms)`)
  })

  test('real PEM private-key blocks are fully redacted and fingerprinted while public certs stay intact', () => {
    const rsaPem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n')
    const ecPem = [
      '-----BEGIN EC PRIVATE KEY-----',
      'MHcCAQEEIK3testECkeyMaterial998877665544',
      '-----END EC PRIVATE KEY-----',
    ].join('\n')
    const certPem = [
      '-----BEGIN CERTIFICATE-----',
      'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
      '-----END CERTIFICATE-----',
    ].join('\n')

    const text = `prefix\n${certPem}\n${rsaPem}\nmiddle\n${ecPem}\nsuffix`
    const scrubbed = redact(text)
    assert.ok(scrubbed.includes(certPem), 'public CERTIFICATE block must not be redacted')
    assert.equal(scrubbed.includes('MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn'), false)
    assert.equal(scrubbed.includes('MHcCAQEEIK3testECkeyMaterial998877665544'), false)
    assert.equal(scrubbed.includes('BEGIN RSA PRIVATE KEY'), false)
    assert.equal(scrubbed.includes('BEGIN EC PRIVATE KEY'), false)
    assert.equal(scrubbed.match(/\[redacted\]/g)?.length, 2)

    const matches = scanSecrets(text)
    const pemMatches = matches.filter(m => m.kind === 'private_key')
    assert.equal(pemMatches.length, 2)
    assert.ok(pemMatches.some(m => m.sha256Prefix === sha256Prefix(rsaPem)))
    assert.ok(pemMatches.some(m => m.sha256Prefix === sha256Prefix(ecPem)))

    // Adjacent dashes edge case (no separator between END/BEGIN markers)
    const adjacent = '-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----'
    assert.equal(redact(adjacent), '[redacted]')
  })

  test('oversized inputs past 4 MiB are safely bounded in redact() and scanSecrets()', () => {
    const huge = 'plain-safe-text '.repeat(300_000) // ~4.8 MB
    const started = performance.now()
    const redacted = redact(huge)
    const scanned = scanSecrets(huge)
    const elapsedMs = performance.now() - started
    assert.ok(redacted.endsWith('…[truncated]'))
    assert.ok(redacted.length <= 4_194_320)
    assert.deepEqual(scanned, [])
    assert.ok(elapsedMs < 250, `4.8 MB redact+scan took ${elapsedMs.toFixed(1)} ms`)
  })
})

describe('WS-11 R2-H-28: compiled secret matcher cache, dedupe, bounds, and browser result throughput', () => {
  test('sanitizeBrowserResult on 2,000 leaves × 200 secrets completes in < 200 ms and scrubs all encoding variants', () => {
    const targetSecret = 's3cr3t+val/99&"tok=1'
    const secrets: NamedSecret[] = [
      { value: targetSecret, placeholder: '[redacted:target]' },
      ...Array.from({ length: 199 }, (_, i) => ({
        value: `cookie_${i}=val_${i}+abc/${i.toString(16).padStart(6, '0')}`,
        placeholder: `[redacted:s${i}]`,
      })),
    ]

    const urlEnc = encodeURIComponent(targetSecret)
    const doubleUrlEnc = encodeURIComponent(urlEnc)
    const b64 = Buffer.from(targetSecret, 'utf8').toString('base64')
    const hex = Buffer.from(targetSecret, 'utf8').toString('hex')
    const unicodeEsc = targetSecret.replace(/[<>&'"=\\/+]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)

    const leaves = Array.from({ length: 2_000 }, (_, i) => {
      switch (i) {
        case 0: return `raw:${targetSecret}`
        case 1: return `url:${urlEnc}`
        case 2: return `doubleUrl:${doubleUrlEnc}`
        case 3: return `b64:${b64}`
        case 4: return `hex:${hex}`
        case 5: return `uni:${unicodeEsc}`
        case 6: return `other:${secrets[150]!.value}`
        default: return `benign_leaf_${i}_navigation_content_ok`
      }
    })

    const browserResult = {
      url: `https://app.example/callback?q=${urlEnc}`,
      title: 'Dashboard',
      domSnippet: `<div>${b64}</div>`,
      links: leaves,
      exchanges: [
        {
          respHeaders: {
            'set-cookie': `sid=${targetSecret}; HttpOnly`,
            'x-trace': `trace-${hex}`,
            'x-ok': 'visible-header',
          },
        },
      ],
    }

    const sanitizer = createEgressSanitizer({ secrets })
    const started = performance.now()
    const sanitized = sanitizer.sanitizeBrowserResult(browserResult)
    const elapsedMs = performance.now() - started

    assert.ok(elapsedMs < 200, `sanitizeBrowserResult (2000 leaves × 200 secrets) took ${elapsedMs.toFixed(1)} ms (budget < 200 ms)`)

    const serialized = JSON.stringify(sanitized)
    for (const variant of [targetSecret, urlEnc, doubleUrlEnc, b64, hex, unicodeEsc, secrets[150]!.value]) {
      assert.equal(serialized.includes(variant), false, `variant leaked after sanitizeBrowserResult: ${variant}`)
    }
    assert.equal(sanitized.exchanges[0]!.respHeaders['set-cookie'], '[redacted]')
    assert.equal(sanitized.exchanges[0]!.respHeaders['x-trace'], 'trace-[redacted:target]')
    assert.equal(sanitized.exchanges[0]!.respHeaders['x-ok'], 'visible-header')
    assert.equal(sanitized.links[7], 'benign_leaf_7_navigation_content_ok')
  })

  test('warm EgressSanitizer at 5,000 secrets sanitizes in < 50 ms', () => {
    const secrets: NamedSecret[] = Array.from({ length: 5_000 }, (_, i) => ({
      value: `sid_${i}=tok_${i}_val+99/${i.toString(16).padStart(6, '0')}`,
      placeholder: `[redacted:c${i}]`,
    }))
    const sanitizer = createEgressSanitizer({ secrets })
    // Warm up compiled automaton once (simulating persistent host sanitizer across browser visits).
    assert.equal(sanitizer.redactSecrets('warm'), 'warm')

    const payload = {
      domSnippet: `leaked=${Buffer.from(secrets[4999]!.value, 'utf8').toString('base64url')}`,
      links: Array.from({ length: 500 }, (_, i) => (i === 42 ? `u=${encodeURIComponent(secrets[1234]!.value)}` : `https://app.example/item/${i}`)),
    }
    const started = performance.now()
    const sanitized = sanitizer.sanitizeBrowserResult(payload)
    const elapsedMs = performance.now() - started

    assert.ok(elapsedMs < 50, `warm sanitizeBrowserResult at 5000 secrets took ${elapsedMs.toFixed(1)} ms (budget < 50 ms)`)
    assert.equal(sanitized.domSnippet, 'leaked=[redacted:c4999]')
    assert.equal(sanitized.links[42], 'u=[redacted:c1234]')
  })

  test('enforces deduplication, bounded secret capacity, and longest-first variant parity', () => {
    const dupSecrets: NamedSecret[] = [
      { value: 'dup_secret_alpha_1234', placeholder: '[redacted:first]' },
      { value: 'dup_secret_alpha_1234', placeholder: '[redacted:second]' },
      { value: 'dup_secret_alpha_1234', placeholder: '[redacted:third]' },
    ]
    const dupMatcher = compileSecretMatcher(dupSecrets)
    assert.equal(dupMatcher.secretCount, 1)
    assert.equal(dupMatcher.redact('hit dup_secret_alpha_1234'), 'hit [redacted:first]')

    // Bounded capacity (providerKey + capabilityVaults stay protected even when secrets exceed cap)
    const vault = new DerivedCapabilityVault({ runId: 'run-ws11-cap' })
    vault.seal({ hopReceiptId: '1', slot: 'otp6', rawValue: '482910' })
    const overflowSecrets: NamedSecret[] = Array.from({ length: DEFAULT_MAX_EXACT_SECRETS + 500 }, (_, i) => ({
      value: `overflow_tok_${i}_xxxxxxxx`,
      placeholder: `[redacted:o${i}]`,
    }))
    const overflowMatcher = compileSecretMatcher(overflowSecrets)
    assert.equal(overflowMatcher.secretCount, DEFAULT_MAX_EXACT_SECRETS)

    const sanitizer = createEgressSanitizer({
      providerKey: 'sk-provider-must-survive-overflow-99',
      capabilityVaults: [vault],
      secrets: overflowSecrets,
      maxSecrets: 100,
    })
    const scrubbed = sanitizer.redactSecrets('p=sk-provider-must-survive-overflow-99 otp=482910 s=overflow_tok_0_xxxxxxxx')
    assert.equal(scrubbed, 'p=[redacted] otp=[redacted:cap:hop_1:otp6] s=[redacted:o0]')

    // Dynamic vault updates invalidate cached matcher automatically
    vault.seal({ hopReceiptId: '2', slot: 'tok7', rawValue: 'xK9mP2a' })
    assert.equal(sanitizer.redactSecrets('new=xK9mP2a'), 'new=[redacted:cap:hop_2:tok7]')

    // Longest-first replacement parity: padded base64 wins over unpadded, full cookie wins over value-only
    const cookieVal = 'sid=s3cr3t+val/99'
    const paddedB64 = Buffer.from('abcd', 'utf8').toString('base64') // YWJjZA==
    assert.equal(
      redactExactValues(`c=${cookieVal} b=${paddedB64}`, [
        { value: cookieVal, placeholder: '[ck]' },
        { value: 'abcd', placeholder: '[ab]' },
      ]),
      'c=[ck] b=[ab]',
    )

    // Shared-prefix adaptive trie splitting + llm_tool_args preservation
    const sharedPrefixSecrets: NamedSecret[] = Array.from({ length: 64 }, (_, i) => ({
      value: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload_${i}_secret`,
      placeholder: `[jwt:${i}]`,
    }))
    const sharedSanitizer = createEgressSanitizer({ secrets: sharedPrefixSecrets })
    const toolArgs = sharedSanitizer.sanitizeValue(
      {
        code: 'const password = "probe"; const token = res.headers["x-csrf-token"];',
        leaked: sharedPrefixSecrets[63]!.value,
      },
      'llm_tool_args',
    )
    assert.equal(toolArgs.code, 'const password = "probe"; const token = res.headers["x-csrf-token"];')
    assert.equal(toolArgs.leaked, '[jwt:63]')

    // Standalone helpers remain parity-compatible
    assert.equal(redactSecrets('v=' + buildSecretEncodingVariants('tok987', 6)[1]!, [{ value: 'tok987', placeholder: '[t]' }], { minSecretLength: 6 }), 'v=[t]')
    assert.deepEqual(
      redactJsonValue({ ok: 'plain', secret_token: 'hidden', leak: sharedPrefixSecrets[0]!.value }, sharedPrefixSecrets),
      { ok: 'plain', secret_token: '[redacted]', leak: '[jwt:0]' },
    )
  })
})
