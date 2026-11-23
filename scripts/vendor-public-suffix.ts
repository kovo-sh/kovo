#!/usr/bin/env node
/**
 * Regenerate the vendored Public Suffix List data used by src/server/public-suffix.ts.
 *
 * Usage: node scripts/vendor-public-suffix.ts [--source <url-or-path>]
 *
 * Default source: https://publicsuffix.org/list/public_suffix_list.dat
 *
 * Output: src/server/public-suffix-list.ts — every ICANN + PRIVATE rule that contains a dot
 * or starts with `*`/`!`, IDN labels normalized to punycode, sorted for stable diffs. Plain
 * single-label TLDs are omitted because the PSL algorithm's implicit `*` default rule already
 * treats the last label as the suffix.
 *
 * Network is only used when this script is run; the build/runtime never fetches the list.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { domainToASCII } from 'node:url'

const DEFAULT_SOURCE = 'https://publicsuffix.org/list/public_suffix_list.dat'
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outputPath = resolve(repoRoot, 'src/server/public-suffix-list.ts')

const sourceIndex = process.argv.indexOf('--source')
const source = sourceIndex > 0 && process.argv[sourceIndex + 1] ? process.argv[sourceIndex + 1] : DEFAULT_SOURCE

const raw = /^https?:\/\//i.test(source)
  ? await (await fetch(source)).text()
  : readFileSync(resolve(process.cwd(), source), 'utf8')

const rules = new Set<string>()
for (const rawLine of raw.split('\n')) {
  const line = rawLine.trim()
  if (!line || line.startsWith('//')) continue
  if (!line.includes('.') && !line.startsWith('*') && !line.startsWith('!')) continue
  const exception = line.startsWith('!')
  const body = exception ? line.slice(1) : line
  const ascii = body
    .split('.')
    .map(label => (label === '*' ? label : (domainToASCII(label) || label)))
    .join('.')
  rules.add(`${exception ? '!' : ''}${ascii}`)
}

const header = `// Public Suffix List (multi-label rules only) — vendored data, no code.
//
// Source: ${DEFAULT_SOURCE}
// Retrieved: ${new Date().toISOString().slice(0, 10)} (ICANN + PRIVATE sections; every rule containing a dot or a
// wildcard/exception marker). Plain single-label TLDs are omitted because the PSL
// algorithm's implicit "*" default rule already treats the last label as the suffix.
// IDN rules are normalized to punycode, matching WHATWG URL hostnames. Rules are
// sorted for stable diffs. Regenerate by re-downloading the list and keeping every
// non-comment rule that contains a dot or starts with "*" or "!".
//
// The Public Suffix List is subject to the Mozilla Public License, v. 2.0.
// A copy of the MPL is available at https://mozilla.org/MPL/2.0/.
//
// Consumed by src/server/public-suffix.ts (registrable-domain scoping for persona
// credential flows). Do not edit by hand.
export const publicSuffixRules = \`
`

writeFileSync(outputPath, `${header}${[...rules].sort().join('\n')}\n\`\n`)
console.log(`Wrote ${rules.size} rules to ${outputPath}`)
