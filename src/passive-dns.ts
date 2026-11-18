import { assetOrigin, maxDnsExportBytes } from './domain.ts'
import type { Candidate, DnsSource } from './domain.ts'

function tokens(line: string, number: number) {
  const fields: string[] = []
  let token = ''
  let quoted = false
  let escaped = false
  for (const character of line) {
    if (escaped) {
      token += '\\' + character
      escaped = false
    } else if (character === '\\') {
      escaped = true
    } else if (character === '"') {
      quoted = !quoted
      token += character
    } else if (quoted) {
      token += character
    } else if (character === ';') {
      break
    } else if (/\s|[()]/.test(character)) {
      if (token) fields.push(token)
      token = ''
      if (character === '(' || character === ')') fields.push(character)
    } else {
      token += character
    }
  }
  if (escaped || quoted) throw new Error(`Finish the escaped or quoted value on DNS export line ${number}.`)
  if (token) fields.push(token)
  return fields
}

function* entries(document: string) {
  let fields: string[] = []
  let depth = 0
  let start = 0
  let inherited = false
  const lines = document.replace(/^\uFEFF/, '').split(/\r?\n/)
  for (const [index, line] of lines.entries()) {
    const parts = tokens(line, index + 1)
    if (!parts.length) continue
    if (!fields.length && depth === 0) {
      start = index + 1
      inherited = /^\s/.test(line)
    }
    for (const field of parts) {
      if (field === '(') depth += 1
      else if (field === ')') depth -= 1
      else fields.push(field)
      if (depth < 0) throw new Error(`Unexpected closing parenthesis on DNS export line ${index + 1}.`)
    }
    if (depth === 0 && fields.length) {
      yield { fields, start, inherited }
      fields = []
    }
  }
  if (depth !== 0) throw new Error(`Finish the DNS record starting on line ${start}.`)
}

function withinZone(name: string, zone: string) {
  return name === zone || name.endsWith('.' + zone)
}

function hostAt(name: string, origin: string) {
  const full = name === '@' ? origin : name.endsWith('.') ? name.slice(0, -1) : `${name}.${origin}`
  if (!/^[\w.-]+$/.test(full) || full.split('.').some(part => !part || part.length > 63)) return undefined
  const checked = assetOrigin.safeParse(full)
  return checked.success ? new URL(checked.data).hostname : undefined
}

const dnsClass = /^(?:IN|CH|HS|CS)$/i
const ttl = /^(?:\d+|(?:\d+[wdhms])+\d*)$/i

export function parseDnsInventory(zoneInput: string, document: string) {
  if (new TextEncoder().encode(document).length > maxDnsExportBytes) throw new Error('Choose a DNS export of at most 128 KiB.')
  const zoneValue = assetOrigin.safeParse(zoneInput.trim().replace(/\.$/, ''))
  if (!zoneValue.success) throw new Error('Enter the DNS zone domain.')
  const zone = new URL(zoneValue.data).hostname
  let origin = zone
  let owner: string | undefined
  const discovered = new Map<string, { recordTypes: Set<DnsSource['recordTypes'][number]>; externalAliases: Set<string> }>()
  for (const { fields, start, inherited } of entries(document)) {
    const head = fields[0].toUpperCase()
    if (head === '$ORIGIN') {
      const next = fields[1] && hostAt(fields[1], origin)
      if (!next || fields.length !== 2) throw new Error(`Enter a DNS origin on line ${start}.`)
      origin = next
      continue
    }
    if (head === '$TTL') continue
    if (head.startsWith('$')) throw new Error(`Use a self-contained DNS export with explicit records. Unsupported directive on line ${start}.`)

    let offset = inherited ? 0 : 1
    if (!inherited) owner = hostAt(fields[0], origin)
    let internetRecord = true
    while (offset < fields.length && (ttl.test(fields[offset]) || dnsClass.test(fields[offset]))) {
      if (dnsClass.test(fields[offset])) internetRecord = fields[offset].toUpperCase() === 'IN'
      offset += 1
    }
    const type = fields[offset]?.toUpperCase()
    if (!owner || !withinZone(owner, zone) || !internetRecord || (type !== 'A' && type !== 'AAAA' && type !== 'CNAME')) continue
    const value = fields[offset + 1]
    if (!value) throw new Error(`Supply the ${type} record value on DNS export line ${start}.`)
    const host = discovered.get(owner) ?? { recordTypes: new Set<DnsSource['recordTypes'][number]>(), externalAliases: new Set<string>() }
    discovered.set(owner, host)
    host.recordTypes.add(type)
    if (type === 'CNAME') {
      const target = hostAt(value, origin)
      if (!target) throw new Error(`Enter a CNAME target hostname on DNS export line ${start}.`)
      if (!withinZone(target, zone)) host.externalAliases.add(target)
    }
  }

  if (!discovered.size) throw new Error('The export contains no A, AAAA, or CNAME hosts in the selected zone.')
  const candidates: (Omit<Candidate, 'id'> & { dnsSource: DnsSource })[] = []
  for (const [host, records] of discovered) {
    const recordTypes = [...records.recordTypes].sort()
    const externalAliases = [...records.externalAliases].sort()
    candidates.push({
      origin: 'https://' + host,
      thirdParty: externalAliases.length > 0,
      source: 'DNS export · ' + recordTypes.join(', '),
      dnsSource: { zone, recordTypes, externalAliases },
    })
  }
  return { zone, candidates: candidates.sort((a, b) => a.origin.localeCompare(b.origin)) }
}
