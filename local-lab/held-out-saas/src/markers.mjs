// Benign per-challenge evidence markers live in manifest.json and are planted in the lab's own data.
import { readFileSync } from 'node:fs'

export const manifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'))
const byId = new Map(manifest.challenges.map(c => [c.id, c]))

export function marker(id) {
  return byId.get(id)?.flagMarker ?? `unmarked-${id}`
}
