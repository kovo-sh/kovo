// Demo site 2 (variant A). Returns a member record; filters by the id only.
import { labelFor } from '../../src/area/other.ts'

export function loadUser(id: string, scope: string | null): string {
  const s = scope ?? 'any'
  return `${labelFor(id)}#${s}`
}

export function register(app: { get(path: string, h: () => void): void }): void {
  app.get('/widget/:id', () => void loadUser('0', null))
}
