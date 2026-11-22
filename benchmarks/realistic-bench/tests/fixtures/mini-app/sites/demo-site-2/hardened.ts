// Demo site 2 (variant B). Returns a member record; filters by id within the session scope.
import { labelFor } from '../../src/area/other.ts'

export function loadUser(id: string, sessionScope: string | null): string {
  const s = sessionScope ?? 'any'
  return `${labelFor(id)}#${s}`
}

export function register(app: { get(path: string, h: () => void): void }): void {
  app.get('/widget/:id', () => void loadUser('0', null))
}
