export interface HeldOutSaasPersona {
  handle: string
  roleLabel: string
  authKind: 'bearer'
  secret: string
  canaryMarkers: string[]
  userId: string
  tenantId: string
}

export interface HeldOutSaasOptions {
  host?: string
  port?: number
  patchedIds?: string[]
}

export interface HeldOutSaasServer {
  origin: string
  port: number
  host: string
  personas: HeldOutSaasPersona[]
  resetState(): void
  setPatchedIds(ids: string[]): void
  getPatchedIds(): string[]
  close(): Promise<void>
}

export interface HeldOutSaasChallenge {
  id: string
  name: string
  vulnClass: string
  cwe: string
  endpoint: string
  method: string
  isDecoy?: boolean
  decoyReason?: string
  flagMarker?: string
  patchId?: string
  [key: string]: unknown
}

export function startHeldOutSaasServer(opts?: HeldOutSaasOptions): Promise<HeldOutSaasServer>
export function loadHeldOutSaasManifest(): { challenges: HeldOutSaasChallenge[]; personas: Record<string, unknown>; [key: string]: unknown }
export const heldOutSaasPatchIds: string[]
