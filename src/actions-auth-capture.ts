/**
 * Server actions for universal IdP-agnostic Browser Session personas (`adapter: 'browser_session'`).
 * Kept in its own module so `src/actions.ts` and `src/domain.ts` stay untouched while supporting
 * full Playwright `storageState` JSON bundles (up to 2 MiB) and live interactive capture saves.
 */
import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { id, personaHandle, scopedAssetOrigin, shortText } from './domain.ts'
import {
  createBrowserSessionPersona,
  updateBrowserSessionPersona,
} from './server/persona-vault.ts'
import { store } from './server/store.ts'

const MAX_STORAGE_STATE_JSON_CHARS = 2 * 1024 * 1024

const optionalVerifyPath = z.string().trim().max(512).transform((raw, ctx) => {
  if (!raw) return undefined
  if (!raw.startsWith('/') || raw.startsWith('//')) {
    ctx.addIssue({ code: 'custom', message: 'Verify path must start with "/" (e.g. /dashboard or /api/me).' })
    return z.NEVER
  }
  return raw
}).optional()

const storageStatePayloadSchema = z.union([
  z.string().trim().min(2).max(MAX_STORAGE_STATE_JSON_CHARS),
  z.record(z.string(), z.unknown()),
])

const observedHeadersSchema = z.record(
  z.string().trim().regex(/^[A-Za-z0-9-]{1,64}$/),
  z.string().max(8192),
).optional()

export const createBrowserSessionPersonaSchema = z.object({
  requestId: id,
  projectId: id,
  handle: personaHandle,
  roleLabel: shortText,
  originAllowlist: z.array(scopedAssetOrigin).min(1).max(64),
  storageState: storageStatePayloadSchema,
  observedHeaders: observedHeadersSchema,
  verifyPath: optionalVerifyPath,
  refreshIntervalSec: z.number().int().min(15).max(3600).optional(),
  canaryMarkers: z.array(shortText).max(16).default([]),
})

export const updateBrowserSessionPersonaSchema = z.object({
  requestId: id,
  projectId: id,
  personaId: id,
  roleLabel: shortText,
  originAllowlist: z.array(scopedAssetOrigin).min(1).max(64),
  storageState: storageStatePayloadSchema.optional(),
  observedHeaders: observedHeadersSchema,
  verifyPath: optionalVerifyPath,
  refreshIntervalSec: z.number().int().min(15).max(3600).optional(),
  canaryMarkers: z.array(shortText).max(16).optional(),
})

export const registerBrowserSessionPersona = createServerFn({ method: 'POST' })
  .validator(createBrowserSessionPersonaSchema)
  .handler(({ data }) => createBrowserSessionPersona(store(), data))

export const updateBrowserSessionPersonaAction = createServerFn({ method: 'POST' })
  .validator(updateBrowserSessionPersonaSchema)
  .handler(({ data }) => updateBrowserSessionPersona(store(), data))
