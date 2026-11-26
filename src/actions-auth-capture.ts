/**
 * Server actions for universal IdP-agnostic Browser Session personas (`adapter: 'browser_session'`).
 * Kept in its own module so `src/actions.ts` and `src/domain.ts` stay untouched while supporting
 * single-use server-side escrowed `captureToken` redemption and explicit Playwright `storageState`
 * JSON imports (up to 2 MiB).
 */
import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { id, personaHandle, personaPrivilegeSchema, personaTenantRefSchema, scopedAssetOrigin, shortText } from './domain.ts'

const MAX_STORAGE_STATE_JSON_CHARS = 2 * 1024 * 1024

const optionalVerifyPath = z.string().trim().max(512).transform((raw, ctx) => {
  if (!raw) return undefined
  if (!raw.startsWith('/') || raw.startsWith('//')) {
    ctx.addIssue({ code: 'custom', message: 'Verify path must start with "/" (e.g. /dashboard or /api/me).' })
    return z.NEVER
  }
  return raw
}).optional()

const captureTokenSchema = z.string().trim().regex(
  /^cap_tok_[a-f0-9]{64}$/,
  'Invalid captured session token format.',
)

const storageStatePayloadSchema = z.union([
  z.string().trim().min(2).max(MAX_STORAGE_STATE_JSON_CHARS),
  z.record(z.string(), z.unknown()).refine(
    value => {
      try {
        return JSON.stringify(value).length <= MAX_STORAGE_STATE_JSON_CHARS
      } catch {
        return false
      }
    },
    { message: 'storageState payload exceeds 2 MiB limit.' },
  ),
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
  tenantRef: personaTenantRefSchema,
  privilege: personaPrivilegeSchema,
  originAllowlist: z.array(scopedAssetOrigin).min(1).max(64),
  captureToken: captureTokenSchema.optional(),
  storageState: storageStatePayloadSchema.optional(),
  observedHeaders: observedHeadersSchema,
  verifyPath: optionalVerifyPath,
  refreshIntervalSec: z.number().int().min(15).max(3600).optional(),
  canaryMarkers: z.array(shortText).max(16).default([]),
}).superRefine((data, ctx) => {
  if (!data.captureToken && data.storageState === undefined) {
    ctx.addIssue({
      code: 'custom',
      path: ['storageState'],
      message: 'Provide either a captured session token or a storageState.json payload.',
    })
  }
})

export const updateBrowserSessionPersonaSchema = z.object({
  requestId: id,
  projectId: id,
  personaId: id,
  roleLabel: shortText,
  tenantRef: personaTenantRefSchema,
  privilege: personaPrivilegeSchema,
  originAllowlist: z.array(scopedAssetOrigin).min(1).max(64),
  captureToken: captureTokenSchema.optional(),
  storageState: storageStatePayloadSchema.optional(),
  observedHeaders: observedHeadersSchema,
  verifyPath: optionalVerifyPath,
  refreshIntervalSec: z.number().int().min(15).max(3600).optional(),
  canaryMarkers: z.array(shortText).max(16).optional(),
})

export const registerBrowserSessionPersona = createServerFn({ method: 'POST' })
  .validator(createBrowserSessionPersonaSchema)
  .handler(async ({ data }) => {
    const [{ store }, { registerBrowserSessionPersonaFromAction }] = await Promise.all([
      import('./server/store.ts'),
      import('./server/browser-session-auth.ts'),
    ])
    return registerBrowserSessionPersonaFromAction(store(), data)
  })

export const updateBrowserSessionPersonaAction = createServerFn({ method: 'POST' })
  .validator(updateBrowserSessionPersonaSchema)
  .handler(async ({ data }) => {
    const [{ store }, { updateBrowserSessionPersonaFromAction }] = await Promise.all([
      import('./server/store.ts'),
      import('./server/browser-session-auth.ts'),
    ])
    return updateBrowserSessionPersonaFromAction(store(), data)
  })
