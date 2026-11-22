// SiteSpec for og.dashboard-cache-poison (authoritative definition lives in truth/sites.ts).
import { sites } from '../../truth/sites.ts'
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = sites.find((s) => s.id === "og.dashboard-cache-poison")!
