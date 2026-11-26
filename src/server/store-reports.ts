/**
 * Store-owned repository helper for `reports` mutations (`R3-09`).
 *
 * Keeps Drizzle writes to `reports` inside `store-*.ts` (`scripts/check-direct-db-writes.ts`)
 * without mutating `store.ts` / `store-session.ts` public export surfaces.
 */
import { eq } from 'drizzle-orm'
import type { ReportBody } from '../domain.ts'
import * as tables from './schema.ts'
import type { StoreDb } from './store-session.ts'

export function updateReportBody(db: StoreDb, reportId: string, body: ReportBody): void {
  db.update(tables.reports).set({ body }).where(eq(tables.reports.id, reportId)).run()
}
