// Tiny in-memory table store. Shared stateful semantics without external dependencies.
export type Row = Record<string, unknown>

export class MemStore {
  private readonly tables = new Map<string, Map<string, Row>>()

  private table(name: string): Map<string, Row> {
    let t = this.tables.get(name)
    if (!t) {
      t = new Map<string, Row>()
      this.tables.set(name, t)
    }
    return t
  }

  insert(table: string, row: Row): Row {
    const id = String(row.id ?? '')
    if (!id) throw new Error(`MemStore.insert(${table}): row needs an id`)
    this.table(table).set(id, { ...row })
    return { ...row }
  }

  get(table: string, id: string): Row | null {
    const row = this.table(table).get(id)
    return row ? { ...row } : null
  }

  update(table: string, id: string, patch: Row): Row | null {
    const current = this.table(table).get(id)
    if (!current) return null
    const next = { ...current, ...patch }
    this.table(table).set(id, next)
    return { ...next }
  }

  delete(table: string, id: string): boolean {
    return this.table(table).delete(id)
  }

  all(table: string): Row[] {
    return [...this.table(table).values()].map((row) => ({ ...row }))
  }

  find(table: string, predicate: (row: Row) => boolean): Row[] {
    return this.all(table).filter(predicate)
  }

  count(table: string): number {
    return this.table(table).size
  }

  clear(): void {
    this.tables.clear()
  }
}
