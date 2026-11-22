// Trivial materialized entrypoint for the fixture app. Real apps wire a router here.
export function startServer(opts: { plan: unknown }): string {
  void opts
  return 'mini-app:ready'
}
