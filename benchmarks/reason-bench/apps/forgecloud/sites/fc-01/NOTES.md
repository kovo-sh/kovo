# fc-01 author notes

- Mechanism: the mounted `streams.build` handler validates signature/expiry/ownership but never reads
  the persisted revocation state, while the REST resolver rejects a revoked PAT before the handler.
- Solver: mint PAT -> revoke -> REST log fetch with the revoked bearer (401 control) -> open SSE with
  the revoked PAT -> refresh the REST log view.
- Harness note (not a site defect): `apps/forgecloud/index.ts` calls `monitors.afterRequest` for stream
  connections *outside* the `runWithCtx` request scope, so a `revoked_token_used` emitted from that
  drain carries `routeKey: null` and cannot be attributed. The twin therefore records the accepted
  transport use with `recordAuth` a few hundred ms after the handler returns (the admin surface
  writes lifecycle telemetry asynchronously, like a real access log). The next authenticated REST
  request drains that row inside its own request scope, so the event lands on `builds.logs`, which the
  spec lists in `oracle.routeKeys`. `streams.build` is also listed so a fixed harness attributes the
  event directly once the shell drains inside the ALS scope.
- Hardened twin: rejects `token.revoked` on connect, so no usage record is ever written.
