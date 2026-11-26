import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { getAppRuntime } from './server/app-runtime.ts'
import type { AppRuntime, AppRuntimeOptions } from './server/app-runtime.ts'
import { execution } from './server/execution.ts'

export function initialize(options?: AppRuntimeOptions): AppRuntime {
  const runtime = getAppRuntime(options)
  // Bind the single shared Store through AppRuntime and run startup crash/lab recovery before
  // starting Execution so Vite SSR and scripts/serve.ts share one recovered runtime.
  void runtime.store
  void runtime.startupRecover().catch(() => undefined)
  execution().start()
  return runtime
}

export { getAppRuntime }

export default createServerEntry({
  fetch(request, options) {
    initialize()
    return handler.fetch(request, options)
  },
})
