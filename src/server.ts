import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { execution } from './server/execution.ts'

export function initialize() {
  execution().start()
}

export default createServerEntry({
  fetch(request, options) {
    initialize()
    return handler.fetch(request, options)
  },
})
