import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { store } from './server/store.ts'

export function initialize() {
  store()
}

export default createServerEntry({
  fetch(request, options) {
    initialize()
    return handler.fetch(request, options)
  },
})
