import { createRouter } from '@tanstack/react-router'
import { NotFoundView, RouteErrorView } from './routes/__root.tsx'
import { routeTree } from './routeTree.gen'

export function getRouter() {
  return createRouter({
    routeTree,
    defaultPreload: 'intent',
    scrollRestoration: true,
    // Both render inside the root Outlet (inside AppShell), never as bare text.
    defaultNotFoundComponent: NotFoundView,
    defaultErrorComponent: RouteErrorView,
  })
}

declare module '@tanstack/react-router' {
  interface Register { router: ReturnType<typeof getRouter> }
}
