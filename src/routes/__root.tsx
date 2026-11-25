import { createRootRoute, HeadContent, Link, Outlet, Scripts, useRouterState } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { workspaceData } from '../actions.ts'
import appStyles from '../app.css?url'
import { AppShell } from '../components/shell/AppShell.tsx'
import { buttonVariants } from '../components/ui/button.tsx'
import designSystemStyles from '../styles/tailwind.css?url'

export const Route = createRootRoute({
  loader: () => workspaceData(),
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'Kovo Hunter' },
    ],
    links: [
      { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
      // Base tokens and element defaults load before Tailwind v4 utilities so
      // utility classes always win cleanly on same-specificity ties.
      { rel: 'stylesheet', href: appStyles },
      { rel: 'stylesheet', href: designSystemStyles },
    ],
  }),
  component: Shell,
  shellComponent: Document,
  errorComponent: ({ error }) => (
    <main className="mx-auto w-full max-w-[960px] px-6 pb-[72px] pt-6">
      <h1>Kovo Hunter couldn’t open this view</h1>
      <p className="mb-3.5 mt-2 text-fg-subtle">
        {error instanceof Error ? error.message : 'This view is unavailable.'}
      </p>
      <Link to="/" className={buttonVariants({ variant: 'outline' })}>
        Return to workspace
      </Link>
    </main>
  ),
})

function Shell() {
  // The run workspace is full-screen with its own rail, palette, and header.
  const isRunRoute = useRouterState({
    select: state => state.matches.some(match => match.routeId.startsWith('/runs/$runId')),
  })
  const data = Route.useLoaderData()
  if (isRunRoute) return <Outlet />
  return <AppShell data={data}><Outlet /></AppShell>
}

const THEME_BOOT_SCRIPT = `(function(){try{var s=localStorage.getItem('guardian-appearance');var a=(s==='dark'||s==='light'||s==='system')?s:'light';document.documentElement.dataset.appearance=a;var d=a==='dark'||(a==='system'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=d?'dark':'light';}catch(e){}})();`

function Document({ children }: { children: ReactNode }) {
  return <html lang="en" data-appearance="light" data-theme="light">
    <head>
      <HeadContent />
      <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
    </head>
    <body>{children}<Scripts /></body>
  </html>
}
