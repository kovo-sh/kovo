import { createRootRoute, HeadContent, Link, Outlet, Scripts, useRouter, useRouterState } from '@tanstack/react-router'
import type { ErrorComponentProps } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { workspaceData } from '../actions.ts'
import appStyles from '../app.css?url'
import { AppShell } from '../components/shell/AppShell.tsx'
import { Button, buttonVariants } from '../components/ui/button.tsx'
import { describeStateError, errorMessage, StatePanel, stateErrorDetails } from '../components/ui/state-panel.tsx'
import { cn } from '../lib/cn.ts'
import designSystemStyles from '../styles/tailwind.css?url'

export const Route = createRootRoute({
  loader: () => workspaceData(),
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'Kovo' },
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
  // Root-loader failures cannot render the shell (its data is missing), so they
  // get the same friendly treatment full-page. Child-route errors use the
  // router's defaultErrorComponent and render inside AppShell's Outlet.
  errorComponent: props => (
    <div className="flex min-h-screen bg-panel text-fg">
      <RouteErrorView {...props} />
    </div>
  ),
})

/** Keep the document title in sync with an in-shell status view, restoring it on exit. */
function useDocumentTitle(title: string) {
  useEffect(() => {
    const previous = document.title
    document.title = title
    return () => { document.title = previous }
  }, [title])
}

/**
 * "Go to Projects" as a router link styled like <Button>. It stays a real link
 * (Base UI's `nativeButton={false}` would stamp `role="button"` on the <a>), so
 * it carries the button data-slot/variant contract and merges classes via cn().
 * The text colour is `!important` because app.css's unlayered
 * `a { color: inherit }` otherwise beats the layered `text-*` utility and the
 * label inherits the panel's `--fg` (black on the blue fill in light mode).
 */
function ProjectsLink({ variant }: { variant: 'default' | 'outline' }) {
  return (
    <Link
      to="/"
      data-slot="button"
      data-variant={variant}
      data-size="default"
      className={cn(buttonVariants({ variant }), 'no-underline', variant === 'default' ? 'text-accent-fg!' : 'text-fg!')}
    >
      Go to Projects
    </Link>
  )
}

/** Styled 404 rendered inside the AppShell, so the rail, ⌘K and theme toggle stay available. */
export function NotFoundView() {
  const pathname = useRouterState({ select: state => state.location.pathname })
  useDocumentTitle('Not found · Kovo')
  return (
    <main className="flex flex-1 items-center justify-center px-6 py-10">
      <StatePanel
        kind="not-found"
        variant="page"
        title="Page not found"
        description={<>Nothing lives at <code className="font-mono text-[12px] [overflow-wrap:anywhere]">{pathname}</code>. It may have moved, or the link is out of date.</>}
        action={<ProjectsLink variant="default" />}
        secondaryAction={<Button type="button" variant="outline" onClick={() => window.history.back()}>Go back</Button>}
        details={['code: not-found', 'status: 404', `path: ${pathname}`].join('\n')}
        copyDetails
        data-testid="state-not-found"
      />
    </main>
  )
}

/** False during SSR and the hydration pass, true after mount. */
function useHydrated(): boolean {
  const [hydrated, setHydrated] = useState(false)
  useEffect(() => setHydrated(true), [])
  return hydrated
}

/**
 * Friendly, recoverable route error: plain-language copy mapped from the error
 * code (401/403/404/5xx/timeout/malformed), a retry that re-runs the loaders, a
 * way home, and the raw message only behind "Technical details" (never a
 * ZodError array or a JS exception in the body copy).
 */
export function RouteErrorView({ error, reset, className }: ErrorComponentProps & { className?: string }) {
  const router = useRouter()
  // The serialized error the client hydrates with can differ from the server's
  // instance, so the copy and raw details render only after mount (no hydration mismatch).
  const hydrated = useHydrated()
  const copy = hydrated ? describeStateError(error) : null
  const details = hydrated && errorMessage(error) ? stateErrorDetails(error) : null
  useDocumentTitle('Something went wrong · Kovo')
  return (
    <main className={cn('flex flex-1 items-center justify-center px-6 py-10', className)}>
      <StatePanel
        kind={copy?.kind === 'degraded' ? 'degraded' : 'error'}
        variant="page"
        role="alert"
        title="Kovo couldn’t open this view"
        description={copy && copy.code !== 'unknown'
          ? `${copy.title}. ${copy.description}`
          : 'Something went wrong while loading this page. Try again, or head back to your projects.'}
        action={(
          <Button
            type="button"
            variant="default"
            onClick={() => {
              reset()
              void router.invalidate()
            }}
          >
            Try again
          </Button>
        )}
        secondaryAction={<ProjectsLink variant="outline" />}
        details={details}
        copyDetails
        data-testid="state-route-error"
      />
    </main>
  )
}

function Shell() {
  // The run workspace is full-screen with its own rail, palette, and header.
  const isRunRoute = useRouterState({
    select: state => state.matches.some(match => match.routeId.startsWith('/runs/$runId')),
  })
  const data = Route.useLoaderData()
  if (isRunRoute) return <Outlet />
  return <AppShell data={data}><Outlet /></AppShell>
}

const THEME_BOOT_SCRIPT = `(function(){try{var s=localStorage.getItem('kovo-appearance');var a=(s==='dark'||s==='light'||s==='system')?s:'light';document.documentElement.dataset.appearance=a;var d=a==='dark'||(a==='system'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=d?'dark':'light';}catch(e){}})();`

function Document({ children }: { children: ReactNode }) {
  return <html lang="en" data-appearance="light" data-theme="light">
    <head>
      <HeadContent />
      <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
    </head>
    <body>{children}<Scripts /></body>
  </html>
}
