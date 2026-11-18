import { createRootRoute, HeadContent, Link, Outlet, Scripts } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { useEffect, useState } from 'react'
import { Brand } from '../components/common.tsx'
import styles from '../app.css?url'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'Guardian' },
    ],
    links: [{ rel: 'stylesheet', href: styles }],
  }),
  component: Shell,
  shellComponent: Document,
  errorComponent: ({ error }) => <main className="workspace-page">
    <h1>Guardian couldn’t open this view</h1>
    <p className="muted">{error instanceof Error ? error.message : 'This view is unavailable.'}</p>
    <Link to="/">Return to workspace</Link>
  </main>,
})

type Appearance = 'system' | 'light' | 'dark'

function ViewPreferences() {
  const [appearance, setAppearance] = useState<Appearance>('system')
  const [layout, setLayout] = useState('workspace')
  useEffect(() => {
    const saved = localStorage.getItem('guardian-appearance')
    if (saved === 'light' || saved === 'dark') setAppearance(saved)
    const savedLayout = localStorage.getItem('guardian-app-layout')
    if (savedLayout === 'canvas' || savedLayout === 'review') setLayout(savedLayout)
  }, [])
  useEffect(() => {
    document.documentElement.dataset.appearance = appearance
    document.documentElement.dataset.appLayout = layout
  }, [appearance, layout])

  return <details className="top-menu">
    <summary>View</summary>
    <div className="menu-surface">
      <label>Appearance
        <select value={appearance} onChange={event => {
          const choice = event.target.value as Appearance
          localStorage.setItem('guardian-appearance', choice)
          setAppearance(choice)
        }}>
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </label>
      <label>Layout
        <select value={layout} onChange={event => {
          localStorage.setItem('guardian-app-layout', event.target.value)
          setLayout(event.target.value)
        }}>
          <option value="workspace">Workspace</option>
          <option value="canvas">Canvas</option>
          <option value="review">Review</option>
        </select>
      </label>
    </div>
  </details>
}

function Shell() {
  return <>
    <header className="app-nav">
      <Brand />
      <nav aria-label="Workspace"><Link to="/">Projects</Link></nav>
      <div className="nav-right"><ViewPreferences /></div>
    </header>
    <Outlet />
  </>
}

function Document({ children }: { children: ReactNode }) {
  return <html lang="en">
    <head><HeadContent /></head>
    <body>{children}<Scripts /></body>
  </html>
}
