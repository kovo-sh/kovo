import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { compile, optimize } from '@tailwindcss/node'
import { badgeVariants, buttonVariants } from '../src/components/ui/variants.ts'
import { cn } from '../src/lib/cn.ts'

const ROOT = new URL('..', import.meta.url).pathname
const CLIENT_ASSETS = join(ROOT, 'build', 'client', 'assets')

function readCss(file: string): string {
  return readFileSync(join(CLIENT_ASSETS, file), 'utf8')
}

async function clientCss(): Promise<Array<{ file: string; css: string }>> {
  if (existsSync(CLIENT_ASSETS)) {
    const built = readdirSync(CLIENT_ASSETS)
      .filter(file => file.endsWith('.css'))
      .map(file => ({ file, css: readCss(file) }))
    if (built.length > 0) return built
  }
  const stylesDir = join(ROOT, 'src', 'styles')
  const compiler = await compile(readFileSync(join(stylesDir, 'tailwind.css'), 'utf8'), {
    base: stylesDir,
    onDependency: () => {},
    customCssResolver: async id => (id.startsWith('tailwindcss/') ? resolve(ROOT, 'node_modules', id) : undefined),
  })
  const compiledTw = optimize(
    compiler.build(['bg-panel', 'bg-sunk', 'text-fg', 'text-fg-muted', 'border-line', 'text-accent', 'shadow-popover']),
    { minify: true },
  ).code
  return [
    { file: 'tailwind.css', css: compiledTw },
    { file: 'tokens.css', css: readFileSync(join(stylesDir, 'tokens.css'), 'utf8') },
  ]
}

test('cn() composes conditionals and resolves conflicting utilities', () => {
  assert.equal(cn('a', 'b'), 'a b')
  assert.equal(cn('px-2 py-2', 'px-4'), 'py-2 px-4')
  assert.equal(cn('bg-panel', 'bg-sunk'), 'bg-sunk')
  assert.equal(cn('text-fg', 'text-fg-muted'), 'text-fg-muted')
  assert.equal(cn('px-2', false, undefined, null, 'text-fg'), 'px-2 text-fg')
  assert.equal(cn('rounded-md', { 'text-accent': true, 'border-line': false }), 'rounded-md text-accent')
})

test('buttonVariants exposes cva variants with token utility classes', () => {
  const base = buttonVariants()
  assert.match(base, /inline-flex/)
  assert.match(base, /h-\[26px\]/)
  assert.match(base, /px-\[9px\]/)
  assert.match(base, /text-\[12\.5px\]/)
  // default variant is outline, keeping the legacy bare-button look
  assert.match(base, /bg-raise/)
  assert.match(base, /shadow-hairline/)

  const primary = buttonVariants({ variant: 'default' })
  assert.match(primary, /bg-accent/)
  assert.match(primary, /text-accent-fg/)
  assert.doesNotMatch(primary, /bg-raise/)

  const ghost = buttonVariants({ variant: 'ghost' })
  assert.match(ghost, /bg-transparent/)
  assert.match(ghost, /text-fg-muted/)

  assert.match(buttonVariants({ size: 'icon' }), /inline-grid/)
  assert.match(buttonVariants({ size: 'icon' }), /size-7/)
})

test('badgeVariants covers every semantic status variant', () => {
  const variants = ['neutral', 'accent', 'ok', 'warn', 'danger', 'outline'] as const
  const classes = variants.map(variant => badgeVariants({ variant }))

  assert.equal(new Set(classes).size, variants.length, 'each badge variant must be visually distinct')
  assert.match(badgeVariants(), /border-line-2/)
  assert.match(badgeVariants({ variant: 'accent' }), /bg-accent-soft/)
  assert.match(badgeVariants({ variant: 'accent' }), /text-accent/)
  assert.match(badgeVariants({ variant: 'ok' }), /text-ok/)
  assert.match(badgeVariants({ variant: 'warn' }), /text-warn/)
  assert.match(badgeVariants({ variant: 'danger' }), /text-danger/)
  assert.match(badgeVariants({ variant: 'outline' }), /border-line/)
})

test('build output ships Tailwind utilities next to the legacy tokens', async () => {
  const assets = await clientCss()
  assert.ok(assets.length > 0, 'no built or compiled CSS found')

  const tailwind = assets.find(({ css }) => /\.bg-panel(?:,[^{]+)?\{/.test(css))
  assert.ok(tailwind, 'no Tailwind stylesheet in build output')

  // Semantic utilities resolve through the legacy token variables (light/dark aware).
  assert.match(tailwind.css, /\.bg-panel(?:,[^{]+)?\{background-color:var\(--panel\)\}/)
  assert.match(tailwind.css, /\.bg-sunk(?:,[^{]+)?\{background-color:var\(--sunk\)\}/)
  assert.match(tailwind.css, /\.text-fg(?:,[^{]+)?\{color:var\(--fg\)\}/)
  assert.match(tailwind.css, /\.text-fg-muted(?:,[^{]+)?\{color:var\(--fg-2\)\}/)
  assert.match(tailwind.css, /\.border-line(?:,[^{]+)?\{border-color:var\(--line\)\}/)
  assert.match(tailwind.css, /\.text-accent(?:,[^{]+)?\{color:var\(--accent\)\}/)
  assert.match(tailwind.css, /\.shadow-popover(?:,[^{]+)?\{[^}]*var\(--shadow-pop\)/)

  // Legacy semantic tokens are still emitted by app.css.
  const tokens = assets.find(({ css }) => /--panel:\s*#fff/.test(css))
  assert.ok(tokens, 'legacy design tokens missing from build output')

  // Preflight must not be shipped: legacy sheets own the base reset.
  assert.doesNotMatch(tailwind.css, /text-size-adjust/)
  assert.doesNotMatch(tailwind.css, /::file-selector-button/)
  assert.doesNotMatch(tailwind.css, /@layer utilities/)
})
