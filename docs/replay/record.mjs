// Record one loop of the replay hero (window.hero.duration, ~51 s) at 1080p.
//
//   node docs/lab/replay-hero/record.mjs [--out hero.webm] [--frames] [--fps 30]
//
// Default mode uses Playwright's recordVideo (real time, WebM) and, when ffmpeg
// is on PATH, also writes an H.264 MP4 next to it. --frames steps the timeline
// deterministically (window.hero.seek) and pipes screenshots to ffmpeg: slower,
// but no dropped frames. Serves this folder itself on a free localhost port.
// Playwright is resolved from the cwd, PLAYWRIGHT_DIR, or the repo root.
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { readFile, rename, mkdir, rm } from 'node:fs/promises'
import { spawn, spawnSync } from 'node:child_process'
import { dirname, extname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d }
const out = resolve(opt('--out', join(here, 'replay-hero.webm')))
const fps = Number(opt('--fps', '30'))
const frames = args.includes('--frames')
const W = 1920, H = 1080

function loadPlaywright() {
  const roots = [process.env.PLAYWRIGHT_DIR, process.cwd(), resolve(here, '../..')].filter(Boolean)
  for (const r of roots) {
    try { return createRequire(join(r, 'noop.js'))('playwright') } catch { /* next */ }
  }
  throw new Error('playwright not found; run from a checkout with node_modules or set PLAYWRIGHT_DIR')
}
const { chromium } = loadPlaywright()

const TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' }
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://x').pathname
  const file = join(here, path === '/' ? 'index.html' : path.replace(/^\/+/, ''))
  if (!file.startsWith(here)) { res.writeHead(403).end(); return }
  try { res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(await readFile(file)) }
  catch { res.writeHead(404).end() }
})
await new Promise(r => server.listen(0, '127.0.0.1', r))
const url = `http://127.0.0.1:${server.address().port}/?rec=1&paused=1`
const hasFfmpeg = spawnSync('ffmpeg', ['-version']).status === 0

const browser = await chromium.launch()
try {
  if (frames) {
    if (!hasFfmpeg) throw new Error('--frames needs ffmpeg on PATH')
    const page = await browser.newPage({ viewport: { width: W, height: H } })
    await page.goto(url, { waitUntil: 'networkidle' })
    await page.evaluate(() => window.hero.ready)
    const mp4 = out.replace(/\.\w+$/, '') + '.mp4'
    const ff = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(fps), '-i', '-', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '18', '-movflags', '+faststart', mp4], { stdio: ['pipe', 'inherit', 'inherit'] })
    const dur = await page.evaluate(() => window.hero.duration)
    const n = Math.round(dur * fps)
    for (let i = 0; i < n; i++) {
      await page.evaluate(t => window.hero.seek(t), i / fps)
      // let CSS transitions advance one frame's worth
      await page.waitForTimeout(1000 / fps)
      ff.stdin.write(await page.screenshot({ type: 'png' }))
      if (i % fps === 0) process.stdout.write(`\r${(i / fps).toFixed(0)}s / ${dur}s`)
    }
    ff.stdin.end()
    await new Promise(r => ff.on('close', r))
    console.log(`\nwrote ${mp4}`)
  } else {
    const tmp = join(dirname(out), '.rec-tmp')
    await mkdir(tmp, { recursive: true })
    const ctx = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir: tmp, size: { width: W, height: H } } })
    const page = await ctx.newPage()
    await page.goto(url, { waitUntil: 'networkidle' })
    await page.evaluate(() => window.hero.ready)
    const dur = await page.evaluate(() => window.hero.duration)
    await page.evaluate(() => { window.hero.seek(0); window.hero.play() })
    await page.waitForTimeout(dur * 1000)
    const video = page.video()
    await ctx.close()
    const raw = await video.path()
    await rename(raw, out)
    await rm(tmp, { recursive: true, force: true })
    console.log(`wrote ${out}`)
    if (hasFfmpeg) {
      const mp4 = out.replace(/\.\w+$/, '') + '.mp4'
      const probe = spawnSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', out], { encoding: 'utf8' })
      const total = Number(probe.stdout.trim()) || dur
      const start = Math.max(0, total - dur) // drop the page-load lead-in
      spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', start.toFixed(2), '-i', out, '-t', String(dur), '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '18', '-r', '30', '-movflags', '+faststart', mp4], { stdio: 'inherit' })
      console.log(`wrote ${mp4} (trimmed ${start.toFixed(2)} s of load time)`)
    }
  }
} finally {
  await browser.close()
  server.close()
}
