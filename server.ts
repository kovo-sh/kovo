import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
const files = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'], '/inter.woff2': ['inter.woff2', 'font/woff2'], '/inter-OFL.txt': ['inter-OFL.txt', 'text/plain'], '/instrument-serif.woff2': ['instrument-serif.woff2', 'font/woff2'], '/instrument-serif-OFL.txt': ['instrument-serif-OFL.txt', 'text/plain'] } as const;
createServer(async (req, res) => {
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;
  const file = files[path as keyof typeof files];
  if (!file) { res.writeHead(404).end(); return; }
  try {
    const body = await readFile(new URL('./dist/' + file[0], import.meta.url));
    res.writeHead(200, { 'Content-Type': file[1], 'Cache-Control': 'no-store' }).end(body);
  } catch { res.writeHead(500).end('Build the prototype with npm run build.'); }
}).listen(Number(process.env.PORT ?? 8000), '127.0.0.1');
