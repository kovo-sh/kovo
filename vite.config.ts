import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  publicDir: 'public',
  plugins: [tanstackStart(), react(), tailwindcss()],
  environments: {
    client: { build: { outDir: 'build/client' } },
    ssr: { build: { outDir: 'build/server' } },
  },
})
