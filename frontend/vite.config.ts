import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// In dev, run the backend with SS_BASE_URL=http://localhost:5173 so links and the
// Origin check match the Vite dev server, which proxies /api to it.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: false },
      '/healthz': 'http://localhost:8080',
    },
  },
  build: { sourcemap: false },
})
