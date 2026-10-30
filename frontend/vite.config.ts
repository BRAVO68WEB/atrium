import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The production build is embedded in the atrium binary and served at /dashboard/.
export default defineConfig({
  base: '/dashboard/',
  plugins: [react()],
  build: {
    outDir: '../internal/dashboard/dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/dashboard/api': 'http://127.0.0.1:8080',
      '/dashboard/session': 'http://127.0.0.1:8080',
      '/dashboard/logout': 'http://127.0.0.1:8080',
    },
  },
})
