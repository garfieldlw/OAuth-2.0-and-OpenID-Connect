import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
      '/oauth': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
      '/.well-known': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
      '/userinfo': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
      '/logout': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
    },
  },
})
