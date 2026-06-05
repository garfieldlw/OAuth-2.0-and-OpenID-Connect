import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
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
