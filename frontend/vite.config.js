import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  test: { environment: 'jsdom', setupFiles: './src/test/setup.js', css: false },
  // Stamped at build time and shown in the sidebar, so it is easy to tell which build is running.
  define: { __BUILD_TIME__: JSON.stringify(new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC") },
})
