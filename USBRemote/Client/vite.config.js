import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './', // crucial for Electron file:// URLs loading correctly
  server: {
    port: 5173,
    strictPort: true
  }
})
