import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

// https://vite.dev/config/
export default defineConfig({
  // The xrpl npm package (via its own dependencies) assumes Node globals
  // like `process` and `Buffer` exist — Vite doesn't polyfill these by
  // default (unlike webpack), so without this the app crashes at import
  // time with "process is not defined" before React ever renders.
  plugins: [react(), nodePolyfills({ include: ['process', 'buffer', 'crypto', 'stream', 'util'] })],
})
