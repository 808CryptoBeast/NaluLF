import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'
import path from 'node:path'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'
import prefixSelector from 'postcss-prefix-selector'
import tailwindProfileAppConfig from './tailwind.profile-app.config.js'

/**
 * Separate build target from the main xrpl-wallet Vite config (vite.config.ts,
 * which stays untouched for xrpl-wallet's own standalone dev/build). This one
 * compiles src/mount.tsx into a single IIFE bundle + CSS file that the plain
 * vanilla-JS NaluLF app (no build step of its own) can load via ordinary
 * <script defer> / <link rel="stylesheet"> tags — see NaluLF/scripts/profile-react-bridge.js.
 *
 * Run with: npm run build:profile-app
 */
export default defineConfig({
  // The xrpl npm package assumes Node globals (`process`, `Buffer`) exist —
  // needed here too, since Phase 1+ will pull xrplService.ts (which imports
  // `xrpl`) into this same bundle.
  plugins: [react(), nodePolyfills({ include: ['process', 'buffer', 'crypto', 'stream', 'util'] })],
  // Don't copy xrpl-wallet's own public/ assets (favicon.svg, icons.svg) into
  // the output — this build only produces the JS/CSS bundle NaluLF loads.
  publicDir: false,
  // Override the project's default postcss.config.js (which points at the
  // unscoped tailwind.config.js used by xrpl-wallet's own standalone app).
  // This build additionally scopes the ENTIRE compiled output — including
  // Tailwind's preflight base-reset layer, which the `important` config
  // option does NOT cover — under #profile-page, via postcss-prefix-selector.
  // (An earlier attempt disabled preflight instead of scoping it, which
  // broke click targets by removing the box-sizing:border-box reset several
  // layout utilities assume.)
  css: {
    postcss: {
      plugins: [
        tailwindcss(tailwindProfileAppConfig),
        prefixSelector({
          prefix: '#profile-page',
          transform(prefix, selector, prefixedSelector) {
            if (selector === ':root' || selector === 'html' || selector === 'body') return prefix;
            if (selector === '*') return `${prefix}, ${prefix} *`;
            return prefixedSelector;
          },
        }),
        autoprefixer(),
      ],
    },
  },
  // Vite's standard app-mode build auto-replaces process.env.NODE_ENV (React's
  // own source checks this at import time for dev-mode warnings), but library
  // mode doesn't inherit that define automatically — without this, the bundle
  // throws "process is not defined" the moment it's evaluated in a plain
  // <script> tag (no Node.js runtime/global in the browser).
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  build: {
    outDir: path.resolve(__dirname, '../NaluLF/scripts/profile-app/dist'),
    emptyOutDir: true,
    cssCodeSplit: false,
    lib: {
      entry: path.resolve(__dirname, 'src/mount.tsx'),
      name: 'NaluLFProfileApp',
      formats: ['iife'],
      fileName: () => 'profile-app.js',
    },
    rollupOptions: {
      output: {
        assetFileNames: 'profile-app[extname]',
      },
    },
  },
})
