import { StrictMode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import './index.profile-app.css'
import App from './App'

/**
 * Entry point for the profile-app bundle (built by vite.profile-app.config.ts),
 * separate from main.tsx (which stays untouched for xrpl-wallet's own
 * standalone dev preview). Mounted into #profile-page .profile-wrap by
 * NaluLF/scripts/profile-react-bridge.js once the nalulf_react_profile
 * feature flag is on.
 *
 * index.css's Tailwind output is safe to import/load globally here because
 * vite.profile-app.config.ts compiles it with a scoped Tailwind config
 * (tailwind.profile-app.config.js — preflight disabled, utilities scoped to
 * #profile-page) instead of the unscoped config xrpl-wallet's own
 * standalone app uses.
 */

export interface NaluLFBridge {
  state?: Record<string, unknown>;
}

let root: Root | null = null;

export function mount(container: HTMLElement, _bridge?: NaluLFBridge) {
  if (root) return; // already mounted — idempotent, matches nav.js's "mount once" page lifecycle
  root = createRoot(container);
  root.render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

export function unmount() {
  root?.unmount();
  root = null;
}
