/* =====================================================
   profile-react-bridge.js — mounts the React Profile app
   (built separately from xrpl-wallet/, see vite.profile-app.config.ts)
   into the existing #profile-page container.

   Gated by the nalulf_react_profile feature flag so legacy profile.js
   keeps serving everyone until each phase reaches parity (see the
   phased-rollout plan). #profile-page is never destroyed by nav.js's
   page switching (pure show/hide), so this mounts once and stays
   mounted — no unmount/remount needed on page navigation.
   ===================================================== */

export function isReactProfileEnabled() {
  try {
    return localStorage.getItem('nalulf_react_profile') === '1'
      || new URLSearchParams(location.search).get('reactProfile') === '1';
  } catch {
    return false;
  }
}

export function mountReactProfile() {
  const wrap = document.querySelector('#profile-page .profile-wrap');
  if (!wrap || wrap.dataset.reactMounted) return;
  if (!window.NaluLFProfileApp) {
    console.error('[profile-react-bridge] profile-app.js did not load — check the <script> tag in index.html.');
    return;
  }
  wrap.innerHTML = '';
  wrap.dataset.reactMounted = '1';
  window.NaluLFProfileApp.mount(wrap, window.NaluLF);
}
