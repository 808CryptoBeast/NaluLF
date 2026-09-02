/* =====================================================
   chart-atmosphere.js — Decorative WebGL particle backdrop
   for the DEX chart panel.
   ─────────────────────────────────────────────────────
   Isolated into its own ES module deliberately: this is the only place in
   the app that touches Three.js, so nothing else needs to change, and no
   `window.THREE` global is created — the imported module namespace stays a
   local reference inside this file. The library itself is loaded as a real
   ES module (three.js's `build/three.module.js`) instead of the deprecated
   global/UMD build (`build/three.js` / `build/three.min.js`), which the
   project's own version of three.js (anything past r160) no longer ships.

   Dynamic import() has no native integrity attribute the way a <script
   integrity="..."> tag does, so the same guarantee this app's other
   CDN-loaded libraries get from SRI is reproduced manually here: fetch the
   file as bytes, hash it with SubtleCrypto, and only import it (via a Blob
   URL) if the hash matches the one pinned below. A wrong pin fails loudly
   instead of silently executing unverified code — if this version is ever
   bumped, the hash must be recomputed from the real downloaded file, never
   guessed.
   ===================================================== */

const THREE_URL = 'https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js';
const THREE_SHA384_B64 = '61S/Nu32S3E5+n+KpCOTb2eRYps6fVKm+9Gz1QBvSePFthb46f063Aa/qe/lykFZ';

let _threeModulePromise = null;
function _loadThreeModule() {
  if (_threeModulePromise) return _threeModulePromise;
  _threeModulePromise = (async () => {
    const res = await fetch(THREE_URL, { mode: 'cors' });
    if (!res.ok) throw new Error(`three.js fetch failed: HTTP ${res.status}`);
    const buf = await res.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-384', buf);
    const digestB64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
    if (digestB64 !== THREE_SHA384_B64) {
      throw new Error('three.js module failed integrity verification — refusing to execute.');
    }
    const blobUrl = URL.createObjectURL(new Blob([buf], { type: 'text/javascript' }));
    try {
      return await import(/* webpackIgnore: true */ blobUrl);
    } finally {
      URL.revokeObjectURL(blobUrl);
    }
  })();
  _threeModulePromise.catch(() => { _threeModulePromise = null; }); // let a failed load be retried later
  return _threeModulePromise;
}

let _runtime = { renderer: null, scene: null, camera: null, points: null, raf: 0, host: null, resizeHandler: null };

/** Whether a scene is currently mounted and animating anywhere (not
 *  necessarily attached to a specific host — callers use this to decide
 *  whether there's anything to tear down or reuse). */
export function hasActiveChartAtmosphere() {
  return !!_runtime.renderer;
}

export function destroyChartAtmosphere() {
  if (_runtime.resizeHandler) {
    try { window.removeEventListener('resize', _runtime.resizeHandler); } catch {}
  }
  if (_runtime.raf) cancelAnimationFrame(_runtime.raf);
  if (_runtime.renderer?.domElement?.parentElement) {
    try { _runtime.renderer.domElement.parentElement.removeChild(_runtime.renderer.domElement); } catch {}
  }
  if (_runtime.renderer) {
    try { _runtime.renderer.dispose(); } catch {}
  }
  _runtime = { renderer: null, scene: null, camera: null, points: null, raf: 0, host: null, resizeHandler: null };
}

/**
 * Mounts the particle field into `host`, or does nothing if it's already
 * mounted there. `getChangePct` is a () => number callback for the DEX
 * chart's current % change, used to recolor/re-speed the particles — passed
 * in rather than imported, so this module has no dependency on any of
 * profile.js's internal state.
 */
export async function mountChartAtmosphere(host, getChangePct) {
  if (!host) return;
  if (_runtime.renderer && host.contains(_runtime.renderer.domElement)) return;
  if ((navigator.hardwareConcurrency || 4) <= 3) return;
  try {
    const THREE = await _loadThreeModule();

    destroyChartAtmosphere();

    const width = Math.max(1, host.clientWidth || 640);
    const height = Math.max(1, host.clientHeight || 460);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(52, width / height, 0.1, 1000);
    camera.position.z = 46;

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(2, window.devicePixelRatio || 1));
    renderer.setSize(width, height);
    host.appendChild(renderer.domElement);

    const count = 900;
    const vertices = new Float32Array(count * 3);
    for (let i = 0; i < count; i += 1) {
      const j = i * 3;
      vertices[j] = (Math.random() - 0.5) * 90;
      vertices[j + 1] = (Math.random() - 0.5) * 40;
      vertices[j + 2] = (Math.random() - 0.5) * 24;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(vertices, 3));
    const mat = new THREE.PointsMaterial({
      color: 0x4dd8ff,
      size: 0.25,
      transparent: true,
      opacity: 0.26,
      depthWrite: false,
    });
    const points = new THREE.Points(geo, mat);
    scene.add(points);

    let frame = 0;
    let lastActiveDraw = 0;
    const animate = () => {
      frame += 1;
      const change = Number(getChangePct?.() || 0);
      const volatility = Math.min(4, Math.max(0.35, Math.abs(change) / 2.2));
      const warm = change > 0 ? 0xffb85a : 0xff6e9f;
      const cool = 0x4dd8ff;
      mat.color.setHex(Math.abs(change) > 1.5 ? warm : cool);
      points.rotation.y += 0.0009 * volatility;
      points.rotation.x = Math.sin(frame * 0.0015 * volatility) * 0.08;
      points.position.y = Math.sin(frame * 0.003 * volatility) * 0.7;
      if (!document.hidden || (Date.now() - lastActiveDraw) > 350) {
        renderer.render(scene, camera);
        lastActiveDraw = Date.now();
      }
      _runtime.raf = requestAnimationFrame(animate);
    };

    const onResize = () => {
      const w = Math.max(1, host.clientWidth || 640);
      const h = Math.max(1, host.clientHeight || 460);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', onResize, { passive: true });

    _runtime = { renderer, scene, camera, points, raf: 0, host, resizeHandler: onResize };
    animate();
  } catch {
    // Atmosphere layer is decorative; never block core chart rendering.
  }
}
