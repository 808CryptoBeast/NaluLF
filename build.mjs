// build.mjs — generates www/ (the Capacitor/iOS web asset dir) fresh from the
// real NaluLF/ source + root index.html on every run, instead of it being a
// hand-maintained copy. It was drifting badly: www/index.html referenced
// `NaluLF/scripts/main.js` and `NaluLF/css/main.css`, but no www/NaluLF/
// directory exists on disk — those were dead links, so the iOS build was
// very likely shipping a page whose entry module 404s. This also minifies
// JS/CSS for that build. The root index.html + NaluLF/ source stay untouched
// and still need zero build step for local dev (per README).
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, rmSync, cpSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const SRC = join(ROOT, 'NaluLF');
const WWW = join(ROOT, 'www');

const CSS_FILES = [
  'base.css', 'navbar.css', 'ui.css', 'landing.css', 'dashboard.css',
  'inspector.css', 'network.css', 'profile.css', 'main.css', 'auth.css',
];

async function main() {
  // www/icons/ holds hand-generated iOS app-icon sizes with no equivalent
  // source under NaluLF/ — never touch it. Everything else under www/ is
  // regenerated from scratch so stale files can't linger between builds.
  for (const name of ['css', 'scripts', 'images']) {
    rmSync(join(WWW, name), { recursive: true, force: true });
  }
  mkdirSync(join(WWW, 'css'), { recursive: true });
  mkdirSync(join(WWW, 'scripts'), { recursive: true });

  // JS: bundle the whole main.js import graph into one minified, code-split
  // output (the dynamic import('./xrpl.js') becomes its own lazily-loaded
  // chunk). Target matches the browsers README already commits to supporting.
  await build({
    entryPoints: [join(SRC, 'scripts', 'main.js')],
    bundle: true,
    minify: true,
    format: 'esm',
    splitting: true,
    outdir: join(WWW, 'scripts'),
    target: ['chrome90', 'edge90', 'firefox88', 'safari15'],
    logLevel: 'info',
  });

  // CSS: minify each file individually rather than concatenating them — the
  // separate <link> tags are a deliberate choice (see index.html's comment)
  // so the browser fetches all 10 in parallel instead of one render-blocking
  // chain; bundling them into one file would undo that.
  for (const name of CSS_FILES) {
    await build({
      entryPoints: [join(SRC, 'css', name)],
      minify: true,
      outfile: join(WWW, 'css', name),
      logLevel: 'info',
    });
  }

  // Images: already hand-optimized in NaluLF/images — just copy.
  cpSync(join(SRC, 'images'), join(WWW, 'images'), { recursive: true });

  // Standalone docs linked from the footer (./Whitepaper.html, ./Roadmap.html).
  for (const name of ['Whitepaper.html', 'Roadmap.html']) {
    cpSync(join(ROOT, name), join(WWW, name));
  }

  // Screenshots embedded in Whitepaper.html (real captures, not mockups) —
  // referenced with a path relative to Whitepaper.html itself, so the same
  // relative path resolves whether it's opened from the repo root or from
  // inside www/.
  cpSync(join(ROOT, 'whitepaper-assets'), join(WWW, 'whitepaper-assets'), { recursive: true });

  // manifest.json: icon paths are root-absolute (`/www/icons/...`), correct
  // when served from the repo root (dev/PWA) but wrong once www/ itself is
  // the site root (Capacitor) — rewrite to `/icons/...` for the www/ copy.
  const manifest = readFileSync(join(SRC, 'manifest.json'), 'utf8')
    .replaceAll('/www/icons/', '/icons/');
  writeFileSync(join(WWW, 'manifest.json'), manifest);

  // index.html: same rewrite idea — strip the `NaluLF/` prefix (www/ already
  // mirrors that folder's contents at its own root) and the `www/` prefix on
  // apple-touch-icons (self-referencing "www/" from inside www/ is wrong).
  let html = readFileSync(join(ROOT, 'index.html'), 'utf8');
  html = html
    .replaceAll('href="NaluLF/css/', 'href="css/')
    .replaceAll('src="NaluLF/scripts/', 'src="scripts/')
    .replaceAll('src="NaluLF/images/', 'src="images/')
    .replaceAll('href="NaluLF/images/', 'href="images/')
    .replaceAll('href="NaluLF/manifest.json"', 'href="manifest.json"')
    .replaceAll('href="www/icons/', 'href="icons/');
  writeFileSync(join(WWW, 'index.html'), html);

  const jsFiles = readdirSync(join(WWW, 'scripts'));
  console.log(`\nBuilt www/ — ${jsFiles.length} JS chunk(s), ${CSS_FILES.length} CSS file(s).`);
}

main().catch((err) => { console.error(err); process.exit(1); });
