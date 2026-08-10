/* =====================================================
   local-ai.js — Fully in-browser AI (WebLLM, no API key)
   =====================================================
   Alternative to ai.js's Claude-via-proxy path for anyone who doesn't want
   to get an Anthropic API key: this runs a small open-weight model entirely
   in the browser via WebGPU, using WebLLM (https://github.com/mlc-ai/web-llm).
   Genuinely zero server, zero key — the model is downloaded once (a few
   hundred MB to a couple GB depending on choice) and cached by the browser
   itself, then every generation after that runs 100% locally.

   Trade-offs vs. the Claude path (ai.js), stated plainly so the UI can be
   honest about them: noticeably lower answer quality than Claude on a
   reasoning-heavy task like this, first-run download is large, and it
   requires WebGPU (Chrome/Edge on desktop; not universally available yet —
   see isWebGpuSupported()).

   Model IDs and the CreateMLCEngine/chat.completions.create shapes below
   are taken directly from WebLLM's own source (src/config.ts) and examples,
   not guessed — see the exact strings in LOCAL_MODEL_OPTIONS.
   ===================================================== */

const WEBLLM_CDN_URL = 'https://esm.run/@mlc-ai/web-llm';

export const LOCAL_MODEL_OPTIONS = [
  { id: 'Llama-3.2-3B-Instruct-q4f16_1-MLC', label: 'Llama 3.2 3B — better quality, ~2.3GB download' },
  { id: 'Llama-3.2-1B-Instruct-q4f16_1-MLC', label: 'Llama 3.2 1B — faster/lighter, ~0.9GB download, weaker answers' },
];
export const LOCAL_DEFAULT_MODEL = LOCAL_MODEL_OPTIONS[0].id;

export function isWebGpuSupported() {
  return typeof navigator !== 'undefined' && !!navigator.gpu;
}

let _webllmModule = null;
let _engine = null;
let _engineModelId = null;

async function _getWebllm() {
  if (!_webllmModule) _webllmModule = await import(/* webpackIgnore: true */ WEBLLM_CDN_URL);
  return _webllmModule;
}

/** Loads (or reuses) the engine for the given model. Safe to call before
 *  every generation — it's a no-op if that model is already loaded, so
 *  callers don't need to track load state themselves. `onProgress` receives
 *  WebLLM's own InitProgressReport objects ({ text, progress, ... }). */
export async function ensureLocalModelLoaded(modelId = LOCAL_DEFAULT_MODEL, onProgress) {
  if (!isWebGpuSupported()) {
    throw new Error('Your browser doesn’t support WebGPU, which the local model needs. Try a recent Chrome or Edge on desktop.');
  }
  if (_engine && _engineModelId === modelId) return _engine;

  const webllm = await _getWebllm();
  if (_engine && _engineModelId !== modelId) {
    // Switch models: reload the existing engine rather than leaking a second one.
    await _engine.reload(modelId);
    _engineModelId = modelId;
    return _engine;
  }

  _engine = await webllm.CreateMLCEngine(modelId, {
    initProgressCallback: onProgress || (() => {}),
  });
  _engineModelId = modelId;
  return _engine;
}

/** Same shape as ai.js's askClaude(): one-shot prompt in, reply text out.
 *  `onProgress` (optional) surfaces model-download/load progress for the
 *  first call — later calls with the same model resolve immediately since
 *  the engine is already loaded. */
export async function askLocalModel(userText, { system, modelId = LOCAL_DEFAULT_MODEL, onProgress } = {}) {
  const engine = await ensureLocalModelLoaded(modelId, onProgress);

  const messages = [];
  if (system) messages.push({ role: 'system', content: system });
  messages.push({ role: 'user', content: userText });

  const reply = await engine.chat.completions.create({ messages });
  const text = reply?.choices?.[0]?.message?.content?.trim();
  if (!text) throw new Error('Local model returned an empty response.');
  return text;
}
