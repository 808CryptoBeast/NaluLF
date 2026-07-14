import type { EncryptedSeedBlob } from '../types/wallet'

/**
 * Must stay byte-compatible with NaluLF/scripts/profile.js's
 * _encryptSeed/_decryptSeed/_deriveWalletKey (same PBKDF2-SHA256 210k-iteration
 * derivation, same AES-GCM-256 cipher, same field names/shapes) — a wallet
 * created by either the legacy vanilla-JS page or this React app must be
 * decryptable by the other.
 */

const WALLET_KDF_ITERATIONS = 210_000
const encoder = new TextEncoder()
const decoder = new TextDecoder()

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function fromBase64(b64: string): Uint8Array {
  const raw = atob(b64)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i)
  return out
}

async function deriveWalletKey(passphrase: string, salt: Uint8Array, iterations = WALLET_KDF_ITERATIONS) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function encryptSeed(seed: string, passphrase: string): Promise<EncryptedSeedBlob> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveWalletKey(passphrase, salt)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, encoder.encode(seed))
  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iter: WALLET_KDF_ITERATIONS,
    alg: 'AES-GCM-256',
    salt: toBase64(salt),
    iv: toBase64(iv),
    ct: toBase64(new Uint8Array(ct)),
  }
}

export async function decryptSeed(blob: EncryptedSeedBlob, passphrase: string): Promise<string> {
  if (!blob?.ct || !blob?.salt || !blob?.iv) throw new Error('Wallet seed blob is invalid.')
  const salt = fromBase64(blob.salt)
  const iv = fromBase64(blob.iv)
  const key = await deriveWalletKey(passphrase, salt, blob.iter || WALLET_KDF_ITERATIONS)
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, fromBase64(blob.ct) as BufferSource)
  return decoder.decode(pt)
}
