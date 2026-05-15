const encoder = new TextEncoder()
const decoder = new TextDecoder()

async function deriveKey(passphrase: string, salt: Uint8Array) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey'],
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 210000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

function toBase64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
}

function fromBase64(data: string): Uint8Array {
  return Uint8Array.from(atob(data), (c) => c.charCodeAt(0))
}

export async function encryptSeed(seed: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(passphrase, salt)

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    encoder.encode(seed),
  )

  const payload = {
    v: 1,
    s: toBase64(salt),
    i: toBase64(iv),
    c: toBase64(new Uint8Array(encrypted)),
  }

  return JSON.stringify(payload)
}

export async function decryptSeed(payload: string, passphrase: string): Promise<string> {
  const parsed = JSON.parse(payload) as { s: string; i: string; c: string }
  const salt = fromBase64(parsed.s)
  const iv = fromBase64(parsed.i)
  const cipher = fromBase64(parsed.c)

  const key = await deriveKey(passphrase, salt)
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    cipher as BufferSource,
  )

  return decoder.decode(decrypted)
}
