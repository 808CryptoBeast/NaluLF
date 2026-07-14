import { useEffect, useState } from 'react'

/**
 * Profile-only personalization layered ON TOP of the app-wide theme (see
 * naluTheme.ts) — a custom accent color and page background just for this
 * user's Profile page. New, additive localStorage keys (not part of
 * profile.js's contract, so no risk of colliding with it).
 */
const LS_ACCENT = 'nalulf_profile_accent'
const LS_BG_PRESET = 'nalulf_profile_bg_preset'
const LS_BG_IMG = 'nalulf_profile_bg_img'
const APPEARANCE_CHANGED_EVENT = 'nalulf:appearance-changed'

export const ACCENT_SWATCHES = [
  '#0f766e', // teal (default)
  '#7c3aed', // violet
  '#d4af37', // gold
  '#e11d48', // rose
  '#2563eb', // blue
  '#16a34a', // green
  '#ea580c', // orange
  '#0891b2', // cyan
]

// Same 6 gradients as the profile banner presets, reused here as full-page
// background options for visual consistency across the app.
export const BACKGROUND_PRESETS = [
  { id: 'banner-ocean', label: 'Ocean' },
  { id: 'banner-neon', label: 'Neon' },
  { id: 'banner-gold', label: 'Gold' },
  { id: 'banner-cosmic', label: 'Cosmic' },
  { id: 'banner-sunset', label: 'Sunset' },
  { id: 'banner-aurora', label: 'Aurora' },
] as const

function readAccent(): string | null {
  return localStorage.getItem(LS_ACCENT)
}

function readBgPreset(): string | null {
  return localStorage.getItem(LS_BG_PRESET)
}

function readBgImage(): string | null {
  return localStorage.getItem(LS_BG_IMG)
}

function notifyChanged() {
  window.dispatchEvent(new CustomEvent(APPEARANCE_CHANGED_EVENT))
}

export function setProfileAccent(hex: string | null) {
  if (hex) localStorage.setItem(LS_ACCENT, hex)
  else localStorage.removeItem(LS_ACCENT)
  notifyChanged()
}

export function setProfileBackgroundPreset(id: string | null) {
  if (id) localStorage.setItem(LS_BG_PRESET, id)
  else localStorage.removeItem(LS_BG_PRESET)
  localStorage.removeItem(LS_BG_IMG)
  notifyChanged()
}

export function setProfileBackgroundImage(dataUrl: string) {
  localStorage.setItem(LS_BG_IMG, dataUrl)
  localStorage.removeItem(LS_BG_PRESET)
  notifyChanged()
}

export function clearProfileBackground() {
  localStorage.removeItem(LS_BG_PRESET)
  localStorage.removeItem(LS_BG_IMG)
  notifyChanged()
}

function loadImage(dataUrl: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.onload = () => resolve(img)
    img.onerror = () => reject(new Error('Could not read that image file.'))
    img.src = dataUrl
  })
}

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = (e) => resolve(e.target?.result as string)
    reader.onerror = () => reject(new Error('Could not read that image file.'))
    reader.readAsDataURL(file)
  })
}

/** Downscales to a reasonable page-background size before storing as a data URL. */
export async function prepareBackgroundImage(file: File): Promise<string> {
  if (file.size > 6 * 1024 * 1024) throw new Error('Image too large — max 6 MB')
  const img = await loadImage(await readFileAsDataUrl(file))
  const canvas = document.createElement('canvas')
  const maxWidth = 1600
  const scale = Math.min(1, maxWidth / img.width)
  canvas.width = Math.round(img.width * scale)
  canvas.height = Math.round(img.height * scale)
  const ctx = canvas.getContext('2d')!
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
  return canvas.toDataURL('image/jpeg', 0.85)
}

export function useProfileAppearance() {
  const [accent, setAccent] = useState<string | null>(() => readAccent())
  const [bgPreset, setBgPreset] = useState<string | null>(() => readBgPreset())
  const [bgImage, setBgImage] = useState<string | null>(() => readBgImage())

  useEffect(() => {
    const sync = () => {
      setAccent(readAccent())
      setBgPreset(readBgPreset())
      setBgImage(readBgImage())
    }
    window.addEventListener(APPEARANCE_CHANGED_EVENT, sync)
    window.addEventListener('storage', sync)
    return () => {
      window.removeEventListener(APPEARANCE_CHANGED_EVENT, sync)
      window.removeEventListener('storage', sync)
    }
  }, [])

  return { accent, bgPreset, bgImage }
}
