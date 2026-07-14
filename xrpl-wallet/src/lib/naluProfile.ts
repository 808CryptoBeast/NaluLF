import { useEffect, useState } from 'react'

/**
 * Reads/writes the exact same localStorage contract NaluLF/scripts/profile.js
 * uses for identity data (`nalulf_profile`, `nalulf_social`,
 * `nalulf_avatar_img`, `nalulf_banner_img`) so editing a profile here is
 * indistinguishable from editing it in the legacy page.
 */
const LS_PROFILE = 'nalulf_profile'
const LS_SOCIAL = 'nalulf_social'
const LS_AVATAR_IMG = 'nalulf_avatar_img'
const LS_BANNER_IMG = 'nalulf_banner_img'
const PROFILE_CHANGED_EVENT = 'nalulf:profile-changed'

export const AVATARS = [
  '🌊', '🐋', '🐉', '🦋', '🦁', '🐺', '🦊', '🐻', '🐼', '🦅', '🐬', '🦈',
  '🐙', '🦑', '🧿', '🌺', '🌸', '🍀', '⚡', '🔥', '💎', '🌙', '⭐', '🎯', '🧠', '🔮', '🛸', '🗺', '🏔', '🎭', '🏛',
]

export const BANNERS = ['banner-ocean', 'banner-neon', 'banner-gold', 'banner-cosmic', 'banner-sunset', 'banner-aurora']

export const SOCIAL_PLATFORMS = [
  { id: 'discord', label: 'Discord', icon: '💬', prefix: 'https://discord.com/users/' },
  { id: 'twitter', label: 'X / Twitter', icon: '𝕏', prefix: 'https://x.com/' },
  { id: 'linkedin', label: 'LinkedIn', icon: 'in', prefix: 'https://linkedin.com/in/' },
  { id: 'github', label: 'GitHub', icon: '⌥', prefix: 'https://github.com/' },
  { id: 'telegram', label: 'Telegram', icon: '✈', prefix: 'https://t.me/' },
  { id: 'facebook', label: 'Facebook', icon: 'f', prefix: 'https://facebook.com/' },
  { id: 'tiktok', label: 'TikTok', icon: '♪', prefix: 'https://tiktok.com/@' },
] as const

export interface NaluProfile {
  displayName: string
  handle: string
  bio: string
  location: string
  website: string
  avatar: string
  banner: string
  joinedDate: string
  domain?: string
}

export type NaluSocial = Record<string, string>

const defaultProfile: NaluProfile = {
  displayName: '',
  handle: '',
  bio: '',
  location: '',
  website: '',
  avatar: '🌊',
  banner: 'banner-ocean',
  joinedDate: new Date().toISOString(),
}

function readProfile(): NaluProfile {
  try {
    const raw = localStorage.getItem(LS_PROFILE)
    return raw ? { ...defaultProfile, ...JSON.parse(raw) } : { ...defaultProfile }
  } catch {
    return { ...defaultProfile }
  }
}

function readSocial(): NaluSocial {
  try {
    const raw = localStorage.getItem(LS_SOCIAL)
    const parsed = raw ? JSON.parse(raw) : {}
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

function writeProfile(profile: NaluProfile) {
  localStorage.setItem(LS_PROFILE, JSON.stringify(profile))
  window.dispatchEvent(new CustomEvent(PROFILE_CHANGED_EVENT))
}

function writeSocial(social: NaluSocial) {
  localStorage.setItem(LS_SOCIAL, JSON.stringify(social))
  window.dispatchEvent(new CustomEvent(PROFILE_CHANGED_EVENT))
}

export function getAvatarImage(): string | null {
  return localStorage.getItem(LS_AVATAR_IMG)
}

export function getBannerImage(): string | null {
  return localStorage.getItem(LS_BANNER_IMG)
}

export function setAvatarImage(dataUrl: string) {
  localStorage.setItem(LS_AVATAR_IMG, dataUrl)
  window.dispatchEvent(new CustomEvent(PROFILE_CHANGED_EVENT))
}

export function clearAvatarImage() {
  localStorage.removeItem(LS_AVATAR_IMG)
  window.dispatchEvent(new CustomEvent(PROFILE_CHANGED_EVENT))
}

export function setBannerImage(dataUrl: string) {
  localStorage.setItem(LS_BANNER_IMG, dataUrl)
  window.dispatchEvent(new CustomEvent(PROFILE_CHANGED_EVENT))
}

export function clearBannerImage() {
  localStorage.removeItem(LS_BANNER_IMG)
  window.dispatchEvent(new CustomEvent(PROFILE_CHANGED_EVENT))
}

export function saveProfile(patch: Partial<NaluProfile>) {
  const next = { ...readProfile(), ...patch }
  writeProfile(next)
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

/** Same square-crop + JPEG re-encode profile.js's uploadAvatarImage() does. */
export async function cropAvatarImage(file: File): Promise<string> {
  if (file.size > 2 * 1024 * 1024) throw new Error('Image too large — max 2 MB')
  const img = await loadImage(await readFileAsDataUrl(file))
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = 200
  const ctx = canvas.getContext('2d')!
  const size = Math.min(img.width, img.height)
  ctx.drawImage(img, (img.width - size) / 2, (img.height - size) / 2, size, size, 0, 0, 200, 200)
  return canvas.toDataURL('image/jpeg', 0.85)
}

/** Same 900x180 letterboxed crop + JPEG re-encode profile.js's uploadBannerImage() does. */
export async function cropBannerImage(file: File): Promise<string> {
  if (file.size > 5 * 1024 * 1024) throw new Error('Image too large — max 5 MB')
  const img = await loadImage(await readFileAsDataUrl(file))
  const canvas = document.createElement('canvas')
  canvas.width = 900
  canvas.height = 180
  const ctx = canvas.getContext('2d')!
  const scale = Math.max(900 / img.width, 180 / img.height)
  ctx.drawImage(
    img,
    (900 - img.width * scale) / 2,
    (180 - img.height * scale) / 2,
    img.width * scale,
    img.height * scale,
  )
  return canvas.toDataURL('image/jpeg', 0.88)
}

export function saveSocialHandle(platformId: string, handle: string) {
  const social = readSocial()
  const trimmed = handle.trim().replace(/^@/, '')
  if (trimmed) social[platformId] = trimmed
  else delete social[platformId]
  writeSocial(social)
}

export function useNaluProfile() {
  const [profile, setProfile] = useState<NaluProfile>(() => readProfile())
  const [social, setSocial] = useState<NaluSocial>(() => readSocial())
  const [avatarImg, setAvatarImgState] = useState<string | null>(() => getAvatarImage())
  const [bannerImg, setBannerImgState] = useState<string | null>(() => getBannerImage())

  useEffect(() => {
    const sync = () => {
      setProfile(readProfile())
      setSocial(readSocial())
      setAvatarImgState(getAvatarImage())
      setBannerImgState(getBannerImage())
    }
    window.addEventListener(PROFILE_CHANGED_EVENT, sync)
    window.addEventListener('storage', sync)
    return () => {
      window.removeEventListener(PROFILE_CHANGED_EVENT, sync)
      window.removeEventListener('storage', sync)
    }
  }, [])

  return { profile, social, avatarImg, bannerImg }
}
