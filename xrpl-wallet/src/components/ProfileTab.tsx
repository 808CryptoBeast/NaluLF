import { useEffect, useRef, useState } from 'react'
import { useNaluSession } from '../lib/naluSession'
import {
  AVATARS,
  BANNERS,
  SOCIAL_PLATFORMS,
  clearAvatarImage,
  clearBannerImage,
  cropAvatarImage,
  cropBannerImage,
  saveProfile,
  saveSocialHandle,
  setAvatarImage,
  setBannerImage,
  useNaluProfile,
} from '../lib/naluProfile'
import { logActivity } from '../lib/naluActivity'
import { AppearancePanel } from './AppearancePanel'
import { PreferencesPanel } from './PreferencesPanel'
import { ProfileCompleteness } from './ProfileCompleteness'
import { Button, Card, Input, Label, SectionTitle } from './ui'

/**
 * Mirrors profile.js's profile editor + social tab, reading/writing the same
 * nalulf_profile / nalulf_social / nalulf_avatar_img / nalulf_banner_img
 * localStorage keys so identity edits made here or in the legacy page are the
 * same data, not two divergent copies.
 *
 * Everything editable (avatar/banner picker, name/bio/location/website form,
 * appearance controls, social connect/edit) is hidden by default — a single
 * "Edit Profile" toggle reveals all of it at once, so the default view reads
 * like an actual profile page rather than a settings form.
 */
export function ProfileTab({ onAddWallet }: { onAddWallet?: () => void }) {
  const session = useNaluSession()
  const { profile, social, avatarImg, bannerImg } = useNaluProfile()

  // Match profile.js's loadData(): default displayName/handle from the
  // signed-in session the first time one becomes available.
  useEffect(() => {
    if (!profile.displayName && session?.name) {
      saveProfile({
        displayName: session.name,
        handle: session.name.toLowerCase().replace(/\s+/g, '_'),
      })
    }
  }, [session, profile.displayName])

  const [editMode, setEditMode] = useState(false)
  const [form, setForm] = useState({
    displayName: profile.displayName,
    handle: profile.handle,
    bio: profile.bio,
    location: profile.location,
    website: profile.website,
  })

  useEffect(() => {
    if (!editMode) {
      setForm({
        displayName: profile.displayName,
        handle: profile.handle,
        bio: profile.bio,
        location: profile.location,
        website: profile.website,
      })
    }
  }, [editMode, profile])

  const avatarInputRef = useRef<HTMLInputElement>(null)
  const bannerInputRef = useRef<HTMLInputElement>(null)
  const [imageError, setImageError] = useState<string | null>(null)

  const saveEdits = () => {
    saveProfile({
      displayName: form.displayName.trim() || profile.displayName,
      handle: (form.handle.trim() || profile.handle).replace(/^@/, '').replace(/\s+/g, '_').toLowerCase(),
      bio: form.bio.trim(),
      location: form.location.trim(),
      website: form.website.trim(),
    })
    logActivity('profile_saved', 'Profile details updated')
    setEditMode(false)
  }

  const onAvatarFile = async (file: File | null) => {
    if (!file) return
    setImageError(null)
    try {
      setAvatarImage(await cropAvatarImage(file))
    } catch (err) {
      setImageError(err instanceof Error ? err.message : 'Could not update avatar.')
    }
  }

  const onBannerFile = async (file: File | null) => {
    if (!file) return
    setImageError(null)
    try {
      setBannerImage(await cropBannerImage(file))
    } catch (err) {
      setImageError(err instanceof Error ? err.message : 'Could not update banner.')
    }
  }

  const connectedPlatforms = SOCIAL_PLATFORMS.filter((p) => social[p.id])

  return (
    <div className="space-y-5">
      <Card className="overflow-hidden !p-0">
        <div
          className={`h-40 w-full sm:h-48 ${bannerImg ? '' : profile.banner || 'banner-ocean'}`}
          style={bannerImg ? { backgroundImage: `url(${bannerImg})`, backgroundSize: 'cover', backgroundPosition: 'center' } : undefined}
        />
        <div className="px-6 pb-6">
          <div className="-mt-14 flex items-end justify-between gap-3">
            {editMode ? (
              <button
                type="button"
                onClick={() => avatarInputRef.current?.click()}
                className="flex h-28 w-28 items-center justify-center overflow-hidden rounded-full border-4 border-slate-900 bg-slate-800 text-4xl shadow-lg"
                title="Upload a new photo"
              >
                {avatarImg ? (
                  <img src={avatarImg} alt="Profile avatar" className="h-full w-full object-cover" />
                ) : (
                  profile.avatar || '🌊'
                )}
              </button>
            ) : (
              <div className="flex h-28 w-28 items-center justify-center overflow-hidden rounded-full border-4 border-slate-900 bg-slate-800 text-4xl shadow-lg">
                {avatarImg ? (
                  <img src={avatarImg} alt="Profile avatar" className="h-full w-full object-cover" />
                ) : (
                  profile.avatar || '🌊'
                )}
              </div>
            )}
            <Button variant="secondary" onClick={() => setEditMode((v) => !v)}>
              {editMode ? 'Cancel' : 'Edit Profile'}
            </Button>
          </div>

          <h2 className="mt-3 text-2xl font-semibold text-white">{profile.displayName || 'Anonymous'}</h2>
          {profile.handle ? <p className="text-sm text-slate-400">@{profile.handle}</p> : null}

          {!editMode ? (
            <>
              <p className="mt-2 text-sm text-slate-300">
                {profile.bio || 'No bio set. Click Edit Profile to add one.'}
              </p>
              <div className="mt-2 flex flex-wrap gap-3 text-xs text-slate-400">
                {profile.location ? <span>📍 {profile.location}</span> : null}
                {profile.website ? (
                  <a href={profile.website} target="_blank" rel="noreferrer" className="text-teal-400 hover:underline">
                    🔗 {profile.website}
                  </a>
                ) : null}
              </div>
              {connectedPlatforms.length ? (
                <div className="mt-3 flex flex-wrap gap-2">
                  {connectedPlatforms.map((p) => (
                    <a
                      key={p.id}
                      href={`${p.prefix}${social[p.id]}`}
                      target="_blank"
                      rel="noreferrer"
                      title={`${p.label} · @${social[p.id]}`}
                      className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-700 bg-slate-800/70 text-sm text-slate-300 hover:border-teal-600 hover:text-teal-300"
                    >
                      {p.icon}
                    </a>
                  ))}
                </div>
              ) : null}
            </>
          ) : null}

          {editMode ? (
            <div className="mt-4 space-y-4 rounded-xl border border-slate-700 bg-slate-800/60 p-4">
              <div>
                <Label>Avatar</Label>
                <div className="flex flex-wrap gap-2">
                  {AVATARS.slice(0, 16).map((a) => (
                    <button
                      key={a}
                      type="button"
                      onClick={() => {
                        clearAvatarImage()
                        saveProfile({ avatar: a })
                      }}
                      className={`h-9 w-9 rounded-lg border text-lg ${
                        !avatarImg && profile.avatar === a ? 'border-teal-600 bg-teal-950' : 'border-slate-700 bg-slate-800'
                      }`}
                    >
                      {a}
                    </button>
                  ))}
                </div>
                <div className="mt-2 flex gap-2">
                  <Button variant="secondary" onClick={() => avatarInputRef.current?.click()}>
                    Upload Photo
                  </Button>
                  {avatarImg ? (
                    <Button variant="secondary" onClick={clearAvatarImage}>
                      Remove Photo
                    </Button>
                  ) : null}
                  <input
                    ref={avatarInputRef}
                    type="file"
                    accept="image/*"
                    className="hidden"
                    onChange={(e) => onAvatarFile(e.target.files?.[0] ?? null)}
                  />
                </div>
              </div>

              <div>
                <Label>Banner</Label>
                <div className="flex flex-wrap gap-2">
                  {BANNERS.map((b) => (
                    <button
                      key={b}
                      type="button"
                      onClick={() => {
                        clearBannerImage()
                        saveProfile({ banner: b })
                      }}
                      className={`h-8 w-14 rounded-lg border-2 ${b} ${
                        !bannerImg && profile.banner === b ? 'border-white' : 'border-transparent'
                      }`}
                    />
                  ))}
                </div>
                <div className="mt-2 flex gap-2">
                  <Button variant="secondary" onClick={() => bannerInputRef.current?.click()}>
                    Upload Banner
                  </Button>
                  {bannerImg ? (
                    <Button variant="secondary" onClick={clearBannerImage}>
                      Remove Banner
                    </Button>
                  ) : null}
                  <input
                    ref={bannerInputRef}
                    type="file"
                    accept="image/*"
                    className="hidden"
                    onChange={(e) => onBannerFile(e.target.files?.[0] ?? null)}
                  />
                </div>
              </div>
              {imageError ? <p className="text-sm text-rose-400">{imageError}</p> : null}

              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <Label>Display Name</Label>
                  <Input value={form.displayName} onChange={(e) => setForm((f) => ({ ...f, displayName: e.target.value }))} />
                </div>
                <div>
                  <Label>Handle</Label>
                  <Input value={form.handle} onChange={(e) => setForm((f) => ({ ...f, handle: e.target.value }))} />
                </div>
                <div className="sm:col-span-2">
                  <Label>Bio</Label>
                  <Input value={form.bio} onChange={(e) => setForm((f) => ({ ...f, bio: e.target.value }))} />
                </div>
                <div>
                  <Label>Location</Label>
                  <Input value={form.location} onChange={(e) => setForm((f) => ({ ...f, location: e.target.value }))} />
                </div>
                <div>
                  <Label>Website</Label>
                  <Input value={form.website} onChange={(e) => setForm((f) => ({ ...f, website: e.target.value }))} />
                </div>
                <div className="sm:col-span-2">
                  <Button onClick={saveEdits}>Save Profile</Button>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </Card>

      {!editMode ? (
        <ProfileCompleteness
          profile={profile}
          social={social}
          avatarImg={avatarImg}
          onEditProfile={() => setEditMode(true)}
          onAddWallet={onAddWallet}
        />
      ) : null}

      {editMode ? <AppearancePanel /> : null}
      {editMode ? <PreferencesPanel /> : null}

      {editMode || connectedPlatforms.length ? (
        <Card>
          <SectionTitle
            title="Social & Community Links"
            subtitle={
              editMode
                ? `${connectedPlatforms.length} of ${SOCIAL_PLATFORMS.length} connected · stored locally only`
                : undefined
            }
          />
          {editMode ? (
            <div className="grid gap-3 sm:grid-cols-2">
              {SOCIAL_PLATFORMS.map((p) => (
                <SocialRow key={p.id} platform={p} handle={social[p.id] || ''} />
              ))}
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {connectedPlatforms.map((p) => (
                <a
                  key={p.id}
                  href={`${p.prefix}${social[p.id]}`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/60 px-3 py-2 text-sm text-slate-200 hover:border-teal-600"
                >
                  <span>{p.icon}</span>
                  {p.label}
                </a>
              ))}
            </div>
          )}
        </Card>
      ) : null}
    </div>
  )
}

function SocialRow({
  platform,
  handle,
}: {
  platform: (typeof SOCIAL_PLATFORMS)[number]
  handle: string
}) {
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(handle)
  const connected = Boolean(handle)

  useEffect(() => {
    setValue(handle)
  }, [handle])

  const save = () => {
    saveSocialHandle(platform.id, value)
    logActivity(value.trim() ? 'social_connected' : 'social_removed', `${platform.label} @${value.trim() || '(removed)'}`)
    setEditing(false)
  }

  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-700 bg-slate-800/60 p-3">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-900 text-sm text-slate-200">
          {platform.icon}
        </div>
        <div>
          <p className="text-sm font-medium text-white">{platform.label}</p>
          {editing ? (
            <input
              autoFocus
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={`Your ${platform.label} handle`}
              className="mt-1 w-40 rounded-lg border border-slate-600 bg-slate-900 px-2 py-1 text-xs text-white outline-none focus:border-teal-600"
            />
          ) : (
            <p className={`text-xs ${connected ? 'text-slate-400' : 'text-slate-500'}`}>
              {connected ? `@${handle}` : 'Not connected'}
            </p>
          )}
        </div>
      </div>
      <div className="flex gap-1.5">
        {editing ? (
          <Button variant="secondary" onClick={save}>
            Save
          </Button>
        ) : (
          <>
            {connected ? (
              <a
                href={`${platform.prefix}${handle}`}
                target="_blank"
                rel="noreferrer"
                className="rounded-lg border border-slate-600 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700"
              >
                ↗
              </a>
            ) : null}
            <Button variant="secondary" onClick={() => setEditing(true)}>
              {connected ? 'Edit' : '+ Connect'}
            </Button>
          </>
        )}
      </div>
    </div>
  )
}
