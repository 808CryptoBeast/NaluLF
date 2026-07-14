import { useRef, useState } from 'react'
import { APP_THEMES, useAppTheme } from '../lib/naluTheme'
import {
  ACCENT_SWATCHES,
  BACKGROUND_PRESETS,
  clearProfileBackground,
  prepareBackgroundImage,
  setProfileAccent,
  setProfileBackgroundImage,
  setProfileBackgroundPreset,
  useProfileAppearance,
} from '../lib/naluAppearance'
import { Button, Card, Label, SectionTitle } from './ui'

/**
 * Two layers of customization: the app-wide theme (gold/cosmic/starry/
 * hawaiian — NaluLF/scripts/theme.js, applies everywhere via CSS variables
 * on <body>) and a profile-only accent color + background that override it
 * just for this page. Both are optional; leaving them unset just inherits
 * the app theme's own accent.
 */
export function AppearancePanel() {
  const { theme, setAppTheme } = useAppTheme()
  const { accent, bgPreset, bgImage } = useProfileAppearance()
  const bgInputRef = useRef<HTMLInputElement>(null)
  const [bgError, setBgError] = useState<string | null>(null)

  const onBgFile = async (file: File | null) => {
    if (!file) return
    setBgError(null)
    try {
      setProfileBackgroundImage(await prepareBackgroundImage(file))
    } catch (err) {
      setBgError(err instanceof Error ? err.message : 'Could not update background.')
    }
  }

  return (
    <Card>
      <SectionTitle title="Appearance" subtitle="Theme the whole app, or just personalize your own profile." />

      <div className="space-y-5">
        <div>
          <Label>App Theme</Label>
          <p className="mb-2 text-xs text-slate-400">Applies everywhere in Nalu LF, not just your profile.</p>
          <div className="flex flex-wrap gap-2">
            {APP_THEMES.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setAppTheme(t.id)}
                className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition ${
                  theme === t.id ? 'border-white bg-slate-800 text-white' : 'border-slate-700 bg-slate-800/60 text-slate-300'
                }`}
              >
                <span className="h-3.5 w-3.5 rounded-full" style={{ background: t.swatch }} />
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div>
          <Label>Your Profile Accent</Label>
          <p className="mb-2 text-xs text-slate-400">Overrides the app theme's accent color, only on this page.</p>
          <div className="flex flex-wrap gap-2">
            {ACCENT_SWATCHES.map((hex) => (
              <button
                key={hex}
                type="button"
                onClick={() => setProfileAccent(hex)}
                title={hex}
                style={{ background: hex }}
                className={`h-8 w-8 rounded-full border-2 ${accent === hex ? 'border-white' : 'border-transparent'}`}
              />
            ))}
            {accent ? (
              <Button variant="secondary" onClick={() => setProfileAccent(null)}>
                Use App Theme
              </Button>
            ) : null}
          </div>
        </div>

        <div>
          <Label>Your Profile Background</Label>
          <p className="mb-2 text-xs text-slate-400">A page background just for your profile — pick one or upload your own.</p>
          <div className="flex flex-wrap gap-2">
            {BACKGROUND_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => setProfileBackgroundPreset(preset.id)}
                title={preset.label}
                className={`h-10 w-16 rounded-lg border-2 ${preset.id} ${
                  !bgImage && bgPreset === preset.id ? 'border-white' : 'border-transparent'
                }`}
              />
            ))}
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button variant="secondary" onClick={() => bgInputRef.current?.click()}>
              Upload Background
            </Button>
            {bgImage || bgPreset ? (
              <Button variant="secondary" onClick={clearProfileBackground}>
                Reset to Default
              </Button>
            ) : null}
            <input
              ref={bgInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => onBgFile(e.target.files?.[0] ?? null)}
            />
          </div>
          {bgError ? <p className="mt-2 text-sm text-rose-400">{bgError}</p> : null}
        </div>
      </div>
    </Card>
  )
}
