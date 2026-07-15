import { useActivityLog } from '../lib/naluActivity'
import { type NaluProfile, type NaluSocial } from '../lib/naluProfile'
import { useWalletStore } from '../store/walletStore'
import { Card, SectionTitle, Stat } from './ui'

interface Props {
  profile: NaluProfile
  social: NaluSocial
  avatarImg: string | null
  onEditProfile: () => void
  onAddWallet?: () => void
}

/**
 * Mirrors profile.js's onboarding checklist (_renderOnboardingChecklist):
 * a short "complete your profile" nudge plus an at-a-glance stats row, so
 * the default (read-only) Profile view isn't just a name and an empty bio.
 */
export function ProfileCompleteness({ profile, social, avatarImg, onEditProfile, onAddWallet }: Props) {
  const walletCount = useWalletStore((s) => s.wallets.length)
  const activityLog = useActivityLog()
  const socialCount = Object.values(social).filter(Boolean).length

  const items = [
    {
      icon: '💎',
      title: 'Add a wallet',
      subtitle: 'Track XRPL balances and activity from your profile.',
      done: walletCount > 0,
      action: onAddWallet,
    },
    {
      icon: '✏️',
      title: 'Add a bio',
      subtitle: 'Tell people who you are.',
      done: Boolean(profile.bio),
      action: onEditProfile,
    },
    {
      icon: '🖼️',
      title: 'Customize your avatar',
      subtitle: 'Upload a photo or pick one that fits.',
      done: Boolean(avatarImg) || profile.avatar !== '🌊',
      action: onEditProfile,
    },
    {
      icon: '🔗',
      title: 'Connect a social account',
      subtitle: 'Link Discord, X, GitHub, or any platform.',
      done: socialCount > 0,
      action: onEditProfile,
    },
  ]

  const doneCount = items.filter((i) => i.done).length

  return (
    <>
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Wallets" value={String(walletCount)} />
        <Stat label="In-App Activity" value={String(activityLog.length)} />
        <Stat label="Social Links" value={String(socialCount)} />
      </div>

      {doneCount < items.length ? (
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <SectionTitle title="Complete Your Profile" />
            <span className="text-sm font-medium text-slate-400">
              {doneCount}/{items.length}
            </span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-[var(--profile-accent,var(--accent-primary,#0f766e))] transition-all"
              style={{ width: `${(doneCount / items.length) * 100}%` }}
            />
          </div>
          <div className="mt-4 space-y-2">
            {items
              .filter((i) => !i.done)
              .map((item) => (
                <button
                  key={item.title}
                  type="button"
                  onClick={item.action}
                  disabled={!item.action}
                  className="flex w-full items-center gap-3 rounded-xl border border-slate-700 bg-slate-800/60 p-3 text-left transition hover:border-teal-600 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <span className="text-xl">{item.icon}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium text-white">{item.title}</span>
                    <span className="block text-xs text-slate-400">{item.subtitle}</span>
                  </span>
                  <span className="text-slate-500">→</span>
                </button>
              ))}
          </div>
        </Card>
      ) : null}
    </>
  )
}
