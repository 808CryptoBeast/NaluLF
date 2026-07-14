import { useNaluSession } from '../lib/naluSession'
import { Button, Card } from './ui'

const PIKOVERSE_URL = 'https://pikoverse.xyz'

function PikoverseLink() {
  return (
    <a
      href={PIKOVERSE_URL}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs font-medium text-slate-300 transition hover:border-teal-700 hover:text-teal-300"
    >
      🌐 Part of the Pikoverse ecosystem
    </a>
  )
}

/**
 * Makes it visually obvious this is a personal Profile page, not a bare
 * wallet creator — wallets are one optional feature *within* the profile,
 * not the gate to it. Sign-in itself stays on NaluLF's existing vanilla-JS
 * auth.js vault (see lib/naluSession.ts); this just reflects its state.
 * The Pikoverse link is a placeholder pointer to the sibling ecosystem site
 * (c:\Users\dkaua\AMP\pikoverse, deployed at pikoverse.xyz per its CNAME) —
 * no shared auth/data with it yet, that's a separate cross-repo project.
 */
export function ProfileIdentityBar() {
  const session = useNaluSession()

  if (session) {
    return (
      <Card className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-full bg-[var(--profile-accent,var(--accent-primary,#0f766e))] text-lg font-semibold text-white">
            {session.name.trim().charAt(0).toUpperCase() || '🌊'}
          </div>
          <div>
            <p className="text-sm font-semibold text-white">{session.name}</p>
            <p className="text-xs text-slate-400">
              {session.domain ? `@${session.domain}` : session.email}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <PikoverseLink />
          <span className="rounded-full border border-teal-800 bg-teal-950 px-3 py-1 text-xs font-medium text-teal-300">
            Signed in
          </span>
        </div>
      </Card>
    )
  }

  return (
    <Card className="mb-5 flex flex-wrap items-center justify-between gap-3">
      <div>
        <p className="text-sm font-semibold text-white">Browsing as a guest</p>
        <p className="text-xs text-slate-400">
          Sign in to save this profile, its wallets, and activity across devices.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <PikoverseLink />
        <Button variant="secondary" onClick={() => window.openAuth?.('login')}>
          Sign In
        </Button>
        <Button onClick={() => window.openAuth?.('signup')}>Create Account</Button>
      </div>
    </Card>
  )
}
