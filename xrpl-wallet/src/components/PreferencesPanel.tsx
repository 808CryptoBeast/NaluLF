import {
  setAutoLockMinutes,
  setDefaultNetwork,
  setDisplayCurrency,
  usePreferences,
  type AutoLockMinutes,
  type DefaultNetwork,
  type DisplayCurrency,
} from '../lib/naluPreferences'
import { Button, Card, Label, SectionTitle } from './ui'

/** Same nalulf_pref_* keys NaluLF/scripts/profile.js's Settings tab uses. */
export function PreferencesPanel() {
  const { currency, network, autoLock } = usePreferences()

  return (
    <Card>
      <SectionTitle title="Preferences" subtitle="Display and network defaults, shared with the rest of Nalu LF." />

      <div className="space-y-5">
        <div>
          <Label>Display Currency</Label>
          <div className="flex gap-2">
            {(['XRP', 'USD'] as DisplayCurrency[]).map((value) => (
              <Button
                key={value}
                variant={currency === value ? 'primary' : 'secondary'}
                onClick={() => setDisplayCurrency(value)}
              >
                {value}
              </Button>
            ))}
          </div>
        </div>

        <div>
          <Label>Default Network for New Wallets</Label>
          <div className="flex gap-2">
            {([
              ['mainnet', '🟢 Mainnet'],
              ['testnet', '🟡 Testnet'],
            ] as [DefaultNetwork, string][]).map(([value, label]) => (
              <Button
                key={value}
                variant={network === value ? 'primary' : 'secondary'}
                onClick={() => setDefaultNetwork(value)}
              >
                {label}
              </Button>
            ))}
          </div>
        </div>

        <div>
          <Label>Auto-lock Signing Key After</Label>
          <div className="flex gap-2">
            {(['15', '30', '60'] as AutoLockMinutes[]).map((value) => (
              <Button
                key={value}
                variant={autoLock === value ? 'primary' : 'secondary'}
                onClick={() => setAutoLockMinutes(value)}
              >
                {value === '60' ? '1 hr' : `${value} min`}
              </Button>
            ))}
          </div>
        </div>
      </div>
    </Card>
  )
}
