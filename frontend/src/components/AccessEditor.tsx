import type { AccessState } from '../lib/access'
import { useMe } from '../lib/auth'
import { policyToRows, rowsToPolicy } from '../lib/policy'
import { PolicyEditor } from './PolicyEditor'
import { TemplatePicker } from './TemplatePicker'

const PRESETS = [
  ['public', 'Anyone with the link'],
  ['owner', 'Only me'],
  ['custom', 'Custom rules'],
] as const

export function AccessEditor({ value, onChange }: { value: AccessState; onChange: (v: AccessState) => void }) {
  const me = useMe()
  const hasMfa = !!(me.data?.totp_enabled || me.data?.passkeys)
  return (
    <div className="stack">
      <div className="segmented" role="radiogroup" aria-label="Access">
        {PRESETS.map(([p, label]) => (
          <button
            key={p}
            type="button"
            role="radio"
            aria-checked={value.preset === p}
            className={value.preset === p ? 'active' : ''}
            onClick={() => onChange({ ...value, preset: p })}
          >
            {label}
          </button>
        ))}
      </div>
      <TemplatePicker
        onApply={(p) => onChange({ ...value, preset: 'custom', rules: policyToRows(p) })}
        current={value.preset === 'custom' ? () => rowsToPolicy(value.rules) : null}
      />
      {value.preset === 'custom' && <PolicyEditor rows={value.rules} onChange={(rules) => onChange({ ...value, rules })} />}
      <label className="check">
        <input type="checkbox" checked={value.requireMfa} disabled={!hasMfa && !value.requireMfa} onChange={(e) => onChange({ ...value, requireMfa: e.target.checked })} />
        Also require my authenticator code or passkey (owner sign-in + fresh MFA){!hasMfa && ' (set up TOTP or a passkey first)'}
      </label>
    </div>
  )
}
