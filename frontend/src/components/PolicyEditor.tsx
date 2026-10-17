import type { Schemas } from '../api/client'
import { useAuthMethods } from '../lib/recipient'
import type { RuleRow, RuleType } from '../lib/policy'

type RuleGroup = Schemas['RuleGroup']

const TYPES: { type: RuleType; label: string; placeholder?: string; hint?: string }[] = [
  { type: 'everyone', label: 'Everyone' },
  { type: 'owner', label: 'Me (owner)' },
  { type: 'ip', label: 'IP / network', placeholder: '203.0.113.0/24, 2001:db8::/32' },
  { type: 'country', label: 'Country', placeholder: 'DK, SE', hint: 'Needs Cloudflare in front (CF-IPCountry).' },
  { type: 'email', label: 'Emails', placeholder: 'alice@example.com, bob@example.org' },
  { type: 'email_domain', label: 'Email domain', placeholder: 'example.com' },
]

const GROUPS: { group: RuleGroup; label: string }[] = [
  { group: 'include', label: 'Allow if' },
  { group: 'require', label: 'Require' },
  { group: 'exclude', label: 'Block if' },
]

export function PolicyEditor({ rows, onChange }: { rows: RuleRow[]; onChange: (rows: RuleRow[]) => void }) {
  const methods = useAuthMethods()
  const update = (i: number, patch: Partial<RuleRow>) => onChange(rows.map((r, j) => (i === j ? { ...r, ...patch } : r)))
  return (
    <div className="policy-editor">
      {rows.map((row, i) => {
        const meta = TYPES.find((t) => t.type === row.type)!
        return (
          <div className="policy-row" key={i}>
            <select value={row.group} onChange={(e) => update(i, { group: e.target.value as RuleGroup })} aria-label="Rule group">
              {GROUPS.map((g) => (
                <option key={g.group} value={g.group}>
                  {g.label}
                </option>
              ))}
            </select>
            <select value={row.type} onChange={(e) => update(i, { type: e.target.value as RuleType, values: '' })} aria-label="Rule type">
              {TYPES.map((t) => (
                <option key={t.type} value={t.type}>
                  {t.label}
                </option>
              ))}
            </select>
            {meta.placeholder ? (
              <input value={row.values} placeholder={meta.placeholder} onChange={(e) => update(i, { values: e.target.value })} aria-label="Values" />
            ) : (
              <span className="policy-spacer" />
            )}
            <button type="button" className="btn btn-small btn-ghost" onClick={() => onChange(rows.filter((_, j) => j !== i))} aria-label="Remove rule">
              ✕
            </button>
            {(row.type === 'email' || row.type === 'email_domain') &&
              (methods.data?.length ? (
                <label className="policy-hint field-inline">
                  Verified with
                  <select value={row.method ?? ''} onChange={(e) => update(i, { method: e.target.value })}>
                    <option value="">any sign-in method</option>
                    {methods.data.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.label}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <p className="hint policy-hint note-error">No recipient sign-in is configured on the server (email codes or OIDC), so nobody could pass this rule.</p>
              ))}
            {meta.hint && <p className="hint policy-hint">{meta.hint}</p>}
          </div>
        )
      })}
      <button type="button" className="btn btn-small" onClick={() => onChange([...rows, { group: 'include', type: 'ip', values: '' }])}>
        + Add rule
      </button>
      <p className="hint">
        <b>Allow if</b>: any one must match. <b>Require</b>: all must match. <b>Block if</b>: any match denies access.
      </p>
    </div>
  )
}
