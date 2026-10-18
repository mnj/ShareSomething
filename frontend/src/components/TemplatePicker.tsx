import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, unwrap, type PolicyRule } from '../api/client'
import { ErrorNote } from './ErrorNote'
import { useMe } from '../lib/auth'

/** Apply a saved access policy, or save the current custom rules under a name. */
export function TemplatePicker({ onApply, current }: { onApply: (p: PolicyRule[]) => void; current: (() => PolicyRule[]) | null }) {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['templates'], queryFn: () => unwrap(api.GET('/api/policy-templates')) })
  const [error, setError] = useState<unknown>(null)
  const [saved, setSaved] = useState<string | null>(null)
  const me = useMe()
  const canOrg = me.data?.mode === 'team' && me.data.user?.role === 'admin'

  const save = async (org: boolean) => {
    if (!current) return
    const name = prompt('Name for this access policy (an existing name is replaced):')?.trim()
    if (!name) return
    setError(null)
    try {
      await unwrap(api.POST('/api/policy-templates', { body: { name, policy: current(), org } }))
      qc.invalidateQueries({ queryKey: ['templates'] })
      setSaved(name)
    } catch (e) {
      setError(e)
    }
  }

  return (
    <div className="stack">
      <div className="row wrap">
        {!!list.data?.length && (
          <select
            aria-label="Saved policy"
            value=""
            onChange={(e) => {
              const t = list.data.find((x) => x.id === e.target.value)
              if (t) onApply(t.policy)
            }}
          >
            <option value="">Use a saved policy…</option>
            {list.data.map((t) => (
              <option key={t.id} value={t.id}>
                {t.org ? `${t.name} (organisation)` : t.name}
              </option>
            ))}
          </select>
        )}
        {current && (
          <button type="button" className="btn btn-small" onClick={() => save(false)}>
            Save rules as…
          </button>
        )}
        {current && canOrg && (
          <button type="button" className="btn btn-small btn-ghost" onClick={() => save(true)}>
            Save for everyone…
          </button>
        )}
        {saved && <span className="badge badge-ok">saved "{saved}"</span>}
      </div>
      <ErrorNote error={error} />
    </div>
  )
}
