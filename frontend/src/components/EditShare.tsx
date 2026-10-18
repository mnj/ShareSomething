import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, unwrap, type ShareSummary } from '../api/client'
import { accessFromPolicy, accessToPolicy } from '../lib/access'
import { formatTime } from '../lib/format'
import { AccessEditor } from './AccessEditor'
import { ErrorNote } from './ErrorNote'

const EXPIRY_CHOICES: { label: string; secs: number }[] = [
  { label: '1 hour from now', secs: 3600 },
  { label: '1 day from now', secs: 86400 },
  { label: '7 days from now', secs: 7 * 86400 },
  { label: '30 days from now', secs: 30 * 86400 },
]

/** Inline editor for an active share's title, limits and access. */
export function EditShare({ share, onDone }: { share: ShareSummary; onDone: () => void }) {
  const qc = useQueryClient()
  const [title, setTitle] = useState(share.title ?? '')
  const [expiry, setExpiry] = useState<string>('keep')
  const [maxViews, setMaxViews] = useState(String(share.max_views ?? 0))
  const [access, setAccess] = useState(() => accessFromPolicy(share.policy, share.require_owner_mfa))
  const [redirect, setRedirect] = useState(share.redirect_secs != null)
  const [redirectSecs, setRedirectSecs] = useState(share.redirect_secs ?? 5)
  const [requireApproval, setRequireApproval] = useState(share.require_approval)
  const [notifyOnOpen, setNotifyOnOpen] = useState(share.notify_on_open)

  const save = useMutation({
    mutationFn: () => {
      const expires_at = expiry === 'keep' ? undefined : expiry === 'never' ? 0 : Math.floor(Date.now() / 1000) + Number(expiry)
      return unwrap(
        api.PATCH('/api/shares/{id}', {
          params: { path: { id: share.id } },
          body: {
            title,
            expires_at,
            max_views: Number(maxViews) || 0,
            require_owner_mfa: access.requireMfa,
            redirect_secs: share.kind === 'link' ? (redirect ? redirectSecs : -1) : undefined,
            require_approval: requireApproval,
            notify_on_open: notifyOnOpen,
            policy: accessToPolicy(access),
          },
        }),
      )
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['shares'] })
      onDone()
    },
  })

  return (
    <form
      className="stack edit-share"
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate()
      }}
    >
      <div className="grid-2">
        <label className="field">
          Title
          <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
        </label>
        <label className="field">
          Expires
          <select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
            <option value="keep">{share.expires_at ? `Keep (${formatTime(share.expires_at)})` : 'Keep (never)'}</option>
            <option value="never">Never</option>
            {EXPIRY_CHOICES.map((c) => (
              <option key={c.secs} value={String(c.secs)}>
                {c.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          View limit <span className="hint">0 = unlimited; {share.views} used so far</span>
          <input type="number" min={0} max={10000} value={maxViews} onChange={(e) => setMaxViews(e.target.value)} />
        </label>
      </div>
      {share.kind === 'link' && (
        <label className="check">
          <input type="checkbox" checked={redirect} onChange={(e) => setRedirect(e.target.checked)} />
          Redirect automatically after
          <input
            type="number"
            className="inline-number"
            min={0}
            max={60}
            value={redirectSecs}
            onChange={(e) => setRedirectSecs(Math.max(0, Math.min(60, Number(e.target.value) || 0)))}
            aria-label="Redirect delay in seconds"
          />
          seconds
        </label>
      )}
      <label className="check">
        <input type="checkbox" checked={requireApproval} onChange={(e) => setRequireApproval(e.target.checked)} />
        Ask me to approve each open
      </label>
      <label className="check">
        <input type="checkbox" checked={notifyOnOpen} onChange={(e) => setNotifyOnOpen(e.target.checked)} />
        Notify me when it's opened
      </label>
      <AccessEditor value={access} onChange={setAccess} />
      <ErrorNote error={save.error} />
      <div className="row">
        <button className="btn btn-primary" disabled={save.isPending}>
          Save changes
        </button>
        <button type="button" className="btn btn-ghost" onClick={onDone}>
          Cancel
        </button>
      </div>
    </form>
  )
}
