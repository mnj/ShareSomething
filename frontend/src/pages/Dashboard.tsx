import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, unwrap, type ShareSummary } from '../api/client'
import { CopyButton } from '../components/CopyButton'
import { EditShare } from '../components/EditShare'
import { ErrorNote } from '../components/ErrorNote'
import { describePolicy, formatRelative, formatTime, viewsLabel } from '../lib/format'

export function Dashboard() {
  const shares = useQuery({ queryKey: ['shares'], queryFn: () => unwrap(api.GET('/api/shares')), refetchInterval: 30_000 })
  const [filter, setFilter] = useState<'active' | 'all'>('active')
  const list = (shares.data ?? []).filter((s) => filter === 'all' || s.status === 'active')

  return (
    <div className="stack">
      <div className="row spread">
        <h1>Shares</h1>
        <Link to="/new" className="btn btn-primary">
          + New share
        </Link>
      </div>
      <div className="segmented small" role="radiogroup" aria-label="Filter">
        {(['active', 'all'] as const).map((f) => (
          <button key={f} type="button" role="radio" aria-checked={filter === f} className={filter === f ? 'active' : ''} onClick={() => setFilter(f)}>
            {f === 'active' ? 'Active' : 'All'}
          </button>
        ))}
      </div>
      <ErrorNote error={shares.error} />
      {shares.isPending && <p className="hint">Loading…</p>}
      {shares.data && list.length === 0 && <p className="hint">Nothing here yet.</p>}
      <ul className="share-list">
        {list.map((s) => (
          <ShareItem key={s.id} s={s} />
        ))}
      </ul>
    </div>
  )
}

function ShareItem({ s }: { s: ShareSummary }) {
  const qc = useQueryClient()
  const [showLog, setShowLog] = useState(false)
  const [editing, setEditing] = useState(false)
  const invalidate = () => qc.invalidateQueries({ queryKey: ['shares'] })
  const revoke = useMutation({
    mutationFn: () => unwrap(api.PATCH('/api/shares/{id}', { params: { path: { id: s.id } }, body: { revoke: true } })),
    onSuccess: invalidate,
  })
  const remove = useMutation({
    mutationFn: () => unwrap(api.DELETE('/api/shares/{id}', { params: { path: { id: s.id } } })),
    onSuccess: invalidate,
  })
  const active = s.status === 'active'
  const fragmentKey = s.enc_mode === 'e2e' && !s.passphrase_required

  return (
    <li className={`card share-item ${active ? '' : 'inactive'}`}>
      <div className="row spread wrap">
        <div className="share-title">
          <strong>{s.title || s.slug}</strong>
          <span className={`badge badge-${s.status}`}>{s.status}</span>
          <span className="badge">{s.kind}</span>
          <span className="badge">{s.enc_mode === 'e2e' ? 'E2E' : 'server'}</span>
          {s.passphrase_required && <span className="badge">passphrase</span>}
          {s.require_owner_mfa && <span className="badge">MFA</span>}
        </div>
        <div className="row">
          {active && (
            <CopyButton
              value={s.url}
              label={fragmentKey ? 'Copy link (no key)' : 'Copy link'}
            />
          )}
          {active && (
            <button type="button" className="btn btn-small btn-ghost" onClick={() => setEditing(!editing)}>
              Edit
            </button>
          )}
          <button type="button" className="btn btn-small btn-ghost" onClick={() => setShowLog(!showLog)}>
            Log
          </button>
          {active ? (
            <button type="button" className="btn btn-small btn-danger" onClick={() => confirm('Revoke this share? Its content is destroyed immediately.') && revoke.mutate()}>
              Revoke
            </button>
          ) : (
            <button type="button" className="btn btn-small btn-ghost" onClick={() => confirm('Delete this share and its log?') && remove.mutate()}>
              Delete
            </button>
          )}
        </div>
      </div>
      <p className="hint">
        <code>/s/{s.slug}</code> · {viewsLabel(s)} · {s.expires_at ? `expires ${formatRelative(s.expires_at)}` : 'no expiry'} · created {formatRelative(s.created_at)}
        {s.failed_attempts > 0 && ` · ${s.failed_attempts} wrong passphrase attempts`}
      </p>
      <p className="hint">Access: {describePolicy(s.policy)}</p>
      <ErrorNote error={revoke.error ?? remove.error} />
      {editing && active && <EditShare share={s} onDone={() => setEditing(false)} />}
      {showLog && <AccessLog id={s.id} />}
    </li>
  )
}

function AccessLog({ id }: { id: string }) {
  const log = useQuery({ queryKey: ['log', id], queryFn: () => unwrap(api.GET('/api/shares/{id}/log', { params: { path: { id } } })) })
  if (log.isPending) return <p className="hint">Loading…</p>
  if (log.error) return <ErrorNote error={log.error} />
  if (!log.data.length) return <p className="hint">No access attempts yet.</p>
  return (
    <table className="log">
      <thead>
        <tr>
          <th>When</th>
          <th>Outcome</th>
          <th>IP</th>
          <th>Who</th>
          <th>Client</th>
        </tr>
      </thead>
      <tbody>
        {log.data.map((e, i) => (
          <tr key={i}>
            <td>{formatTime(e.ts)}</td>
            <td>{e.outcome}</td>
            <td>
              {e.ip}
              {e.country ? ` (${e.country})` : ''}
            </td>
            <td>{e.identity ?? 'anonymous'}</td>
            <td className="ua">{e.user_agent}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
