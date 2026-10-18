import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, ApiError, unwrap } from '../api/client'
import { formatRelative } from '../lib/format'
import { ErrorNote } from './ErrorNote'
import { MfaPrompt } from './MfaPrompt'

/** Pending "may I open this?" requests for the owner's shares. */
export function PendingApprovals() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['approvals'], queryFn: () => unwrap(api.GET('/api/approvals')), refetchInterval: 5000 })
  const [needMfa, setNeedMfa] = useState<{ id: string; approve: boolean } | null>(null)
  const decide = useMutation({
    mutationFn: ({ id, approve }: { id: string; approve: boolean }) =>
      unwrap(api.POST('/api/approvals/{id}/decide', { params: { path: { id } }, body: { approve } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['approvals'] })
      qc.invalidateQueries({ queryKey: ['notifications'] })
    },
    onError: (e, vars) => {
      if (e instanceof ApiError && e.code === 'need_owner_mfa') setNeedMfa(vars)
    },
  })
  if (!list.data?.length) return null
  return (
    <section className="card stack approvals" aria-label="Pending approvals">
      <h2>Waiting for your approval</h2>
      {list.data.map((a) => (
        <div key={a.id} className="row spread wrap approval">
          <div>
            <b>{a.requester_label ?? 'Someone'}</b> wants to open <b>{a.share_label}</b>
            <p className="hint">
              from {a.ip}
              {a.country ? ` (${a.country})` : ''} · {formatRelative(a.created_at)} · expires {formatRelative(a.expires_at)}
            </p>
          </div>
          <div className="row">
            <button type="button" className="btn btn-small btn-primary" disabled={decide.isPending} onClick={() => decide.mutate({ id: a.id, approve: true })}>
              Approve
            </button>
            <button type="button" className="btn btn-small btn-danger" disabled={decide.isPending} onClick={() => decide.mutate({ id: a.id, approve: false })}>
              Deny
            </button>
          </div>
        </div>
      ))}
      {needMfa && (
        <div className="note">
          <MfaPrompt
            onDone={() => {
              const v = needMfa
              setNeedMfa(null)
              decide.mutate(v)
            }}
          >
            <p>Confirm it's you to decide.</p>
          </MfaPrompt>
        </div>
      )}
      {!(decide.error instanceof ApiError && decide.error.code === 'need_owner_mfa') && <ErrorNote error={decide.error} />}
    </section>
  )
}

/** Latest notifications with "mark all read". */
export function Notifications() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['notifications'], queryFn: () => unwrap(api.GET('/api/notifications')), refetchInterval: 15_000 })
  const read = useMutation({
    mutationFn: () => unwrap(api.POST('/api/notifications/read')),
    onSuccess: (d) => qc.setQueryData(['notifications'], d),
  })
  const items = list.data?.items.slice(0, 8) ?? []
  if (!items.length) return null
  return (
    <details className="card notifications" open={!!list.data?.unread}>
      <summary>
        Notifications {list.data?.unread ? <span className="badge badge-warn">{list.data.unread} new</span> : null}
      </summary>
      <ul className="file-list">
        {items.map((n) => (
          <li key={n.id} className={n.read ? 'hint' : ''}>
            <span className="file-name">{n.message}</span>
            <span className="hint">{formatRelative(n.ts)}</span>
          </li>
        ))}
      </ul>
      {!!list.data?.unread && (
        <button type="button" className="btn btn-small btn-ghost" onClick={() => read.mutate()}>
          Mark all read
        </button>
      )}
    </details>
  )
}
