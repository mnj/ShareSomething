import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { api, unwrap, type Schemas } from '../api/client'
import { ErrorNote } from '../components/ErrorNote'
import { formatRelative, formatTime } from '../lib/format'

type Record = Schemas['Record']

const CATEGORIES: [string, string][] = [
  ['', 'All actions'],
  ['auth.', 'Sign-in & MFA'],
  ['share.', 'Shares'],
  ['recipient.', 'Recipient sign-in'],
  ['user.', 'Users'],
  ['template.', 'Saved policies'],
  ['audit.', 'Audit'],
  ['siem.', 'SIEM delivery'],
  ['system.', 'System'],
]

interface Filters {
  action: string
  outcome: string
  actor: string
  from: string
  to: string
}

const EMPTY: Filters = { action: '', outcome: '', actor: '', from: '', to: '' }

/** Date input (local day) -> unix seconds. */
const day = (v: string, end = false) => (v ? Math.floor(new Date(`${v}T00:00:00`).getTime() / 1000) + (end ? 86400 : 0) : undefined)

function toQuery(f: Filters) {
  return {
    action: f.action || undefined,
    outcome: f.outcome || undefined,
    actor: f.actor.trim() || undefined,
    from: day(f.from),
    to: day(f.to, true),
  }
}

export function Audit() {
  const [draft, setDraft] = useState<Filters>(EMPTY)
  const [filters, setFilters] = useState<Filters>(EMPTY)
  const query = toQuery(filters)
  const events = useInfiniteQuery({
    queryKey: ['audit', filters],
    queryFn: ({ pageParam }) => unwrap(api.GET('/api/audit', { params: { query: { ...query, limit: 100, before: pageParam } } })),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before ?? undefined,
  })
  const exportUrl = (format: 'csv' | 'jsonl') => {
    const p = new URLSearchParams({ format })
    for (const [k, v] of Object.entries(query)) if (v !== undefined) p.set(k, String(v))
    return `/api/audit/export?${p}`
  }
  const rows = events.data?.pages.flatMap((p) => p.events) ?? []

  return (
    <div className="stack">
      <div className="row spread wrap">
        <h1>Audit trail</h1>
        <div className="row">
          <a className="btn btn-small" href={exportUrl('csv')} download>
            Export CSV
          </a>
          <a className="btn btn-small" href={exportUrl('jsonl')} download>
            Export JSON lines
          </a>
        </div>
      </div>
      <ChainStatus />
      <Shippers />
      <form
        className="card audit-filters"
        onSubmit={(e) => {
          e.preventDefault()
          setFilters(draft)
        }}
      >
        <label className="field-inline">
          Category
          <select value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })}>
            {CATEGORIES.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <label className="field-inline">
          Outcome
          <select value={draft.outcome} onChange={(e) => setDraft({ ...draft, outcome: e.target.value })}>
            <option value="">Any</option>
            <option value="success">Success</option>
            <option value="denied">Denied</option>
            <option value="error">Error</option>
          </select>
        </label>
        <label className="field-inline grow">
          Actor
          <input value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} placeholder="email or user id" />
        </label>
        <label className="field-inline">
          From
          <input type="date" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
        </label>
        <label className="field-inline">
          To
          <input type="date" value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} />
        </label>
        <div className="row">
          <button className="btn btn-primary btn-small">Apply</button>
          <button
            type="button"
            className="btn btn-ghost btn-small"
            onClick={() => {
              setDraft(EMPTY)
              setFilters(EMPTY)
            }}
          >
            Reset
          </button>
        </div>
      </form>
      <ErrorNote error={events.error} />
      {events.isPending && <p className="hint">Loading…</p>}
      {events.data && rows.length === 0 && <p className="hint">No matching events.</p>}
      {rows.length > 0 && (
        <div className="card scroll-x">
          <table className="log audit-table">
            <thead>
              <tr>
                <th>#</th>
                <th>When</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Actor</th>
                <th>Source</th>
                <th>Target</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <AuditRow key={r.seq} r={r} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {events.hasNextPage && (
        <button type="button" className="btn" disabled={events.isFetchingNextPage} onClick={() => events.fetchNextPage()}>
          Load older events
        </button>
      )}
    </div>
  )
}

function AuditRow({ r }: { r: Record }) {
  const details = (() => {
    try {
      const d = JSON.parse(r.details) as { [k: string]: unknown }
      return Object.keys(d).length ? JSON.stringify(d) : ''
    } catch {
      return r.details
    }
  })()
  return (
    <tr>
      <td className="mono">{r.seq}</td>
      <td title={formatTime(r.ts)}>{formatRelative(r.ts)}</td>
      <td className="mono">{r.action}</td>
      <td>
        <span className={`badge badge-${r.outcome === 'success' ? 'ok' : r.outcome === 'denied' ? 'warn' : 'revoked'}`}>{r.outcome}</span>
      </td>
      <td>
        {r.actor_label ?? 'anonymous'}
        <span className="hint"> ({r.actor_type})</span>
      </td>
      <td title={r.user_agent ?? ''}>{r.ip ?? ''}</td>
      <td>{r.target_type ? `${r.target_type}: ${r.target_label ?? r.target_id}` : ''}</td>
      <td className="details" title={details}>
        {details}
      </td>
    </tr>
  )
}

function ChainStatus() {
  const v = useQuery({ queryKey: ['audit-verify'], queryFn: () => unwrap(api.GET('/api/audit/verify')) })
  if (!v.data) return null
  return v.data.ok ? (
    <p className="note">
      Hash chain intact: {v.data.checked} records verified
      {v.data.head_hash ? (
        <>
          , head <code>{v.data.head_hash.slice(0, 16)}…</code>
        </>
      ) : null}
      .
    </p>
  ) : (
    <p className="note note-error" role="alert">
      Audit chain broken at record #{v.data.first_bad_seq}: records were modified or deleted outside the application.
    </p>
  )
}

function Shippers() {
  const s = useQuery({ queryKey: ['audit-shippers'], queryFn: () => unwrap(api.GET('/api/audit/shippers')), refetchInterval: 15_000 })
  if (!s.data?.length) return <p className="hint">No SIEM shippers configured. See docs/audit.md to stream events to Splunk, Elastic, Sentinel, QRadar or syslog.</p>
  return (
    <div className="grid-2">
      {s.data.map((x) => (
        <div key={x.name} className="card stack shipper">
          <div className="row spread">
            <strong>{x.name}</strong>
            <span className={`badge ${x.failures ? 'badge-revoked' : x.behind > 0 ? 'badge-warn' : 'badge-ok'}`}>
              {x.failures ? `failing (${x.failures})` : x.behind > 0 ? `${x.behind} pending` : 'up to date'}
            </span>
          </div>
          <p className="hint">
            {x.kind} · delivered up to #{x.last_seq}
            {x.updated_at ? ` · ${formatRelative(x.updated_at)}` : ''}
          </p>
          {x.last_error && <p className="hint note-error">{x.last_error}</p>}
        </div>
      ))}
    </div>
  )
}
