import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, ApiError, unwrap } from '../api/client'
import { ErrorNote } from '../components/ErrorNote'
import { MfaPrompt } from '../components/MfaPrompt'
import { useMe } from '../lib/auth'
import { describePolicy, formatRelative } from '../lib/format'
import { createPasskey, passkeyError, webauthnSupported } from '../lib/webauthn'

export function Settings() {
  return (
    <div className="stack">
      <h1>Settings</h1>
      <Passkeys />
      <Templates />
    </div>
  )
}

function Passkeys() {
  const me = useMe()
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['passkeys'], queryFn: () => unwrap(api.GET('/api/auth/passkeys')) })
  const [name, setName] = useState('')
  const [needMfa, setNeedMfa] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['passkeys'] })
    qc.invalidateQueries({ queryKey: ['me'] })
  }
  // Credential changes need a fresh second factor; ask for it and let the user retry.
  const guard = async (fn: () => Promise<void>) => {
    setError(null)
    try {
      await fn()
    } catch (e) {
      if (e instanceof ApiError && e.code === 'need_owner_mfa') setNeedMfa(true)
      else setError(passkeyError(e))
    }
  }
  const add = useMutation({
    mutationFn: () =>
      guard(async () => {
        const start = await unwrap(api.POST('/api/auth/passkey/register/start', { body: { name } }))
        const credential = await createPasskey(start.options)
        await unwrap(api.POST('/api/auth/passkey/register/finish', { body: { ceremony_id: start.ceremony_id, credential } }))
        setName('')
        refresh()
      }),
  })
  const remove = (id: string) =>
    guard(async () => {
      await unwrap(api.DELETE('/api/auth/passkeys/{id}', { params: { path: { id } } }))
      refresh()
    })

  return (
    <section className="card stack">
      <h2>Passkeys</h2>
      <p className="hint">
        Sign in with your device's fingerprint, face or PIN instead of a password and code. A passkey also confirms "require my authenticator" shares.
        {me.data?.totp_enabled ? ' Authenticator app (TOTP) is enabled too.' : ' No authenticator app (TOTP) is set up.'}
      </p>
      {list.data && list.data.length > 0 && (
        <ul className="file-list">
          {list.data.map((p) => (
            <li key={p.id}>
              <span className="file-name">{p.name}</span>
              <span className="hint">
                added {formatRelative(p.created_at)}
                {p.last_used_at ? `, used ${formatRelative(p.last_used_at)}` : ', never used'}
              </span>
              <button type="button" className="btn btn-small btn-danger" onClick={() => confirm(`Remove passkey "${p.name}"?`) && remove(p.id)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {needMfa && (
        <div className="note">
          <MfaPrompt onDone={() => setNeedMfa(false)}>
            <p>Confirm it's you before changing passkeys, then try again.</p>
          </MfaPrompt>
        </div>
      )}
      {webauthnSupported() ? (
        <form
          className="row wrap"
          onSubmit={(e) => {
            e.preventDefault()
            add.mutate()
          }}
        >
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name, e.g. Laptop" aria-label="Passkey name" maxLength={64} required />
          <button className="btn btn-primary" disabled={add.isPending}>
            Add passkey
          </button>
        </form>
      ) : (
        <p className="note note-warn">This browser doesn't support passkeys (they also need https or localhost).</p>
      )}
      <ErrorNote error={error ?? list.error} />
    </section>
  )
}

function Templates() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['templates'], queryFn: () => unwrap(api.GET('/api/policy-templates')) })
  const remove = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE('/api/policy-templates/{id}', { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['templates'] }),
  })
  return (
    <section className="card stack">
      <h2>Saved access policies</h2>
      <p className="hint">Save rules from "Custom rules" when creating a share, then reuse them with one click. Changing or deleting a saved policy doesn't affect existing shares.</p>
      {list.data?.length === 0 && <p className="hint">None yet.</p>}
      {list.data && list.data.length > 0 && (
        <ul className="file-list">
          {list.data.map((t) => (
            <li key={t.id}>
              <span className="file-name">
                <b>{t.name}</b>
                <br />
                <span className="hint">{describePolicy(t.policy)}</span>
              </span>
              <button type="button" className="btn btn-small btn-ghost" onClick={() => confirm(`Delete "${t.name}"?`) && remove.mutate(t.id)}>
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
      <ErrorNote error={list.error ?? remove.error} />
    </section>
  )
}
