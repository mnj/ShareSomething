import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api, unwrap } from '../api/client'
import { ErrorNote } from '../components/ErrorNote'

/** Accept an invitation: choose a password and sign in. */
export function Invite() {
  const { token = '' } = useParams()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const info = useQuery({ queryKey: ['invite', token], queryFn: () => unwrap(api.GET('/api/invites/{token}', { params: { path: { token } } })), retry: false })
  const [name, setName] = useState<string | null>(null)
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  if (info.isPending) return <p className="hint">Loading…</p>
  if (info.error)
    return (
      <section className="card stack narrow">
        <h1>Invitation not valid</h1>
        <p>This invitation link has expired or was already used. Ask your admin for a new one.</p>
      </section>
    )
  return (
    <form
      className="card stack narrow"
      onSubmit={async (e) => {
        e.preventDefault()
        setError(null)
        if (password !== repeat) return setError(new Error("The passwords don't match."))
        setBusy(true)
        try {
          const me = await unwrap(api.POST('/api/invites/{token}/accept', { params: { path: { token } }, body: { password, name: name ?? info.data.name } }))
          qc.setQueryData(['me'], me)
          navigate(me.mfa_setup_required ? '/settings' : '/', { replace: true })
        } catch (err) {
          setError(err)
        } finally {
          setBusy(false)
        }
      }}
    >
      <h1>Welcome to ShareSomething</h1>
      <p>
        You've been invited as <b>{info.data.email}</b>. Choose a password to finish setting up your account.
      </p>
      <label className="field">
        Your name
        <input value={name ?? info.data.name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
      </label>
      <label className="field">
        Password <span className="hint">at least 12 characters</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={12} required />
      </label>
      <label className="field">
        Repeat password
        <input type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} autoComplete="new-password" minLength={12} required />
      </label>
      <ErrorNote error={error} />
      <button className="btn btn-primary" disabled={busy}>
        Create my account
      </button>
    </form>
  )
}
