import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, ApiError, unwrap } from '../api/client'
import { ErrorNote } from '../components/ErrorNote'
import { useMe } from '../lib/auth'
import { getPasskey, passkeyError, webauthnSupported } from '../lib/webauthn'

export function Login() {
  const me = useMe()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needTotp, setNeedTotp] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const next = params.get('next')
  const target = next && next.startsWith('/') && !next.startsWith('//') ? next : '/'

  if (me.data && !me.data.initialised) {
    return (
      <section className="card stack narrow">
        <h1>Set up ShareSomething</h1>
        <p>
          Create the owner account on the server: <code>sharesomething admin init</code> (or <code>docker exec -it sharesomething sharesomething admin init</code>).
        </p>
      </section>
    )
  }

  const showTotp = needTotp || !!me.data?.totp_enabled
  const passkeyLogin = async () => {
    setBusy(true)
    setError(null)
    try {
      const start = await unwrap(api.POST('/api/auth/passkey/login/start'))
      const credential = await getPasskey(start.options)
      const res = await unwrap(api.POST('/api/auth/passkey/login/finish', { body: { ceremony_id: start.ceremony_id, credential } }))
      qc.setQueryData(['me'], res)
      navigate(target, { replace: true })
    } catch (err) {
      setError(passkeyError(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <form
      className="card stack narrow"
      onSubmit={async (e) => {
        e.preventDefault()
        setBusy(true)
        setError(null)
        try {
          const res = await unwrap(api.POST('/api/auth/login', { body: { password, totp: totp || null } }))
          qc.setQueryData(['me'], res)
          navigate(target, { replace: true })
        } catch (err) {
          if (err instanceof ApiError && err.code === 'totp_required') setNeedTotp(true)
          else setError(err)
        } finally {
          setBusy(false)
        }
      }}
    >
      <h1>Sign in</h1>
      {!!me.data?.passkeys && webauthnSupported() && (
        <>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={passkeyLogin}>
            Sign in with a passkey
          </button>
          <div className="divider">or use your password</div>
        </>
      )}
      <label className="field">
        Password
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />
      </label>
      {showTotp && (
        <label className="field">
          Authenticator code
          <input inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="123456" required />
        </label>
      )}
      <ErrorNote error={error} />
      <button className={me.data?.passkeys ? 'btn' : 'btn btn-primary'} disabled={busy}>
        Sign in
      </button>
    </form>
  )
}
