import { useQuery, useQueryClient } from '@tanstack/react-query'
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
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needTotp, setNeedTotp] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const next = params.get('next')
  const target = next && next.startsWith('/') && !next.startsWith('//') ? next : '/'
  const sso = useQuery({
    queryKey: ['sso-providers'],
    queryFn: () => unwrap(api.GET('/api/auth/sso-providers')),
    enabled: me.data?.mode === 'team',
  })

  if (me.data && !me.data.initialised) {
    return (
      <section className="card stack narrow">
        <h1>Set up ShareSomething</h1>
        <p>
          Create the first account on the server: <code>sharesomething admin init</code> (or <code>docker exec -it sharesomething sharesomething admin init</code>).
        </p>
      </section>
    )
  }

  const team = me.data?.mode === 'team'
  const ssoError = params.get('sso_error')
  // Team mode: we don't know the account's factors until the server answers, so ask when needed.
  const showTotp = needTotp || (!team && !!me.data?.totp_enabled)
  const offerPasskey = webauthnSupported() && (team || !!me.data?.passkeys)
  const passkeyLogin = async () => {
    setBusy(true)
    setError(null)
    try {
      if (team && !email) throw new Error('Enter your email address first.')
      const start = await unwrap(api.POST('/api/auth/passkey/login/start', { body: { email: team ? email : null } }))
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
          const res = await unwrap(api.POST('/api/auth/login', { body: { email: team ? email : null, password, totp: totp || null } }))
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
      {ssoError && <p className="note note-error" role="alert">{SSO_ERRORS[ssoError] ?? 'Single sign-on failed. Try again or ask your admin.'}</p>}
      {team && !!sso.data?.length && (
        <>
          {sso.data.map((p) => (
            <a key={p.id} className="btn btn-primary" href={`/api/recipient/oidc/${encodeURIComponent(p.id)}/start?purpose=member&next=${encodeURIComponent(target)}`}>
              Sign in with {p.name}
            </a>
          ))}
          <div className="divider">or with a local account</div>
        </>
      )}
      {team && (
        <label className="field">
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username webauthn" autoFocus required />
        </label>
      )}
      {offerPasskey && (
        <>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={passkeyLogin}>
            Sign in with a passkey
          </button>
          <div className="divider">or use your password</div>
        </>
      )}
      <label className="field">
        Password
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus={!team} required />
      </label>
      {showTotp && (
        <label className="field">
          Authenticator code
          <input inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="123456" required />
        </label>
      )}
      <ErrorNote error={error} />
      <button className={offerPasskey ? 'btn' : 'btn btn-primary'} disabled={busy}>
        Sign in
      </button>
    </form>
  )
}

const SSO_ERRORS: Record<string, string> = {
  not_a_member: "Your account isn't allowed to sign in here. Ask your admin for an invite.",
  account_disabled: 'Your account has been disabled.',
  no_verified_email: "Your identity provider didn't share a verified email address.",
  provider_error: 'Single sign-on failed. Try again.',
}
