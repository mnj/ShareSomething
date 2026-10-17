import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, unwrap, type ShareInfo } from '../api/client'
import { stashFragmentKey, useAuthMethods } from '../lib/recipient'
import { ErrorNote } from './ErrorNote'

/** Lets a visitor prove an email address that the share's policy accepts. */
export function RecipientSignIn({ info, fragmentKey }: { info: ShareInfo; fragmentKey?: string }) {
  const qc = useQueryClient()
  const methods = useAuthMethods()
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [challenge, setChallenge] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const labels = new Map(methods.data?.map((m) => [m.id, m.label]))
  const providers = info.auth_methods.filter((m) => m.startsWith('oidc:'))
  const emailCode = info.auth_methods.includes('email_otp')
  const next = encodeURIComponent(location.pathname)
  const done = () => {
    qc.invalidateQueries({ queryKey: ['share-info', info.slug] })
    qc.invalidateQueries({ queryKey: ['recipient'] })
  }
  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  if (!providers.length && !emailCode) {
    return (
      <section className="card stack narrow">
        <h1>Sign-in required</h1>
        <p>This share is restricted to specific people, but no sign-in method is available. Ask the sender for help.</p>
      </section>
    )
  }

  return (
    <section className="card stack narrow">
      <h1>Sign in to open this share</h1>
      <p className="hint">The sender limited this share to specific people. Confirm your email address to continue.</p>
      {providers.map((id) => (
        <a
          key={id}
          className="btn"
          href={`/api/recipient/oidc/${encodeURIComponent(id.slice(5))}/start?next=${next}`}
          onClick={() => stashFragmentKey(info.slug, fragmentKey)}
        >
          Continue with {labels.get(id) ?? id.slice(5)}
        </a>
      ))}
      {emailCode && providers.length > 0 && <div className="divider">or</div>}
      {emailCode &&
        (challenge ? (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault()
              run(async () => {
                await unwrap(api.POST('/api/recipient/email/verify', { body: { challenge_id: challenge, code } }))
                done()
              })
            }}
          >
            <p>
              If <b>{email}</b> has access, we've sent it a 6-digit code.
            </p>
            <label className="field">
              Code
              <input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" autoFocus required />
            </label>
            <ErrorNote error={error} />
            <div className="row">
              <button className="btn btn-primary" disabled={busy}>
                Verify
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => setChallenge(null)}>
                Use another email
              </button>
            </div>
          </form>
        ) : (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault()
              run(async () => {
                const r = await unwrap(api.POST('/api/recipient/email/start', { body: { slug: info.slug, email } }))
                setCode('')
                setChallenge(r.challenge_id)
              })
            }}
          >
            <label className="field">
              Email
              <input type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" required />
            </label>
            <ErrorNote error={error} />
            <button className="btn btn-primary" disabled={busy}>
              Email me a code
            </button>
          </form>
        ))}
    </section>
  )
}

/** "Signed in as …" line with a sign-out button, shown on share pages. */
export function RecipientBar({ emails }: { emails: string[] }) {
  const qc = useQueryClient()
  if (!emails.length) return null
  return (
    <p className="hint row wrap recipient-bar">
      Signed in as {emails.join(', ')}
      <button
        type="button"
        className="btn btn-small btn-ghost"
        onClick={async () => {
          await unwrap(api.POST('/api/recipient/logout'))
          qc.invalidateQueries({ queryKey: ['recipient'] })
          qc.invalidateQueries({ queryKey: ['share-info'] })
        }}
      >
        Sign out
      </button>
    </p>
  )
}
