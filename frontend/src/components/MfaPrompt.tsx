import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, unwrap } from '../api/client'
import { useMe } from '../lib/auth'
import { getPasskey, passkeyError, webauthnSupported } from '../lib/webauthn'
import { ErrorNote } from './ErrorNote'

/** Re-confirms the owner with TOTP or a passkey; refreshes `me` on success. */
export function MfaPrompt({ onDone, children }: { onDone?: () => void; children?: React.ReactNode }) {
  const me = useMe()
  const qc = useQueryClient()
  const [totp, setTotp] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const done = (res: unknown) => {
    qc.setQueryData(['me'], res)
    onDone?.()
  }
  const usePasskey = async () => {
    setBusy(true)
    setError(null)
    try {
      const start = await unwrap(api.POST('/api/auth/passkey/step-up/start'))
      const credential = await getPasskey(start.options)
      done(await unwrap(api.POST('/api/auth/passkey/step-up/finish', { body: { ceremony_id: start.ceremony_id, credential } })))
    } catch (e) {
      setError(passkeyError(e))
    } finally {
      setBusy(false)
    }
  }
  const hasPasskey = (me.data?.passkeys ?? 0) > 0 && webauthnSupported()

  return (
    <div className="stack">
      {children}
      {hasPasskey && (
        <button type="button" className="btn btn-primary" disabled={busy} onClick={usePasskey}>
          Confirm with a passkey
        </button>
      )}
      {me.data?.totp_enabled && (
        <form
          className="row"
          onSubmit={async (e) => {
            e.preventDefault()
            setError(null)
            try {
              done(await unwrap(api.POST('/api/auth/step-up', { body: { totp } })))
              setTotp('')
            } catch (err) {
              setError(err)
            }
          }}
        >
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
            placeholder="Authenticator code"
            aria-label="Authenticator code"
            required
          />
          <button className={hasPasskey ? 'btn' : 'btn btn-primary'}>Confirm</button>
        </form>
      )}
      <ErrorNote error={error} />
    </div>
  )
}
