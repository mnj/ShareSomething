import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, ApiError, unwrap, type Schemas, type ShareInfo, type SharePayload } from '../api/client'
import { CopyButton } from '../components/CopyButton'
import { ErrorNote } from '../components/ErrorNote'
import { decryptShare, derivePassphraseKeys, keyFromFragment, toB64, type E2eMeta, type KdfParams } from '../crypto/e2e'
import { formatRelative } from '../lib/format'

interface Revealed {
  payload: SharePayload
  title?: string | null
  burned: boolean
  viewsLeft?: number | null
}

export function ShareView() {
  const { slug = '' } = useParams()
  const [fragmentKey] = useState(() => keyFromFragment(window.location.hash))
  const [revealed, setRevealedState] = useState<Revealed | null>(null)
  const setRevealed = (r: Revealed) => {
    // The key is useless now; drop it from the address bar so it doesn't linger in history.
    history.replaceState(null, '', window.location.pathname)
    setRevealedState(r)
  }
  const info = useQuery({
    queryKey: ['share-info', slug],
    queryFn: () => unwrap(api.GET('/api/s/{slug}', { params: { path: { slug } } })),
    retry: false,
    enabled: !revealed,
  })

  if (revealed) return <RevealedView r={revealed} />
  if (info.isPending) return <p className="hint">Loading…</p>
  if (info.error) {
    if (info.error instanceof ApiError && info.error.status === 404) {
      return (
        <Notice title="Nothing here">This share doesn't exist, has expired, or has already been opened. Shares that were opened or expired are destroyed for good.</Notice>
      )
    }
    return <ErrorNote error={info.error} />
  }
  return <Gate info={info.data} fragmentKey={fragmentKey} onRevealed={setRevealed} />
}

function Notice({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="card stack narrow">
      <h1>{title}</h1>
      <p>{children}</p>
    </section>
  )
}

function Gate({ info, fragmentKey, onRevealed }: { info: ShareInfo; fragmentKey?: string; onRevealed: (r: Revealed) => void }) {
  const qc = useQueryClient()
  const [passphrase, setPassphrase] = useState('')
  const [totp, setTotp] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const refresh = () => qc.invalidateQueries({ queryKey: ['share-info', info.slug] })
  const next = encodeURIComponent(location.pathname)

  switch (info.status) {
    case 'denied':
      return <Notice title="Access denied">You don't have access to this share from here.</Notice>
    case 'need_auth':
      return <Notice title="Sign-in required">This share is restricted to specific people. Recipient sign-in isn't available in this version yet.</Notice>
    case 'need_owner_login':
      return (
        <Notice title="Owner only">
          This share can only be opened by its owner. <Link to={`/login?next=${next}`}>Sign in</Link>
        </Notice>
      )
    case 'need_owner_mfa':
      return (
        <form
          className="card stack narrow"
          onSubmit={async (e) => {
            e.preventDefault()
            setError(null)
            try {
              await unwrap(api.POST('/api/auth/step-up', { body: { totp } }))
              qc.invalidateQueries({ queryKey: ['me'] })
              refresh()
            } catch (err) {
              setError(err)
            }
          }}
        >
          <h1>Confirm it's you</h1>
          <p>Enter the code from your authenticator app to open this share.</p>
          <input inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="123456" autoFocus required />
          <ErrorNote error={error} />
          <button className="btn btn-primary">Confirm</button>
        </form>
      )
  }

  const e2eFragmentMissing = info.enc_mode === 'e2e' && !info.passphrase_required && !fragmentKey
  const reveal = async () => {
    setBusy(true)
    setError(null)
    try {
      onRevealed(await openShare(info, passphrase, fragmentKey))
    } catch (err) {
      setError(err)
      if (err instanceof ApiError && err.status === 404) refresh()
    } finally {
      setBusy(false)
    }
  }

  return (
    <form
      className="card stack narrow"
      onSubmit={(e) => {
        e.preventDefault()
        reveal()
      }}
    >
      <h1>{info.title || 'Someone shared something with you'}</h1>
      <p className="hint">
        {kindLabel(info.kind)} · {info.enc_mode === 'e2e' ? 'end-to-end encrypted' : 'encrypted'}
        {info.expires_at ? ` · expires ${formatRelative(info.expires_at)}` : ''}
      </p>
      {info.views_left === 1 && <p className="note note-warn">This can be opened only once. After you reveal it, it is destroyed.</p>}
      {info.views_left != null && info.views_left > 1 && <p className="note">Can be opened {info.views_left} more times.</p>}
      {e2eFragmentMissing ? (
        <p className="note note-error">This link is incomplete: it's missing the key after "#". Ask the sender for the full link.</p>
      ) : (
        <>
          {info.passphrase_required && (
            <label className="field">
              Passphrase
              <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoFocus required />
            </label>
          )}
          <ErrorNote error={error} />
          <button className="btn btn-primary" disabled={busy}>
            {busy ? 'Opening…' : 'Reveal'}
          </button>
        </>
      )}
    </form>
  )
}

function kindLabel(kind?: Schemas['ShareKind'] | null) {
  return kind === 'link' ? 'Link' : kind === 'credential' ? 'Credential' : 'Text'
}

async function openShare(info: ShareInfo, passphrase: string, fragmentKey?: string): Promise<Revealed> {
  let verifier: string | null = null
  let kek: Uint8Array<ArrayBuffer> | undefined
  if (info.enc_mode === 'e2e' && info.passphrase_required) {
    const keys = await derivePassphraseKeys(passphrase, info.kdf as unknown as KdfParams)
    verifier = toB64(keys.verifier)
    kek = keys.kek
  }
  const body = info.enc_mode === 'server' ? { passphrase: passphrase || null } : { passphrase_verifier: verifier }
  const res = await unwrap(api.POST('/api/s/{slug}/open', { params: { path: { slug: info.slug } }, body }))
  let payload: SharePayload
  if (res.enc_mode === 'server') {
    payload = res.payload!
  } else {
    payload = await decryptShare<SharePayload>(res.ciphertext!, res.enc_meta as unknown as E2eMeta, { fragmentKey, kek })
  }
  return { payload, title: res.title, burned: res.burned, viewsLeft: res.views_left }
}

function RevealedView({ r }: { r: Revealed }) {
  return (
    <section className="card stack narrow">
      {r.title && <h1>{r.title}</h1>}
      {r.burned && <p className="note note-warn">This share has now been destroyed. Copy what you need before you leave this page.</p>}
      <Payload p={r.payload} />
    </section>
  )
}

function safeHttpUrl(s: string): string | null {
  try {
    const u = new URL(s)
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null
  } catch {
    return null
  }
}

function Payload({ p }: { p: SharePayload }) {
  switch (p.kind) {
    case 'text':
      return (
        <div className="stack">
          <pre className="secret-text">{p.text}</pre>
          <div className="row">
            <CopyButton value={p.text} />
          </div>
        </div>
      )
    case 'link': {
      const href = safeHttpUrl(p.url)
      return (
        <div className="stack">
          <div className="link-box">
            <code>{p.url}</code>
            <CopyButton value={p.url} />
          </div>
          {href && (
            <a className="btn btn-primary" href={href} target="_blank" rel="noopener noreferrer">
              Open link
            </a>
          )}
          {p.note && <p className="pre-wrap">{p.note}</p>}
        </div>
      )
    }
    case 'credential':
      return (
        <div className="stack">
          {p.fields.map((f, i) => (
            <CredentialValue key={i} label={f.label} value={f.value} secret={!!f.secret} />
          ))}
          {p.note && <p className="pre-wrap">{p.note}</p>}
        </div>
      )
  }
}

function CredentialValue({ label, value, secret }: { label: string; value: string; secret: boolean }) {
  const [shown, setShown] = useState(!secret)
  return (
    <div className="cred-value">
      <span className="cred-label">{label}</span>
      <code>{shown ? value : '•'.repeat(Math.min(value.length, 16))}</code>
      {secret ? (
        <button type="button" className="btn btn-small btn-ghost" onClick={() => setShown(!shown)}>
          {shown ? 'Hide' : 'Show'}
        </button>
      ) : (
        <span />
      )}
      <CopyButton value={value} />
    </div>
  )
}
