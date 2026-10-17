import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { activeWorker, StreamUnavailable } from '../lib/swDownload'
import { api, ApiError, unwrap, type Schemas, type ShareInfo, type SharePayload } from '../api/client'
import { CopyButton } from '../components/CopyButton'
import { ErrorNote } from '../components/ErrorNote'
import { MfaPrompt } from '../components/MfaPrompt'
import { RecipientBar, RecipientSignIn } from '../components/RecipientSignIn'
import { decryptPayload, derivePassphraseKeys, keyFromFragment, toB64, unwrapDek, type E2eMeta, type KdfParams } from '../crypto/e2e'
import {
  canSaveToDisk,
  canSaveToFolder,
  downloadFile,
  downloadToHandle,
  downloadViaWorker,
  formatBytes,
  isAbort,
  MEMORY_WARN_BYTES,
  safeFileName,
  saveBlob,
  streamServerDownload,
  type Progress,
} from '../lib/files'
import { AUTH_ERRORS, clearStashedKey, readStashedKey, useRecipient } from '../lib/recipient'
import { formatRelative } from '../lib/format'

interface Revealed {
  slug: string
  payload: SharePayload
  title?: string | null
  burned: boolean
  viewsLeft?: number | null
  /** Link shares: seconds before opening the target automatically. */
  redirectSecs?: number | null
  /** File shares: token for fetching chunks, and the content key for E2E. */
  download?: { token: string; expiresAt: number; dek?: Uint8Array<ArrayBuffer> }
}

export function ShareView() {
  const { slug = '' } = useParams()
  // After an OIDC round trip the fragment is gone; the key was parked in sessionStorage.
  const [fragmentKey] = useState(() => keyFromFragment(window.location.hash) ?? readStashedKey(slug))
  const [params] = useSearchParams()
  const [authError] = useState(() => params.get('auth_error'))
  const recipient = useRecipient()
  const [revealed, setRevealedState] = useState<Revealed | null>(null)
  const setRevealed = (r: Revealed) => {
    // The key is useless now; drop it from the address bar so it doesn't linger in history.
    history.replaceState(null, '', window.location.pathname)
    clearStashedKey(slug)
    setRevealedState(r)
  }
  const emails = [...new Set(recipient.data?.identities.map((i) => i.email) ?? [])]
  const info = useQuery({
    queryKey: ['share-info', slug],
    queryFn: () => unwrap(api.GET('/api/s/{slug}', { params: { path: { slug } } })),
    retry: false,
    enabled: !revealed,
  })

  const bar = <RecipientBar emails={emails} />
  if (revealed)
    return (
      <>
        {bar}
        <RevealedView r={revealed} />
      </>
    )
  if (info.isPending) return <p className="hint">Loading…</p>
  if (info.error) {
    if (info.error instanceof ApiError && info.error.status === 404) {
      return (
        <Notice title="Nothing here">This share doesn't exist, has expired, or has already been opened. Shares that were opened or expired are destroyed for good.</Notice>
      )
    }
    return <ErrorNote error={info.error} />
  }
  return (
    <div className="stack">
      {authError && <p className="note note-error narrow">{AUTH_ERRORS[authError] ?? AUTH_ERRORS.failed}</p>}
      {bar}
      <Gate info={info.data} fragmentKey={fragmentKey} onRevealed={setRevealed} />
    </div>
  )
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
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const refresh = () => qc.invalidateQueries({ queryKey: ['share-info', info.slug] })
  const next = encodeURIComponent(location.pathname)
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

  // Redirect links open without a click, but only when that can't burn anything: no view limit
  // (mail scanners run JavaScript too) and nothing to type in.
  const autoOpen =
    info.status === 'ready' && info.kind === 'link' && info.redirect_secs != null && info.views_left == null && !info.passphrase_required && !e2eFragmentMissing
  const autoStarted = useRef(false)
  useEffect(() => {
    if (autoOpen && !autoStarted.current) {
      autoStarted.current = true
      void reveal()
    }
  })

  switch (info.status) {
    case 'denied':
      return <Notice title="Access denied">You don't have access to this share from here, or with the account you're signed in with.</Notice>
    case 'need_auth':
      return <RecipientSignIn info={info} fragmentKey={fragmentKey} />
    case 'need_owner_login':
      return (
        <Notice title="Owner only">
          This share can only be opened by its owner. <Link to={`/login?next=${next}`}>Sign in</Link>
        </Notice>
      )
    case 'need_owner_mfa':
      return (
        <section className="card stack narrow">
          <h1>Confirm it's you</h1>
          <MfaPrompt onDone={refresh}>
            <p>Use a passkey or your authenticator app to open this share.</p>
          </MfaPrompt>
        </section>
      )
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
  return kind === 'link' ? 'Link' : kind === 'credential' ? 'Credential' : kind === 'files' ? 'Files' : 'Text'
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
  let dek: Uint8Array<ArrayBuffer> | undefined
  if (res.enc_mode === 'server') {
    payload = res.payload!
  } else {
    dek = await unwrapDek(res.enc_meta as unknown as E2eMeta, { fragmentKey, kek })
    payload = await decryptPayload<SharePayload>(res.ciphertext!, dek)
  }
  const download = res.download_token ? { token: res.download_token, expiresAt: res.download_expires_at ?? 0, dek } : undefined
  return { slug: info.slug, payload, title: res.title, burned: res.burned, viewsLeft: res.views_left, download, redirectSecs: info.redirect_secs }
}

function RevealedView({ r }: { r: Revealed }) {
  return (
    <section className="card stack narrow">
      {r.title && <h1>{r.title}</h1>}
      {r.burned && (
        <p className="note note-warn">
          {r.download
            ? `This share has now been destroyed. Download the files before ${new Date(r.download.expiresAt * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}; after that they're gone.`
            : 'This share has now been destroyed. Copy what you need before you leave this page.'}
        </p>
      )}
      {r.payload.kind === 'files' && r.download ? (
        <FileList r={r} files={r.payload.files} note={r.payload.note} />
      ) : r.payload.kind === 'link' && r.redirectSecs != null && safeHttpUrl(r.payload.url) ? (
        <RedirectCountdown url={safeHttpUrl(r.payload.url)!} secs={r.redirectSecs} note={r.payload.note} />
      ) : (
        <Payload p={r.payload} />
      )}
    </section>
  )
}

/** Shows where a short link goes, then navigates there unless the visitor stops it. */
function RedirectCountdown({ url, secs, note }: { url: string; secs: number; note?: string | null }) {
  const [left, setLeft] = useState(secs)
  const [stopped, setStopped] = useState(false)
  const target = new URL(url)
  useEffect(() => {
    if (stopped) return
    if (left <= 0) {
      window.location.assign(url)
      return
    }
    const t = setTimeout(() => setLeft((n) => n - 1), 1000)
    return () => clearTimeout(t)
  }, [left, stopped, url])

  return (
    <div className="stack redirect">
      <p className="hint">This link goes to</p>
      <p className="redirect-host">{target.host}</p>
      <code className="redirect-url">{url}</code>
      {note && <p className="pre-wrap">{note}</p>}
      {stopped ? (
        <p className="hint">Redirect stopped.</p>
      ) : (
        <>
          <p aria-live="polite">{left > 0 ? `Opening in ${left} second${left === 1 ? '' : 's'}…` : 'Opening…'}</p>
          <progress className="progress" value={secs - left} max={secs || 1} aria-label="Time until redirect" />
        </>
      )}
      <div className="row">
        <a className="btn btn-primary" href={url} rel="noopener noreferrer">
          Go now
        </a>
        {!stopped && (
          <button type="button" className="btn btn-ghost" onClick={() => setStopped(true)}>
            Stay here
          </button>
        )}
        <CopyButton value={url} />
      </div>
    </div>
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
    case 'files':
      return null
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

type FileState = Progress | 'done' | 'started'

function FileList({ r, files, note }: { r: Revealed; files: Schemas['FileEntry'][]; note?: string | null }) {
  const [progress, setProgress] = useState<Record<number, FileState>>({})
  const [error, setError] = useState<unknown>(null)
  const { token, dek } = r.download!
  const serverMode = !dek
  const set = (i: number, p: FileState | undefined) =>
    setProgress((s) => {
      const next = { ...s }
      if (p) next[i] = p
      else delete next[i]
      return next
    })

  const fetchOne = async (i: number, dir?: FileSystemDirectoryHandle) => {
    const f = files[i]
    setError(null)
    try {
      if (serverMode) {
        streamServerDownload(r.slug, i, token, f.name)
        set(i, 'started')
        return
      }
      const onProgress = (p: Progress) => set(i, p)
      if (dir || canSaveToDisk()) {
        // Pick the destination first (needs the click's user activation), then stream to it.
        const handle = dir ? await dir.getFileHandle(safeFileName(f.name), { create: true }) : await window.showSaveFilePicker!({ suggestedName: f.name })
        await downloadToHandle(handle, r.slug, token, i, f, dek, onProgress)
      } else {
        const sw = await activeWorker()
        let streamed = false
        if (sw) {
          try {
            await downloadViaWorker(sw, r.slug, token, i, f, dek, onProgress)
            streamed = true
          } catch (e) {
            if (!(e instanceof StreamUnavailable)) throw e
          }
        }
        if (!streamed) saveBlob(await downloadFile(r.slug, token, i, f, dek, onProgress), f.name)
      }
      set(i, 'done')
    } catch (e) {
      set(i, undefined)
      if (!isAbort(e)) setError(e)
    }
  }

  const fetchAll = async () => {
    if (serverMode) {
      for (let i = 0; i < files.length; i++) {
        if (progress[i]) continue
        await fetchOne(i)
        // Let each form-submitted download start before the next one.
        await new Promise((res) => setTimeout(res, 1200))
      }
      return
    }
    let dir: FileSystemDirectoryHandle | undefined
    if (canSaveToFolder()) {
      try {
        dir = await window.showDirectoryPicker!({ mode: 'readwrite' })
      } catch (e) {
        if (isAbort(e)) return
        throw e
      }
    }
    for (let i = 0; i < files.length; i++) if (progress[i] !== 'done') await fetchOne(i, dir)
  }

  const busy = Object.values(progress).some((p) => typeof p === 'object')
  const [workerReady, setWorkerReady] = useState(false)
  useEffect(() => {
    activeWorker().then((w) => setWorkerReady(!!w))
  }, [])
  const big = !serverMode && !canSaveToDisk() && !workerReady && files.some((f) => f.size > MEMORY_WARN_BYTES)
  return (
    <div className="stack">
      <ul className="file-list">
        {files.map((f, i) => {
          const p = progress[i]
          return (
            <li key={i}>
              <span className="file-name">{f.name}</span>
              <span className="hint">{formatBytes(f.size)}</span>
              {p === 'done' ? (
                <span className="badge badge-ok">saved</span>
              ) : p === 'started' ? (
                <span className="badge badge-ok">downloading</span>
              ) : p ? (
                <progress className="progress small" value={p.done} max={p.total || 1} aria-label={`Downloading ${f.name}`} />
              ) : (
                <button type="button" className="btn btn-small" disabled={busy} onClick={() => fetchOne(i)}>
                  Download
                </button>
              )}
            </li>
          )
        })}
      </ul>
      {files.length > 1 && (
        <button type="button" className="btn btn-primary" disabled={busy} onClick={() => fetchAll().catch(setError)}>
          Download all
        </button>
      )}
      <ErrorNote error={error} />
      {big && <p className="note note-warn">Large files are assembled in this browser's memory. If a download fails, try a Chromium-based browser, which can save straight to disk.</p>}
      {note && <p className="pre-wrap">{note}</p>}
      <p className="hint">
        {serverMode
          ? "Files are decrypted by the server and saved by your browser's download manager."
          : canSaveToDisk() || workerReady
            ? 'Files are decrypted in your browser and written straight to disk.'
            : 'Files are decrypted in your browser as they download.'}
      </p>
    </div>
  )
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
