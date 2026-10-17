import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useCallback, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, unwrap, type Schemas, type SharePayload, type ShareSummary } from '../api/client'
import { CopyButton } from '../components/CopyButton'
import { CredentialEditor } from '../components/CredentialEditor'
import { ErrorNote } from '../components/ErrorNote'
import { PolicyEditor } from '../components/PolicyEditor'
import { SlugPicker, type SlugChoice } from '../components/SlugPicker'
import { encryptShare } from '../crypto/e2e'
import { useMe } from '../lib/auth'
import { rowsToPolicy, type RuleRow } from '../lib/policy'

type Kind = Schemas['ShareKind']
type Access = 'public' | 'owner' | 'custom'

const EXPIRY: { label: string; secs: number | null }[] = [
  { label: 'Never', secs: null },
  { label: '10 minutes', secs: 600 },
  { label: '1 hour', secs: 3600 },
  { label: '1 day', secs: 86400 },
  { label: '7 days', secs: 7 * 86400 },
  { label: '30 days', secs: 30 * 86400 },
]

const KINDS: { kind: Kind; label: string }[] = [
  { kind: 'text', label: 'Text' },
  { kind: 'link', label: 'Link' },
  { kind: 'credential', label: 'Credential' },
]

interface Created {
  share: ShareSummary
  fullUrl: string
  passphrase: boolean
}

export function NewShare() {
  const me = useMe()
  const qc = useQueryClient()
  const [kind, setKind] = useState<Kind>('text')
  const [text, setText] = useState('')
  const [url, setUrl] = useState('')
  const [note, setNote] = useState('')
  const [fields, setFields] = useState<Schemas['CredentialField'][]>([
    { label: 'Username', value: '', secret: false },
    { label: 'Password', value: '', secret: true },
  ])
  const [title, setTitle] = useState('')
  const [encMode, setEncMode] = useState<Schemas['EncMode']>('e2e')
  const [passphrase, setPassphrase] = useState('')
  const [slug, setSlug] = useState<SlugChoice | null>(null)
  const [expiry, setExpiry] = useState<number | null>(86400)
  const [maxViews, setMaxViews] = useState<number | null>(1)
  const [access, setAccess] = useState<Access>('public')
  const [rules, setRules] = useState<RuleRow[]>([{ group: 'include', type: 'everyone', values: '' }])
  const [requireMfa, setRequireMfa] = useState(false)
  const [created, setCreated] = useState<Created | null>(null)
  const onSlug = useCallback((v: SlugChoice) => setSlug(v), [])

  const pickKind = (k: Kind) => {
    setKind(k)
    // Credentials default to the locked-down "only me" setup for moving secrets between machines.
    if (k === 'credential' && access === 'public') {
      setAccess('owner')
      if (me.data?.totp_enabled) setRequireMfa(true)
    }
  }

  const payload = (): SharePayload => {
    const n = note.trim() || null
    switch (kind) {
      case 'text':
        return { kind, text }
      case 'link':
        return { kind, url: url.trim(), note: n }
      case 'credential':
        return { kind, fields: fields.filter((f) => f.label.trim() || f.value), note: n }
    }
  }

  const policy = () => {
    if (access === 'public') return [{ group: 'include' as const, type: 'everyone' as const }]
    if (access === 'owner') return [{ group: 'include' as const, type: 'owner' as const }]
    return rowsToPolicy(rules)
  }

  const create = useMutation({
    mutationFn: async (): Promise<Created> => {
      const base = {
        kind,
        enc_mode: encMode,
        title: title.trim() || null,
        slug: slug ?? {},
        max_views: maxViews,
        expires_in_secs: expiry,
        require_owner_mfa: requireMfa,
        policy: policy(),
      }
      if (encMode === 'server') {
        const share = await unwrap(api.POST('/api/shares', { body: { ...base, payload: payload(), passphrase: passphrase || null } }))
        return { share, fullUrl: share.url, passphrase: !!passphrase }
      }
      const enc = await encryptShare(payload(), passphrase || undefined)
      const share = await unwrap(
        api.POST('/api/shares', {
          body: { ...base, ciphertext: enc.ciphertext, enc_meta: { ...enc.meta }, passphrase_verifier: enc.verifier ?? null },
        }),
      )
      return { share, fullUrl: enc.fragmentKey ? `${share.url}#k=${enc.fragmentKey}` : share.url, passphrase: !!passphrase }
    },
    onSuccess: (c) => {
      setCreated(c)
      qc.invalidateQueries({ queryKey: ['shares'] })
    },
  })

  if (created) return <CreatedView created={created} onAnother={() => location.reload()} />

  const totp = me.data?.totp_enabled
  const e2eFragment = encMode === 'e2e' && !passphrase

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault()
        create.mutate()
      }}
    >
      <h1>New share</h1>

      <section className="card stack">
        <div className="segmented" role="radiogroup" aria-label="Type">
          {KINDS.map((k) => (
            <button key={k.kind} type="button" role="radio" aria-checked={kind === k.kind} className={kind === k.kind ? 'active' : ''} onClick={() => pickKind(k.kind)}>
              {k.label}
            </button>
          ))}
        </div>
        {kind === 'text' && <textarea rows={8} value={text} onChange={(e) => setText(e.target.value)} placeholder="Text, notes, a code snippet…" required />}
        {kind === 'link' && <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" required />}
        {kind === 'credential' && <CredentialEditor fields={fields} onChange={setFields} />}
        {kind !== 'text' && <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (optional)" />}
        <label className="field">
          Title <span className="hint">optional; shown to people who pass the access policy, stored unencrypted</span>
          <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
        </label>
      </section>

      <section className="card stack">
        <h2>Security</h2>
        <div className="grid-2">
          <label className="field">
            Encryption
            <select value={encMode} onChange={(e) => setEncMode(e.target.value as Schemas['EncMode'])}>
              <option value="e2e">End-to-end (in your browser)</option>
              <option value="server">Server-side at rest</option>
            </select>
          </label>
          <label className="field">
            Passphrase <span className="hint">optional, share it another way</span>
            <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="new-password" />
          </label>
          <label className="field">
            Expires
            <select value={String(expiry)} onChange={(e) => setExpiry(e.target.value === 'null' ? null : Number(e.target.value))}>
              {EXPIRY.map((x) => (
                <option key={x.label} value={String(x.secs)}>
                  {x.label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Views
            <select value={String(maxViews)} onChange={(e) => setMaxViews(e.target.value === 'null' ? null : Number(e.target.value))}>
              <option value="1">Read once, then destroy</option>
              <option value="3">3 views</option>
              <option value="10">10 views</option>
              <option value="null">Unlimited</option>
            </select>
          </label>
        </div>
        <p className="hint">
          {encMode === 'e2e'
            ? e2eFragment
              ? 'The decryption key goes in the link after "#". Browsers never send that part to the server, but anyone with the full link can open the share. Add a passphrase to keep the link short and the key out of it.'
              : 'Encrypted in your browser with a key derived from the passphrase. The server never sees the content or the passphrase.'
            : passphrase
              ? 'Encrypted by the server. The passphrase is mixed into the key, so the content can only be read with it.'
              : 'Encrypted by the server with its master key. Use this when you want short links without a passphrase.'}
        </p>
      </section>

      <section className="card stack">
        <h2>Who can open it</h2>
        <div className="segmented" role="radiogroup" aria-label="Access">
          {(
            [
              ['public', 'Anyone with the link'],
              ['owner', 'Only me'],
              ['custom', 'Custom rules'],
            ] as const
          ).map(([a, label]) => (
            <button key={a} type="button" role="radio" aria-checked={access === a} className={access === a ? 'active' : ''} onClick={() => setAccess(a)}>
              {label}
            </button>
          ))}
        </div>
        {access === 'custom' && <PolicyEditor rows={rules} onChange={setRules} />}
        <label className="check">
          <input type="checkbox" checked={requireMfa} disabled={!totp} onChange={(e) => setRequireMfa(e.target.checked)} />
          Also require my authenticator code (owner sign-in + fresh TOTP){!totp && ' (enable TOTP first)'}
        </label>
      </section>

      <section className="card stack">
        <h2>Link</h2>
        <SlugPicker value={slug} onChange={onSlug} />
      </section>

      <ErrorNote error={create.error} />
      <div className="row">
        <button className="btn btn-primary" disabled={create.isPending}>
          {create.isPending ? 'Encrypting…' : 'Create share'}
        </button>
        <Link to="/" className="btn btn-ghost">
          Cancel
        </Link>
      </div>
    </form>
  )
}

function CreatedView({ created, onAnother }: { created: Created; onAnother: () => void }) {
  const { share, fullUrl } = created
  const keyInLink = fullUrl !== share.url
  return (
    <div className="stack">
      <h1>Share created</h1>
      <section className="card stack">
        <div className="link-box">
          <code>{fullUrl}</code>
          <CopyButton value={fullUrl} label="Copy link" className="btn-primary" />
        </div>
        {keyInLink && (
          <p className="note note-warn">This link contains the decryption key. It is shown only once and is not stored anywhere, so copy it now.</p>
        )}
        {created.passphrase && <p className="note">Send the passphrase separately, e.g. by phone or another chat.</p>}
        <p className="hint">
          {share.max_views === 1 ? 'Read once: it is destroyed after it is opened.' : share.max_views ? `Destroyed after ${share.max_views} views.` : 'No view limit.'}{' '}
          {share.expires_at ? `Expires ${new Date(share.expires_at * 1000).toLocaleString()}.` : 'Never expires.'}
        </p>
      </section>
      <div className="row">
        <button type="button" className="btn" onClick={onAnother}>
          Share something else
        </button>
        <Link to="/" className="btn btn-ghost">
          Back to dashboard
        </Link>
      </div>
    </div>
  )
}
