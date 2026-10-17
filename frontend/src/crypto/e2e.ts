/**
 * End-to-end encryption for shares. The server only ever sees ciphertext.
 *
 * Content: nonce(12) || AES-256-GCM(DEK, payload JSON, aad = "sharesomething/v1").
 * The DEK reaches the recipient either:
 *  - "fragment":   in the URL fragment (#k=...), which browsers never send to the server, or
 *  - "passphrase": wrapped with a KEK from argon2id(passphrase). The second half of the argon2
 *                  output is a verifier the server checks before spending a view, so a typo
 *                  doesn't burn a read-once share. The server stores only sha256(verifier).
 */
import { argon2id } from 'hash-wasm'

const AAD_CONTENT = new TextEncoder().encode('sharesomething/v1')
const AAD_WRAP = new TextEncoder().encode('sharesomething/v1/wrap')

export interface KdfParams {
  alg: 'argon2id'
  salt: string // base64
  m: number // memory KiB
  t: number // iterations
  p: number // parallelism
}

export interface E2eMeta {
  v: 1
  alg: 'A256GCM'
  key: 'fragment' | 'passphrase'
  kdf?: KdfParams
  wrapped_key?: string // base64 nonce || ciphertext
}

export const DEFAULT_KDF = { m: 64 * 1024, t: 3, p: 1 } as const

// --- encoding helpers ----------------------------------------------------------------------

export function toB64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function fromB64(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

export function toB64Url(bytes: Uint8Array): string {
  return toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function random(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n))
}

// --- primitives ----------------------------------------------------------------------------

async function aesKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

async function seal(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const iv = random(12)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, await aesKey(key), data)
  const out = new Uint8Array(12 + ct.byteLength)
  out.set(iv)
  out.set(new Uint8Array(ct), 12)
  return out
}

async function open(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  if (data.length < 12 + 16) throw new DecryptError()
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12), additionalData: aad }, await aesKey(key), data.slice(12))
    return new Uint8Array(pt)
  } catch {
    throw new DecryptError()
  }
}

export class DecryptError extends Error {
  constructor() {
    super('Could not decrypt: the key or passphrase is wrong, or the data was tampered with.')
  }
}

/** argon2id(passphrase) → { kek, verifier }, 32 bytes each. */
export async function derivePassphraseKeys(passphrase: string, kdf: KdfParams): Promise<{ kek: Uint8Array<ArrayBuffer>; verifier: Uint8Array<ArrayBuffer> }> {
  const out = await argon2id({
    password: passphrase.normalize('NFC'),
    salt: fromB64(kdf.salt),
    iterations: kdf.t,
    parallelism: kdf.p,
    memorySize: kdf.m,
    hashLength: 64,
    outputType: 'binary',
  })
  const bytes = new Uint8Array(out)
  return { kek: bytes.slice(0, 32), verifier: bytes.slice(32, 64) }
}

// --- share-level API -----------------------------------------------------------------------

export interface EncryptedShare {
  ciphertext: string // base64
  meta: E2eMeta
  /** base64; present in passphrase mode, sent to the server at create time. */
  verifier?: string
  /** base64url DEK for the URL fragment; present in fragment mode. */
  fragmentKey?: string
}

export async function encryptShare(payload: unknown, passphrase?: string, kdfCost: Omit<KdfParams, 'alg' | 'salt'> = DEFAULT_KDF): Promise<EncryptedShare> {
  const dek = random(32)
  const ct = await seal(dek, new TextEncoder().encode(JSON.stringify(payload)), AAD_CONTENT)
  if (!passphrase) {
    return { ciphertext: toB64(ct), meta: { v: 1, alg: 'A256GCM', key: 'fragment' }, fragmentKey: toB64Url(dek) }
  }
  const kdf: KdfParams = { alg: 'argon2id', salt: toB64(random(16)), ...kdfCost }
  const { kek, verifier } = await derivePassphraseKeys(passphrase, kdf)
  const wrapped = await seal(kek, dek, AAD_WRAP)
  return {
    ciphertext: toB64(ct),
    meta: { v: 1, alg: 'A256GCM', key: 'passphrase', kdf, wrapped_key: toB64(wrapped) },
    verifier: toB64(verifier),
  }
}

/** Decrypts with either the fragment key or the KEK derived from the passphrase. */
export async function decryptShare<T>(ciphertext: string, meta: E2eMeta, secret: { fragmentKey?: string; kek?: Uint8Array<ArrayBuffer> }): Promise<T> {
  if (meta.v !== 1 || meta.alg !== 'A256GCM') throw new Error('Unsupported encryption format')
  let dek: Uint8Array<ArrayBuffer>
  if (meta.key === 'fragment') {
    if (!secret.fragmentKey) throw new Error('The link is missing its key (the part after #).')
    dek = fromB64(secret.fragmentKey)
  } else {
    if (!secret.kek || !meta.wrapped_key) throw new Error('Passphrase required')
    dek = await open(secret.kek, fromB64(meta.wrapped_key), AAD_WRAP)
  }
  const pt = await open(dek, fromB64(ciphertext), AAD_CONTENT)
  return JSON.parse(new TextDecoder().decode(pt)) as T
}

/** Reads `k` from a URL fragment like `#k=abc`. */
export function keyFromFragment(hash: string): string | undefined {
  return new URLSearchParams(hash.replace(/^#/, '')).get('k') ?? undefined
}
