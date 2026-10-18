/**
 * End-to-end encryption for shares. The server only ever sees ciphertext.
 *
 * Content: nonce(12) || AES-256-GCM(DEK, payload JSON, aad = "sharesomething/v1").
 * The DEK reaches the recipient either:
 *  - "fragment":   in the URL fragment (#k=...), which browsers never send to the server, or
 *  - "passphrase": wrapped with a KEK from argon2id(passphrase). The second half of the argon2
 *                  output is a verifier the server checks before spending a view, so a typo
 *                  doesn't burn a read-once share. The server stores only sha256(verifier).
 *
 * File bodies are split into 1 MiB chunks, each nonce(12) || AES-GCM(DEK, chunk) with
 * aad = "sharesomething/v1/file" || u32 file index || u32 chunk index || u8 is-last,
 * so chunks can't be reordered, swapped between files or truncated unnoticed.
 */
import { argon2id } from 'hash-wasm'
import { combine, split, type Part } from './shamir'

const AAD_CONTENT = new TextEncoder().encode('sharesomething/v1')
const AAD_WRAP = new TextEncoder().encode('sharesomething/v1/wrap')
const AAD_FILE = new TextEncoder().encode('sharesomething/v1/file')

export const CHUNK_SIZE = 1024 * 1024
/** Bytes added to every encrypted chunk (nonce + tag). */
export const CHUNK_OVERHEAD = 12 + 16

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
  key: 'fragment' | 'passphrase' | 'split'
  kdf?: KdfParams
  wrapped_key?: string // base64 nonce || ciphertext
  /** Split keys: k of n parts needed; `check` verifies the combined key before opening. */
  split?: { k: number; n: number; check: string }
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
  /** Content key; never sent to the server. Needed to encrypt file chunks. */
  dek: Uint8Array<ArrayBuffer>
  /** base64; present in passphrase mode, sent to the server at create time. */
  verifier?: string
  /** base64url DEK for the URL fragment; present in fragment mode. */
  fragmentKey?: string
}

export async function encryptShare(payload: unknown, passphrase?: string, kdfCost: Omit<KdfParams, 'alg' | 'salt'> = DEFAULT_KDF): Promise<EncryptedShare> {
  const dek = random(32)
  const ct = await seal(dek, new TextEncoder().encode(JSON.stringify(payload)), AAD_CONTENT)
  if (!passphrase) {
    return { ciphertext: toB64(ct), meta: { v: 1, alg: 'A256GCM', key: 'fragment' }, dek, fragmentKey: toB64Url(dek) }
  }
  const kdf: KdfParams = { alg: 'argon2id', salt: toB64(random(16)), ...kdfCost }
  const { kek, verifier } = await derivePassphraseKeys(passphrase, kdf)
  const wrapped = await seal(kek, dek, AAD_WRAP)
  return {
    ciphertext: toB64(ct),
    meta: { v: 1, alg: 'A256GCM', key: 'passphrase', kdf, wrapped_key: toB64(wrapped) },
    dek,
    verifier: toB64(verifier),
  }
}

/** Recovers the content key from either the fragment key or the KEK derived from the passphrase. */
export async function unwrapDek(meta: E2eMeta, secret: { fragmentKey?: string; kek?: Uint8Array<ArrayBuffer>; dek?: Uint8Array<ArrayBuffer> }): Promise<Uint8Array<ArrayBuffer>> {
  if (meta.v !== 1 || meta.alg !== 'A256GCM') throw new Error('Unsupported encryption format')
  if (meta.key === 'fragment') {
    if (!secret.fragmentKey) throw new Error('The link is missing its key (the part after #).')
    return fromB64(secret.fragmentKey)
  }
  if (meta.key === 'split') {
    if (!secret.dek) throw new Error('Key parts are needed.')
    return secret.dek
  }
  if (!secret.kek || !meta.wrapped_key) throw new Error('Passphrase required')
  return open(secret.kek, fromB64(meta.wrapped_key), AAD_WRAP)
}

export async function decryptPayload<T>(ciphertext: string, dek: Uint8Array<ArrayBuffer>): Promise<T> {
  const pt = await open(dek, fromB64(ciphertext), AAD_CONTENT)
  return JSON.parse(new TextDecoder().decode(pt)) as T
}

/** Decrypts with either the fragment key or the KEK derived from the passphrase. */
export async function decryptShare<T>(ciphertext: string, meta: E2eMeta, secret: { fragmentKey?: string; kek?: Uint8Array<ArrayBuffer>; dek?: Uint8Array<ArrayBuffer> }): Promise<T> {
  return decryptPayload<T>(ciphertext, await unwrapDek(meta, secret))
}

function chunkAad(fileIdx: number, chunk: number, last: boolean): Uint8Array<ArrayBuffer> {
  const aad = new Uint8Array(AAD_FILE.length + 9)
  aad.set(AAD_FILE)
  const view = new DataView(aad.buffer)
  view.setUint32(AAD_FILE.length, fileIdx)
  view.setUint32(AAD_FILE.length + 4, chunk)
  aad[AAD_FILE.length + 8] = last ? 1 : 0
  return aad
}

export function encryptChunk(dek: Uint8Array<ArrayBuffer>, fileIdx: number, chunk: number, last: boolean, data: Uint8Array<ArrayBuffer>) {
  return seal(dek, data, chunkAad(fileIdx, chunk, last))
}

export function decryptChunk(dek: Uint8Array<ArrayBuffer>, fileIdx: number, chunk: number, last: boolean, data: Uint8Array<ArrayBuffer>) {
  return open(dek, data, chunkAad(fileIdx, chunk, last))
}

// --- split keys (k-of-n) ---------------------------------------------------------------

const CHECK_LABEL = new TextEncoder().encode('sharesomething/v1/check')

/** 8-byte fingerprint of the DEK. Public, so a browser can tell whether combined parts are right
 *  before spending a view; 64 bits of a hash reveal nothing useful about a 256-bit key. */
export async function keyCheck(dek: Uint8Array<ArrayBuffer>): Promise<string> {
  const data = new Uint8Array(CHECK_LABEL.length + dek.length)
  data.set(CHECK_LABEL)
  data.set(dek, CHECK_LABEL.length)
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', data))
  return Array.from(h.slice(0, 8), (b) => b.toString(16).padStart(2, '0')).join('')
}

/** A key part as a short code: `<x>.<base64url(y)>`. */
export function partCode(p: Part): string {
  return `${p.x}.${toB64Url(p.y)}`
}

/** Accepts a bare code or a full link containing `#p=<code>`. */
export function parsePart(input: string): Part {
  const raw = input.trim()
  const code = raw.includes('#') ? (new URLSearchParams(raw.slice(raw.indexOf('#') + 1)).get('p') ?? '') : raw
  const m = /^(\d{1,3})\.([A-Za-z0-9_-]{40,})$/.exec(code)
  if (!m || Number(m[1]) < 1 || Number(m[1]) > 255) throw new Error('That is not a key part. Paste the link or code you were given.')
  return { x: Number(m[1]), y: fromB64(m[2]) }
}

export interface SplitShare {
  ciphertext: string
  meta: E2eMeta
  dek: Uint8Array<ArrayBuffer>
  /** One code per key holder; put each in its own link as `#p=<code>`. */
  parts: string[]
}

export async function encryptShareSplit(payload: unknown, k: number, n: number): Promise<SplitShare> {
  const dek = random(32)
  const ct = await seal(dek, new TextEncoder().encode(JSON.stringify(payload)), AAD_CONTENT)
  return {
    ciphertext: toB64(ct),
    meta: { v: 1, alg: 'A256GCM', key: 'split', split: { k, n, check: await keyCheck(dek) } },
    dek,
    parts: split(dek, k, n).map(partCode),
  }
}

/** Combines key parts into the DEK, verifying it against the published check value. */
export async function dekFromParts(meta: Pick<E2eMeta, 'split'>, codes: string[]): Promise<Uint8Array<ArrayBuffer>> {
  if (!meta.split) throw new Error('This share is not split.')
  const parts = codes.map(parsePart)
  if (new Set(parts.map((p) => p.x)).size !== parts.length) throw new Error('The same key part was entered twice.')
  if (parts.length < meta.split.k) throw new Error(`${meta.split.k} key parts are needed.`)
  const dek = combine(parts)
  if (dek.length !== 32 || (await keyCheck(dek)) !== meta.split.check) {
    throw new Error("These key parts don't belong together. Check that each one was copied completely.")
  }
  return dek
}

/** Reads a split-key part from a URL fragment like `#p=2.abc`. */
export function partFromFragment(hash: string): string | undefined {
  return new URLSearchParams(hash.replace(/^#/, '')).get('p') ?? undefined
}

/** Reads `k` from a URL fragment like `#k=abc`. */
export function keyFromFragment(hash: string): string | undefined {
  return new URLSearchParams(hash.replace(/^#/, '')).get('k') ?? undefined
}
