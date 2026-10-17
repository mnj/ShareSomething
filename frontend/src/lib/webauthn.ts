/**
 * Bridges webauthn-rs JSON (binary fields as base64url) and the browser's WebAuthn API
 * (ArrayBuffers), in both directions.
 */
import { fromB64, toB64Url } from '../crypto/e2e'

type Json = Record<string, unknown>

/** webauthn-rs emits `null` for absent optional members; browsers reject some of those. */
function stripNulls<T>(v: T): T {
  if (Array.isArray(v)) return v.map(stripNulls) as T
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v).filter(([, x]) => x !== null).map(([k, x]) => [k, stripNulls(x)])) as T
  }
  return v
}

const buf = (b64u: string) => fromB64(b64u)
const enc = (b: ArrayBuffer) => toB64Url(new Uint8Array(b))
const withIds = (list?: Json[]) => list?.map((c) => ({ ...c, id: buf(c.id as string) }))

export function webauthnSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials
}

export async function createPasskey(options: Json): Promise<Json> {
  const pk = stripNulls(options.publicKey as Json)
  const user = pk.user as Json
  const publicKey = {
    ...pk,
    challenge: buf(pk.challenge as string),
    user: { ...user, id: buf(user.id as string) },
    excludeCredentials: withIds(pk.excludeCredentials as Json[] | undefined),
  } as unknown as PublicKeyCredentialCreationOptions
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null
  if (!cred) throw new Error('No passkey was created.')
  const r = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: enc(cred.rawId),
    type: cred.type,
    extensions: {},
    response: { attestationObject: enc(r.attestationObject), clientDataJSON: enc(r.clientDataJSON), transports: r.getTransports?.() ?? [] },
  }
}

export async function getPasskey(options: Json): Promise<Json> {
  const pk = stripNulls(options.publicKey as Json)
  const publicKey = {
    ...pk,
    challenge: buf(pk.challenge as string),
    allowCredentials: withIds(pk.allowCredentials as Json[] | undefined),
  } as unknown as PublicKeyCredentialRequestOptions
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null
  if (!cred) throw new Error('No passkey was used.')
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: enc(cred.rawId),
    type: cred.type,
    extensions: {},
    response: {
      authenticatorData: enc(r.authenticatorData),
      clientDataJSON: enc(r.clientDataJSON),
      signature: enc(r.signature),
      userHandle: r.userHandle ? enc(r.userHandle) : null,
    },
  }
}

/** A cancelled/timed-out prompt surfaces as NotAllowedError; show something friendlier. */
export function passkeyError(e: unknown): unknown {
  if (e instanceof DOMException && e.name === 'NotAllowedError') return new Error('The passkey prompt was cancelled or timed out.')
  return e
}
