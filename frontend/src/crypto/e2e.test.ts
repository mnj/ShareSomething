import { describe, expect, it } from 'vitest'
import { DecryptError, decryptShare, derivePassphraseKeys, encryptShare, fromB64, keyFromFragment, toB64 } from './e2e'

// Cheap KDF params so tests are fast; production uses DEFAULT_KDF.
const FAST = { m: 1024, t: 1, p: 1 }
const payload = { kind: 'credential', fields: [{ label: 'password', value: 'hunter2 🔑', secret: true }] }

describe('e2e', () => {
  it('round-trips with a fragment key', async () => {
    const enc = await encryptShare(payload)
    expect(enc.meta.key).toBe('fragment')
    expect(enc.verifier).toBeUndefined()
    expect(enc.fragmentKey).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(await decryptShare(enc.ciphertext, enc.meta, { fragmentKey: enc.fragmentKey })).toEqual(payload)
  })

  it('round-trips with a passphrase and produces a stable verifier', async () => {
    const enc = await encryptShare(payload, 'correct horse', FAST)
    expect(enc.meta.key).toBe('passphrase')
    expect(enc.fragmentKey).toBeUndefined()
    const { kek, verifier } = await derivePassphraseKeys('correct horse', enc.meta.kdf!)
    expect(toB64(verifier)).toBe(enc.verifier)
    expect(await decryptShare(enc.ciphertext, enc.meta, { kek })).toEqual(payload)
  })

  it('rejects a wrong passphrase', async () => {
    const enc = await encryptShare(payload, 'right', FAST)
    const { kek, verifier } = await derivePassphraseKeys('wrong', enc.meta.kdf!)
    expect(toB64(verifier)).not.toBe(enc.verifier)
    await expect(decryptShare(enc.ciphertext, enc.meta, { kek })).rejects.toBeInstanceOf(DecryptError)
  })

  it('rejects a wrong fragment key and tampered ciphertext', async () => {
    const enc = await encryptShare(payload)
    const other = await encryptShare(payload)
    await expect(decryptShare(enc.ciphertext, enc.meta, { fragmentKey: other.fragmentKey })).rejects.toBeInstanceOf(DecryptError)
    const ct = fromB64(enc.ciphertext)
    ct[ct.length - 1] ^= 1
    await expect(decryptShare(toB64(ct), enc.meta, { fragmentKey: enc.fragmentKey })).rejects.toBeInstanceOf(DecryptError)
    await expect(decryptShare(enc.ciphertext, enc.meta, {})).rejects.toThrow(/missing its key/)
  })

  it('reads the key from a fragment', () => {
    expect(keyFromFragment('#k=abc-_')).toBe('abc-_')
    expect(keyFromFragment('')).toBeUndefined()
  })
})
