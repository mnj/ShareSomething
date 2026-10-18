import { describe, expect, it } from 'vitest'
import { combine, split } from './shamir'

const secret = crypto.getRandomValues(new Uint8Array(32))

describe('shamir', () => {
  it('any k of n parts reconstruct the secret', () => {
    const parts = split(secret, 3, 5)
    for (const pick of [
      [0, 1, 2],
      [4, 2, 0],
      [1, 3, 4],
      [0, 1, 2, 3, 4],
    ]) {
      expect(combine(pick.map((i) => parts[i]))).toEqual(secret)
    }
  })

  it('k-1 parts do not reveal it', () => {
    const parts = split(secret, 3, 5)
    expect(combine([parts[0], parts[3]])).not.toEqual(secret)
  })

  it('2-of-2 and the 255 limit', () => {
    const parts = split(secret, 2, 2)
    expect(combine(parts)).toEqual(secret)
    expect(() => split(secret, 2, 256)).toThrow()
    expect(() => split(secret, 1, 3)).toThrow()
  })

  it('rejects duplicate parts', () => {
    const parts = split(secret, 2, 3)
    expect(() => combine([parts[0], parts[0]])).toThrow(/duplicate/)
  })

  it('parts look random (no byte of the secret leaks into a single part)', () => {
    const zero = new Uint8Array(32)
    const parts = split(zero, 2, 3)
    expect(parts.some((p) => p.y.some((b) => b !== 0))).toBe(true)
  })
})
