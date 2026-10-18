/**
 * Shamir's secret sharing over GF(256) (AES polynomial x^8+x^4+x^3+x+1), byte by byte.
 * Any k of the n parts reconstruct the secret; k-1 parts reveal nothing about it.
 */

const EXP = new Uint8Array(510)
const LOG = new Uint8Array(256)
{
  let x = 1
  for (let i = 0; i < 255; i++) {
    EXP[i] = x
    LOG[x] = i
    // Multiply by the generator 3: x*3 = x ^ xtime(x).
    x ^= ((x << 1) ^ (x & 0x80 ? 0x11b : 0)) & 0xff
  }
  for (let i = 255; i < 510; i++) EXP[i] = EXP[i - 255]
}

const mul = (a: number, b: number) => (a && b ? EXP[LOG[a] + LOG[b]] : 0)
const div = (a: number, b: number) => {
  if (b === 0) throw new Error('division by zero')
  return a ? EXP[LOG[a] + 255 - LOG[b]] : 0
}

export interface Part {
  /** The x coordinate, 1..255. */
  x: number
  y: Uint8Array<ArrayBuffer>
}

export function split(secret: Uint8Array, k: number, n: number): Part[] {
  if (!(k >= 2 && n >= k && n <= 255)) throw new Error('need 2 <= k <= n <= 255')
  const parts: Part[] = Array.from({ length: n }, (_, i) => ({ x: i + 1, y: new Uint8Array(secret.length) }))
  const coeffs = new Uint8Array(k - 1)
  for (let b = 0; b < secret.length; b++) {
    crypto.getRandomValues(coeffs)
    for (const p of parts) {
      // Horner: ((c[k-2] * x + c[k-3]) * x + ...) * x + secret
      let acc = 0
      for (let c = k - 2; c >= 0; c--) acc = mul(acc, p.x) ^ coeffs[c]
      p.y[b] = mul(acc, p.x) ^ secret[b]
    }
  }
  return parts
}

export function combine(parts: Part[]): Uint8Array<ArrayBuffer> {
  if (parts.length < 2) throw new Error('need at least two parts')
  const xs = new Set(parts.map((p) => p.x))
  if (xs.size !== parts.length || xs.has(0)) throw new Error('duplicate or invalid key parts')
  const len = parts[0].y.length
  if (parts.some((p) => p.y.length !== len)) throw new Error('key parts have different lengths')
  const out = new Uint8Array(len)
  for (const [i, pi] of parts.entries()) {
    // Lagrange basis at 0: prod_{j != i} x_j / (x_j - x_i); subtraction is xor in GF(2^8).
    let basis = 1
    for (const [j, pj] of parts.entries()) if (i !== j) basis = mul(basis, div(pj.x, pj.x ^ pi.x))
    for (let b = 0; b < len; b++) out[b] ^= mul(pi.y[b], basis)
  }
  return out
}
