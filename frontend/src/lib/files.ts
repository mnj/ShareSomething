import { ApiError, type Schemas } from '../api/client'
import { CHUNK_SIZE, decryptChunk, encryptChunk } from '../crypto/e2e'

export interface Progress {
  done: number
  total: number
}

async function check(res: Response): Promise<Response> {
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as Partial<Schemas['ErrorBody']>
    throw new ApiError(res.status, body.error ?? `http_${res.status}`, body.message ?? res.statusText)
  }
  return res
}

/**
 * Uploads every file chunk by chunk. With a DEK (E2E) chunks are encrypted in the browser;
 * without one (server mode) plaintext goes over TLS and the server encrypts it.
 */
export async function uploadFiles(
  shareId: string,
  uploadToken: string,
  files: File[],
  plan: Schemas['FileUploadInfo'][],
  dek: Uint8Array<ArrayBuffer> | undefined,
  onProgress: (p: Progress) => void,
): Promise<void> {
  const total = files.reduce((n, f) => n + f.size, 0)
  let done = 0
  onProgress({ done, total })
  for (const info of plan) {
    const file = files[info.idx]
    for (let n = 0; n < info.chunk_count; n++) {
      const slice = new Uint8Array(await file.slice(n * CHUNK_SIZE, (n + 1) * CHUNK_SIZE).arrayBuffer())
      const last = n === info.chunk_count - 1
      const body = dek ? await encryptChunk(dek, info.idx, n, last, slice) : slice
      await uploadWithRetry(`/api/shares/${shareId}/files/${info.idx}/chunks/${n}`, uploadToken, body)
      done += slice.length
      onProgress({ done, total })
    }
  }
  await check(await fetch(`/api/shares/${shareId}/finalize`, { method: 'POST', headers: { 'x-upload-token': uploadToken } }))
}

async function uploadWithRetry(url: string, token: string, body: Uint8Array<ArrayBuffer>, attempts = 3): Promise<void> {
  for (let i = 1; ; i++) {
    try {
      await check(await fetch(url, { method: 'PUT', headers: { 'x-upload-token': token, 'content-type': 'application/octet-stream' }, body }))
      return
    } catch (e) {
      // Only network errors and 5xx are worth retrying; the server accepts re-sent chunks.
      const retryable = !(e instanceof ApiError) || e.status >= 500
      if (!retryable || i >= attempts) throw e
      await new Promise((r) => setTimeout(r, 500 * i))
    }
  }
}

/** Downloads (and for E2E decrypts) one file into a Blob. Holds the whole file in memory. */
export async function downloadFile(
  slug: string,
  token: string,
  idx: number,
  file: Schemas['FileEntry'],
  dek: Uint8Array<ArrayBuffer> | undefined,
  onProgress: (p: Progress) => void,
): Promise<Blob> {
  const chunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE))
  const parts: Uint8Array<ArrayBuffer>[] = []
  let done = 0
  for (let n = 0; n < chunks; n++) {
    const res = await check(await fetch(`/api/s/${encodeURIComponent(slug)}/files/${idx}/chunks/${n}`, { headers: { 'x-download-token': token } }))
    const data = new Uint8Array(await res.arrayBuffer())
    const plain = dek ? await decryptChunk(dek, idx, n, n === chunks - 1, data) : data
    parts.push(plain)
    done += plain.length
    onProgress({ done, total: file.size })
  }
  if (done !== file.size) throw new Error(`${file.name}: size mismatch, the download is incomplete`)
  return new Blob(parts, { type: file.mime || 'application/octet-stream' })
}

export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KiB', 'MiB', 'GiB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`
}
