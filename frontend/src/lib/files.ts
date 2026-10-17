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

declare global {
  interface Window {
    showSaveFilePicker?: (opts?: { suggestedName?: string }) => Promise<FileSystemFileHandle>
    showDirectoryPicker?: (opts?: { mode?: 'read' | 'readwrite' }) => Promise<FileSystemDirectoryHandle>
  }
}

/** Fetches (and for E2E decrypts) a file chunk by chunk, handing each plaintext chunk to `sink`. */
async function pipeFile(
  slug: string,
  token: string,
  idx: number,
  file: Schemas['FileEntry'],
  dek: Uint8Array<ArrayBuffer> | undefined,
  sink: (chunk: Uint8Array<ArrayBuffer>) => Promise<void> | void,
  onProgress: (p: Progress) => void,
): Promise<void> {
  const chunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE))
  let done = 0
  for (let n = 0; n < chunks; n++) {
    const res = await check(await fetch(`/api/s/${encodeURIComponent(slug)}/files/${idx}/chunks/${n}`, { headers: { 'x-download-token': token } }))
    const data = new Uint8Array(await res.arrayBuffer())
    const plain = dek ? await decryptChunk(dek, idx, n, n === chunks - 1, data) : data
    await sink(plain)
    done += plain.length
    onProgress({ done, total: file.size })
  }
  if (done !== file.size) throw new Error(`${file.name}: size mismatch, the download is incomplete`)
}

/** Downloads one file into a Blob. Holds the whole file in memory (fallback path). */
export async function downloadFile(
  slug: string,
  token: string,
  idx: number,
  file: Schemas['FileEntry'],
  dek: Uint8Array<ArrayBuffer> | undefined,
  onProgress: (p: Progress) => void,
): Promise<Blob> {
  const parts: Uint8Array<ArrayBuffer>[] = []
  await pipeFile(slug, token, idx, file, dek, (c) => void parts.push(c), onProgress)
  return new Blob(parts, { type: file.mime || 'application/octet-stream' })
}

/** Streams one file straight to disk via the File System Access API (constant memory). */
export async function downloadToHandle(
  handle: FileSystemFileHandle,
  slug: string,
  token: string,
  idx: number,
  file: Schemas['FileEntry'],
  dek: Uint8Array<ArrayBuffer> | undefined,
  onProgress: (p: Progress) => void,
): Promise<void> {
  const out = await handle.createWritable()
  try {
    await pipeFile(slug, token, idx, file, dek, (c) => out.write(c), onProgress)
    await out.close()
  } catch (e) {
    await out.abort().catch(() => {})
    throw e
  }
}

export const canSaveToDisk = () => typeof window.showSaveFilePicker === 'function'
export const canSaveToFolder = () => typeof window.showDirectoryPicker === 'function'

/** Files bigger than this are risky to assemble in memory. */
export const MEMORY_WARN_BYTES = 512 * 1024 * 1024

/** A name that is safe as a single path component in a chosen folder. */
export function safeFileName(name: string): string {
  // Control characters are exactly what we want to strip here.
  // eslint-disable-next-line no-control-regex
  return name.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/^\.+/, '_') || 'file'
}

/**
 * Server-mode files: submit a form so the server streams the decrypted file into the browser's
 * own download manager (no page memory, works in every browser).
 */
export function streamServerDownload(slug: string, idx: number, token: string, name: string) {
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = `/api/s/${encodeURIComponent(slug)}/files/${idx}/download`
  form.hidden = true
  for (const [k, v] of Object.entries({ token, name })) {
    const input = document.createElement('input')
    input.type = 'hidden'
    input.name = k
    input.value = v
    form.appendChild(input)
  }
  document.body.appendChild(form)
  form.submit()
  form.remove()
}

export const isAbort = (e: unknown) => e instanceof DOMException && e.name === 'AbortError'

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
