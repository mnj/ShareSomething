// ShareSomething service worker. Its only job: stream end-to-end-decrypted downloads to disk in
// browsers without the File System Access API. It caches nothing and ignores every other request.
//
// Protocol: the page sends {type: 'register-download', id, name, size} with a MessagePort, then
// navigates a hidden iframe to /__download/<id>. Each time the stream wants data we send 'pull' and
// the page answers with one decrypted chunk ('chunk'), 'end' or 'error' (backpressure: one chunk
// in flight). If the user cancels the download we send 'cancel'.

const pending = new Map()

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))

self.addEventListener('message', (event) => {
  const data = event.data || {}
  const port = event.ports[0]
  if (data.type !== 'register-download' || !port || typeof data.id !== 'string') return
  pending.set(data.id, { name: String(data.name || 'download'), size: data.size, port })
  // Forget registrations that never get fetched.
  setTimeout(() => pending.delete(data.id), 60_000)
  port.postMessage({ type: 'registered' })
})

function disposition(name) {
  const ascii = name.replace(/[^\x20-\x7e]|["%;\\]/g, '_')
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (url.origin !== self.location.origin || !url.pathname.startsWith('/__download/')) return
  const id = url.pathname.slice('/__download/'.length)
  const entry = pending.get(id)
  pending.delete(id)
  if (!entry) {
    event.respondWith(new Response('This download has expired.', { status: 404, headers: { 'Content-Type': 'text/plain' } }))
    return
  }
  const { port, name, size } = entry
  let wake = null
  const stream = new ReadableStream(
    {
      start(controller) {
        port.onmessage = ({ data }) => {
          if (data.type === 'chunk') controller.enqueue(new Uint8Array(data.chunk))
          else if (data.type === 'end') controller.close()
          else if (data.type === 'error') controller.error(new Error(data.message || 'download failed'))
          if (wake) {
            wake()
            wake = null
          }
        }
      },
      pull() {
        return new Promise((resolve) => {
          wake = resolve
          port.postMessage({ type: 'pull' })
        })
      },
      cancel() {
        port.postMessage({ type: 'cancel' })
      },
    },
    { highWaterMark: 1 },
  )
  const headers = new Headers({
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': disposition(name),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  })
  if (Number.isFinite(size)) headers.set('Content-Length', String(size))
  event.respondWith(new Response(stream, { headers }))
})
