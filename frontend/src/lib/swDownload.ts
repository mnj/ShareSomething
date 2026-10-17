/**
 * Streams a download through the service worker (public/sw.js) so large E2E files are written to
 * disk without being held in memory. Used when the File System Access API isn't available
 * (Firefox, Safari). See sw.js for the message protocol.
 */

export function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return
  navigator.serviceWorker.register('/sw.js').catch((e) => console.warn('service worker unavailable', e))
}

const timeout = <T>(ms: number, value: T) => new Promise<T>((res) => setTimeout(() => res(value), ms))

/** The active worker, if this page can use it (not in private mode, registered, activated). */
export async function activeWorker(): Promise<ServiceWorker | null> {
  if (!('serviceWorker' in navigator) || typeof ReadableStream === 'undefined') return null
  const reg = await Promise.race([navigator.serviceWorker.ready, timeout(2000, null)])
  return reg?.active ?? null
}

export class StreamUnavailable extends Error {}

/**
 * Pipes chunks from `next` (null = done) into a browser download named `name`.
 * Rejects with StreamUnavailable if the worker never starts pulling (caller should fall back).
 */
export async function streamViaWorker(sw: ServiceWorker, name: string, size: number, next: () => Promise<Uint8Array<ArrayBuffer> | null>): Promise<void> {
  const id = crypto.randomUUID()
  const { port1, port2 } = new MessageChannel()
  const registered = new Promise<void>((resolve) => {
    port1.onmessage = (e) => e.data?.type === 'registered' && resolve()
  })
  sw.postMessage({ type: 'register-download', id, name, size }, [port2])
  if ((await Promise.race([registered.then(() => true), timeout(2000, false)])) === false) throw new StreamUnavailable('service worker did not respond')

  const iframe = document.createElement('iframe')
  iframe.hidden = true
  try {
    await new Promise<void>((resolve, reject) => {
      let started = false
      const watchdog = setTimeout(() => !started && reject(new StreamUnavailable('service worker did not intercept the download')), 5000)
      port1.onmessage = async ({ data }) => {
        if (data?.type === 'cancel') {
          clearTimeout(watchdog)
          reject(new DOMException('Download cancelled', 'AbortError'))
          return
        }
        if (data?.type !== 'pull') return
        started = true
        clearTimeout(watchdog)
        try {
          const chunk = await next()
          if (chunk) {
            port1.postMessage({ type: 'chunk', chunk: chunk.buffer }, [chunk.buffer])
          } else {
            port1.postMessage({ type: 'end' })
            resolve()
          }
        } catch (e) {
          port1.postMessage({ type: 'error', message: e instanceof Error ? e.message : String(e) })
          reject(e)
        }
      }
      iframe.src = `/__download/${id}`
      document.body.appendChild(iframe)
    })
  } finally {
    port1.close()
    // Give the browser a moment to finish handing the stream to its download manager.
    setTimeout(() => iframe.remove(), 5000)
  }
}
