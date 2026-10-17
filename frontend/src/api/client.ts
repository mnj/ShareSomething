import createClient from 'openapi-fetch'
import type { components, paths } from './schema'

export type Schemas = components['schemas']
export type ShareSummary = Schemas['ShareSummary']
export type ShareInfo = Schemas['ShareInfo']
export type SharePayload = Schemas['SharePayload']
export type PolicyRule = Schemas['PolicyRule']
export type GeneratorInfo = Schemas['GeneratorInfo']
export type OptionField = Schemas['OptionField']

export const api = createClient<paths>({ baseUrl: '', credentials: 'same-origin' })

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

/** Resolves an openapi-fetch call to its data, throwing ApiError on non-2xx. */
export async function unwrap<T>(call: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  const { data, error, response } = await call
  if (!response.ok) {
    const body = (error ?? {}) as Partial<Schemas['ErrorBody']>
    throw new ApiError(response.status, body.error ?? `http_${response.status}`, body.message ?? response.statusText)
  }
  return data as T
}
