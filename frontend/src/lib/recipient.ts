import { useQuery } from '@tanstack/react-query'
import { api, unwrap } from '../api/client'

export function useAuthMethods() {
  return useQuery({ queryKey: ['auth-methods'], queryFn: () => unwrap(api.GET('/api/recipient/methods')), staleTime: 300_000 })
}

export function useRecipient() {
  return useQuery({ queryKey: ['recipient'], queryFn: () => unwrap(api.GET('/api/recipient/me')) })
}

// The E2E key lives in the URL fragment, which is lost when bouncing through an identity
// provider. Park it in this tab's sessionStorage for the round trip.
const stashKey = (slug: string) => `ss_k:${slug}`

export function stashFragmentKey(slug: string, key: string | undefined) {
  if (!key) return
  try {
    sessionStorage.setItem(stashKey(slug), key)
  } catch {
    // storage unavailable: the user can reopen the original link
  }
}

export function readStashedKey(slug: string): string | undefined {
  try {
    return sessionStorage.getItem(stashKey(slug)) ?? undefined
  } catch {
    return undefined
  }
}

export function clearStashedKey(slug: string) {
  try {
    sessionStorage.removeItem(stashKey(slug))
  } catch {
    // ignore
  }
}

export const AUTH_ERRORS: Record<string, string> = {
  cancelled: 'Sign-in was cancelled.',
  expired: 'The sign-in attempt expired. Please try again.',
  no_verified_email: "That account doesn't have a verified email address.",
  failed: 'Sign-in failed. Please try again.',
}
