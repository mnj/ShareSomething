import { useQuery } from '@tanstack/react-query'
import { api, unwrap } from '../api/client'

export function useMe() {
  return useQuery({ queryKey: ['me'], queryFn: () => unwrap(api.GET('/api/auth/me')), staleTime: 30_000 })
}
