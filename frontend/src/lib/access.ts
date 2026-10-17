import type { PolicyRule } from '../api/client'
import { policyToRows, rowsToPolicy, type RuleRow } from './policy'

export type AccessPreset = 'public' | 'owner' | 'custom'

export interface AccessState {
  preset: AccessPreset
  rules: RuleRow[]
  requireMfa: boolean
}

export const DEFAULT_ACCESS: AccessState = { preset: 'public', rules: [{ group: 'include', type: 'everyone', values: '' }], requireMfa: false }

export function accessToPolicy(a: AccessState): PolicyRule[] {
  if (a.preset === 'public') return [{ group: 'include', type: 'everyone' }]
  if (a.preset === 'owner') return [{ group: 'include', type: 'owner' }]
  return rowsToPolicy(a.rules)
}

/** Recognises the two presets; anything else opens in the rule editor. */
export function accessFromPolicy(policy: PolicyRule[], requireMfa: boolean): AccessState {
  const only = policy.length === 1 && policy[0].group === 'include' ? policy[0].type : null
  if (only === 'everyone') return { ...DEFAULT_ACCESS, requireMfa }
  if (only === 'owner') return { preset: 'owner', rules: DEFAULT_ACCESS.rules, requireMfa }
  return { preset: 'custom', rules: policyToRows(policy), requireMfa }
}
