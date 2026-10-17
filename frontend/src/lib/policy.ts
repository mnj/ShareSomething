import type { PolicyRule, Schemas } from '../api/client'

export type RuleType = PolicyRule['type']

/** Editable form state for one policy rule; `values` is a comma/space separated list. */
export interface RuleRow {
  group: Schemas['RuleGroup']
  type: RuleType
  values: string
  /** Email/domain rules: required sign-in method id, '' = any configured method. */
  method?: string
}

function splitList(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}

export function rowsToPolicy(rows: RuleRow[]): PolicyRule[] {
  return rows.map(({ group, type, values, method }): PolicyRule => {
    const list = splitList(values)
    const methods = method ? [method] : []
    switch (type) {
      case 'everyone':
      case 'owner':
        return { group, type }
      case 'ip':
        return { group, type, cidrs: list }
      case 'country':
        return { group, type, countries: list }
      case 'email':
        return { group, type, emails: list, methods }
      case 'email_domain':
        return { group, type, domains: list, methods }
    }
  })
}
