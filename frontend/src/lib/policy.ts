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
      case 'member':
        return { group, type }
      case 'group':
        return { group, type, groups: list.map(Number).filter(Boolean) }
      case 'user':
        return { group, type, users: list.map(Number).filter(Boolean) }
    }
  })
}

/** Inverse of rowsToPolicy, for loading saved templates into the editor. */
export function policyToRows(policy: PolicyRule[]): RuleRow[] {
  return policy.map((r): RuleRow => {
    switch (r.type) {
      case 'everyone':
      case 'owner':
        return { group: r.group, type: r.type, values: '' }
      case 'ip':
        return { group: r.group, type: r.type, values: r.cidrs.join(', ') }
      case 'country':
        return { group: r.group, type: r.type, values: r.countries.join(', ') }
      case 'email':
        return { group: r.group, type: r.type, values: r.emails.join(', '), method: r.methods?.[0] ?? '' }
      case 'email_domain':
        return { group: r.group, type: r.type, values: r.domains.join(', '), method: r.methods?.[0] ?? '' }
      case 'member':
        return { group: r.group, type: r.type, values: '' }
      case 'group':
        return { group: r.group, type: r.type, values: r.groups.join(', ') }
      case 'user':
        return { group: r.group, type: r.type, values: r.users.join(', ') }
    }
  })
}
