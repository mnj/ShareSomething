import type { PolicyRule, ShareSummary } from '../api/client'

export function formatTime(unix: number): string {
  return new Date(unix * 1000).toLocaleString()
}

export function formatRelative(unix: number): string {
  const diff = unix - Date.now() / 1000
  const abs = Math.abs(diff)
  const units: [number, string][] = [
    [86400, 'day'],
    [3600, 'hour'],
    [60, 'minute'],
  ]
  for (const [secs, name] of units) {
    if (abs >= secs) {
      const n = Math.round(abs / secs)
      const s = `${n} ${name}${n === 1 ? '' : 's'}`
      return diff > 0 ? `in ${s}` : `${s} ago`
    }
  }
  return diff > 0 ? 'in under a minute' : 'just now'
}

/** Optional id -> name lookups for group/user rules. */
export interface RuleNames {
  groups?: Map<number, string>
  users?: Map<number, string>
}

export function describeRule(r: PolicyRule, names?: RuleNames): string {
  switch (r.type) {
    case 'everyone':
      return 'anyone with the link'
    case 'owner':
      return 'only me'
    case 'ip':
      return `IP ${r.cidrs.join(', ')}`
    case 'country':
      return `country ${r.countries.join(', ')}`
    case 'email':
      return `email ${r.emails.join(', ')}`
    case 'email_domain':
      return `@${r.domains.join(', @')}`
    case 'member':
      return 'any team member'
    case 'group':
      return `group ${r.groups.map((g) => names?.groups?.get(g) ?? `#${g}`).join(', ')}`
    case 'user':
      return r.users.map((u) => names?.users?.get(u) ?? `user #${u}`).join(', ')
  }
}

export function describePolicy(policy: PolicyRule[], names?: RuleNames): string {
  const parts: string[] = []
  const d = (r: PolicyRule) => describeRule(r, names)
  const inc = policy.filter((r) => r.group === 'include').map(d)
  const req = policy.filter((r) => r.group === 'require').map(d)
  const exc = policy.filter((r) => r.group === 'exclude').map(d)
  if (inc.length) parts.push(inc.join(' or '))
  if (req.length) parts.push(`must match ${req.join(' and ')}`)
  if (exc.length) parts.push(`except ${exc.join(', ')}`)
  return parts.join('; ')
}

export function viewsLabel(s: Pick<ShareSummary, 'views' | 'max_views'>): string {
  if (s.max_views == null) return `${s.views} view${s.views === 1 ? '' : 's'}`
  return `${s.views} / ${s.max_views} views`
}

export function entropyLabel(bits: number): { label: string; weak: boolean } {
  if (bits === 0) return { label: 'guessable', weak: true }
  if (bits < 40) return { label: `${Math.round(bits)} bits: easy to guess`, weak: true }
  if (bits < 64) return { label: `${Math.round(bits)} bits`, weak: false }
  return { label: `${Math.round(bits)} bits: very hard to guess`, weak: false }
}
