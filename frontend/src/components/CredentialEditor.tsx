import type { Schemas } from '../api/client'

type Field = Schemas['CredentialField']

export function CredentialEditor({ fields, onChange }: { fields: Field[]; onChange: (f: Field[]) => void }) {
  const update = (i: number, patch: Partial<Field>) => onChange(fields.map((f, j) => (i === j ? { ...f, ...patch } : f)))
  return (
    <div className="cred-editor">
      {fields.map((f, i) => (
        <div className="cred-row" key={i}>
          <input value={f.label} placeholder="Label" onChange={(e) => update(i, { label: e.target.value })} aria-label="Field label" />
          <input
            value={f.value}
            placeholder="Value"
            type={f.secret ? 'password' : 'text'}
            autoComplete="off"
            onChange={(e) => update(i, { value: e.target.value })}
            aria-label="Field value"
          />
          <label className="check" title="Mask this value until the recipient reveals it">
            <input type="checkbox" checked={!!f.secret} onChange={(e) => update(i, { secret: e.target.checked })} /> secret
          </label>
          <button type="button" className="btn btn-small btn-ghost" disabled={fields.length === 1} onClick={() => onChange(fields.filter((_, j) => j !== i))} aria-label="Remove field">
            ✕
          </button>
        </div>
      ))}
      <button type="button" className="btn btn-small" onClick={() => onChange([...fields, { label: '', value: '', secret: false }])}>
        + Add field
      </button>
    </div>
  )
}
