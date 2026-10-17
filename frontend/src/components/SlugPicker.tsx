import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { api, ApiError, unwrap, type GeneratorInfo, type OptionField } from '../api/client'
import { entropyLabel } from '../lib/format'

export interface SlugChoice {
  generator: string
  options: Record<string, unknown>
}

function defaults(g: GeneratorInfo): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const o of g.options) if (o.type !== 'text') out[o.name] = o.default
  return out
}

export function SlugPicker({ value, onChange }: { value: SlugChoice | null; onChange: (v: SlugChoice) => void }) {
  const gens = useQuery({ queryKey: ['slug-generators'], queryFn: () => unwrap(api.GET('/api/slug-generators')) })
  const [preview, setPreview] = useState<{ url: string; entropy_bits: number } | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    if (!value && gens.data?.length) onChange({ generator: gens.data[0].id, options: defaults(gens.data[0]) })
  }, [gens.data, value, onChange])

  const current = gens.data?.find((g) => g.id === value?.generator)
  const optionsKey = JSON.stringify(value)

  useEffect(() => {
    if (!value) return
    let cancelled = false
    const t = setTimeout(async () => {
      try {
        const p = await unwrap(api.POST('/api/slug-generators/{id}/preview', { params: { path: { id: value.generator } }, body: { options: value.options } }))
        if (!cancelled) {
          setPreview(p)
          setPreviewError(null)
        }
      } catch (e) {
        if (!cancelled) {
          setPreview(null)
          setPreviewError(e instanceof ApiError ? e.message : String(e))
        }
      }
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(t)
    }
  }, [optionsKey, nonce]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!gens.data || !value) return <p className="hint">Loading link styles…</p>
  const strength = preview ? entropyLabel(preview.entropy_bits) : null

  return (
    <div className="slug-picker">
      <div className="segmented" role="radiogroup" aria-label="Link style">
        {gens.data.map((g) => (
          <button
            key={g.id}
            type="button"
            role="radio"
            aria-checked={g.id === value.generator}
            className={g.id === value.generator ? 'active' : ''}
            onClick={() => onChange({ generator: g.id, options: defaults(g) })}
            title={g.description}
          >
            {g.label}
          </button>
        ))}
      </div>
      {current && <p className="hint">{current.description}</p>}
      <div className="slug-options">
        {current?.options.map((o) => (
          <OptionInput key={o.name} field={o} value={value.options[o.name]} onChange={(v) => onChange({ ...value, options: { ...value.options, [o.name]: v } })} />
        ))}
      </div>
      <div className="slug-preview">
        {preview && (
          <>
            <code>{preview.url}</code>
            {!current?.user_supplied && (
              <button type="button" className="btn btn-small btn-ghost" onClick={() => setNonce((n) => n + 1)} title="Show another example">
                ↻
              </button>
            )}
            <span className={`badge ${strength?.weak ? 'badge-warn' : 'badge-ok'}`}>{strength?.label}</span>
          </>
        )}
        {previewError && <span className="note-error">{previewError}</span>}
      </div>
      {!current?.user_supplied && <p className="hint">Example only: the real link is generated when you create the share.</p>}
    </div>
  )
}

function OptionInput({ field, value, onChange }: { field: OptionField; value: unknown; onChange: (v: unknown) => void }) {
  switch (field.type) {
    case 'int':
      return (
        <label className="field-inline">
          {field.label}
          <input type="number" min={field.min} max={field.max} value={Number(value ?? field.default)} onChange={(e) => onChange(Number(e.target.value))} />
        </label>
      )
    case 'select':
      return (
        <label className="field-inline">
          {field.label}
          <select value={String(value ?? field.default)} onChange={(e) => onChange(e.target.value)}>
            {field.choices.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </label>
      )
    case 'text':
      return (
        <label className="field-inline grow">
          {field.label}
          <input value={String(value ?? '')} placeholder={field.placeholder} pattern={field.pattern} onChange={(e) => onChange(e.target.value)} required />
        </label>
      )
  }
}
