import { useRef, useState } from 'react'
import { formatBytes } from '../lib/files'

export function FilePicker({ files, onChange }: { files: File[]; onChange: (f: File[]) => void }) {
  const input = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const add = (list: FileList | null) => {
    if (!list) return
    const known = new Set(files.map((f) => `${f.name}:${f.size}:${f.lastModified}`))
    onChange([...files, ...Array.from(list).filter((f) => !known.has(`${f.name}:${f.size}:${f.lastModified}`))])
  }
  const total = files.reduce((n, f) => n + f.size, 0)

  return (
    <div className="stack">
      <div
        className={`dropzone ${dragging ? 'dragging' : ''}`}
        role="button"
        tabIndex={0}
        onClick={() => input.current?.click()}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          add(e.dataTransfer.files)
        }}
      >
        Drop files here or click to choose
        <input ref={input} type="file" multiple hidden aria-label="Files" onChange={(e) => add(e.target.files)} />
      </div>
      {files.length > 0 && (
        <ul className="file-list">
          {files.map((f, i) => (
            <li key={`${f.name}-${i}`}>
              <span className="file-name">{f.name}</span>
              <span className="hint">{formatBytes(f.size)}</span>
              <button type="button" className="btn btn-small btn-ghost" onClick={() => onChange(files.filter((_, j) => j !== i))} aria-label={`Remove ${f.name}`}>
                ✕
              </button>
            </li>
          ))}
          <li className="hint">
            {files.length} file{files.length === 1 ? '' : 's'}, {formatBytes(total)}
          </li>
        </ul>
      )}
    </div>
  )
}
