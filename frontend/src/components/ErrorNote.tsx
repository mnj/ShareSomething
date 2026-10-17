export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof Error ? error.message : String(error)
  return (
    <p className="note note-error" role="alert">
      {msg}
    </p>
  )
}
