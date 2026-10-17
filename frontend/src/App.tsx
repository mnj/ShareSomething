import { useQueryClient } from '@tanstack/react-query'
import { Link, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { api, unwrap } from './api/client'
import { useMe } from './lib/auth'
import { Dashboard } from './pages/Dashboard'
import { Login } from './pages/Login'
import { NewShare } from './pages/NewShare'
import { ShareView } from './pages/ShareView'

function Layout() {
  const me = useMe()
  const qc = useQueryClient()
  return (
    <>
      <header className="topbar">
        <Link to="/" className="brand">
          ShareSomething
        </Link>
        {me.data?.authenticated && (
          <button
            type="button"
            className="btn btn-small btn-ghost"
            onClick={async () => {
              qc.setQueryData(['me'], await unwrap(api.POST('/api/auth/logout')))
              qc.removeQueries({ queryKey: ['shares'] })
            }}
          >
            Sign out
          </button>
        )}
      </header>
      <main className="container">
        <Outlet />
      </main>
    </>
  )
}

function RequireOwner() {
  const me = useMe()
  const loc = useLocation()
  if (me.isPending) return <p className="hint">Loading…</p>
  if (!me.data?.authenticated) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname)}`} replace />
  return <Outlet />
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/s/:slug" element={<ShareView />} />
        <Route path="/login" element={<Login />} />
        <Route element={<RequireOwner />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/new" element={<NewShare />} />
        </Route>
        <Route path="*" element={<p className="hint">Page not found.</p>} />
      </Route>
    </Routes>
  )
}
