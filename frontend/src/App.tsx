import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { api, unwrap } from './api/client'
import { useMe } from './lib/auth'
import { Dashboard } from './pages/Dashboard'
import { Login } from './pages/Login'
import { NewShare } from './pages/NewShare'
import { Settings } from './pages/Settings'
import { Audit } from './pages/Audit'
import { ShareView } from './pages/ShareView'

function Layout() {
  const me = useMe()
  const loc = useLocation()
  const unread = useQuery({
    queryKey: ['notifications'],
    queryFn: () => unwrap(api.GET('/api/notifications')),
    enabled: !!me.data?.authenticated,
    refetchInterval: 15_000,
  }).data?.unread
  const qc = useQueryClient()
  return (
    <>
      <header className="topbar">
        <Link to="/" className="brand">
          ShareSomething
        </Link>
        {me.data?.authenticated && (
          <nav className="row">
            <Link to="/" className="btn btn-small btn-ghost">
              Shares
              {!!unread && (
                <span className="badge badge-warn nav-count" aria-label={`${unread} unread notifications`}>
                  {unread}
                </span>
              )}
            </Link>
            {(me.data.user?.role === 'admin' || me.data.user?.role === 'auditor') && (
              <Link to="/audit" className="btn btn-small btn-ghost">
                Audit
              </Link>
            )}
            <Link to="/settings" className="btn btn-small btn-ghost">
              Settings
            </Link>
            <span className="hint user-label">{me.data.user?.email ?? me.data.user?.name}</span>
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
          </nav>
        )}
      </header>
      <main className={loc.pathname.startsWith('/audit') ? 'container wide' : 'container'}>
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
          <Route path="/settings" element={<Settings />} />
          <Route path="/audit" element={<Audit />} />
        </Route>
        <Route path="*" element={<p className="hint">Page not found.</p>} />
      </Route>
    </Routes>
  )
}
