import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap, type Schemas } from "../api/client";
import { CopyButton } from "../components/CopyButton";
import { ErrorNote } from "../components/ErrorNote";
import { useMe } from "../lib/auth";
import { describePolicy, formatRelative } from "../lib/format";

type Tab = "users" | "groups" | "policies" | "shares";
type Role = Schemas["Role"];

export function Admin() {
  const [tab, setTab] = useState<Tab>("users");
  return (
    <div className="stack">
      <h1>Administration</h1>
      <div className="segmented" role="tablist" aria-label="Admin sections">
        {(
          [
            ["users", "Users"],
            ["groups", "Groups"],
            ["policies", "Org policies"],
            ["shares", "All shares"],
          ] as const
        ).map(([t, label]) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={tab === t}
            className={tab === t ? "active" : ""}
            onClick={() => setTab(t)}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === "users" && <Users />}
      {tab === "groups" && <Groups />}
      {tab === "policies" && <OrgPolicies />}
      {tab === "shares" && <AllShares />}
    </div>
  );
}

function Users() {
  const qc = useQueryClient();
  const me = useMe();
  const users = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => unwrap(api.GET("/api/admin/users")),
  });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [lastInvite, setLastInvite] = useState<Schemas["InviteResult"] | null>(
    null,
  );
  const refresh = () => qc.invalidateQueries({ queryKey: ["admin-users"] });
  const invite = useMutation({
    mutationFn: () =>
      unwrap(api.POST("/api/admin/users", { body: { email, role } })),
    onSuccess: (r) => {
      setLastInvite(r);
      setEmail("");
      refresh();
    },
  });
  const action = useMutation({
    mutationFn: async (a: {
      id: number;
      kind: "role" | "status" | "reset-mfa" | "sign-out" | "reinvite";
      value?: string;
    }) => {
      const path = { params: { path: { id: a.id } } };
      if (a.kind === "role")
        return unwrap(
          api.PATCH("/api/admin/users/{id}", {
            ...path,
            body: { role: a.value as Role },
          }),
        );
      if (a.kind === "status")
        return unwrap(
          api.PATCH("/api/admin/users/{id}", {
            ...path,
            body: { status: a.value },
          }),
        );
      if (a.kind === "reset-mfa")
        return unwrap(api.POST("/api/admin/users/{id}/reset-mfa", path));
      if (a.kind === "sign-out")
        return unwrap(api.POST("/api/admin/users/{id}/sign-out", path));
      setLastInvite(
        await unwrap(api.POST("/api/admin/users/{id}/reinvite", path)),
      );
    },
    onSuccess: refresh,
  });

  return (
    <div className="stack">
      <form
        className="card inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          invite.mutate();
        }}
      >
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="name@company.com"
          aria-label="Email to invite"
          required
          className="grow"
        />
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
          aria-label="Role"
        >
          <option value="member">Member</option>
          <option value="admin">Admin</option>
          <option value="auditor">Auditor (read-only audit)</option>
        </select>
        <button className="btn btn-primary">Invite</button>
      </form>
      <ErrorNote error={invite.error ?? action.error} />
      {lastInvite && (
        <div className="note stack">
          <span>
            Invited <b>{lastInvite.user.email}</b>
            {lastInvite.emailed ? " (email sent)." : "."}
          </span>
          {lastInvite.invite_url ? (
            <div className="link-box">
              <code>{lastInvite.invite_url}</code>
              <CopyButton
                value={lastInvite.invite_url}
                label="Copy invite link"
              />
            </div>
          ) : (
            <span className="hint">
              They sign in with your company SSO; no password needed.
            </span>
          )}
        </div>
      )}
      <div className="card scroll-x">
        <table className="log admin-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Status</th>
              <th>Sign-in</th>
              <th>Last seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.data?.map((u) => {
              const self = u.id === me.data?.user?.id;
              return (
                <tr key={u.id}>
                  <td>
                    <b>{u.name}</b>
                    <br />
                    <span className="hint">{u.email ?? "—"}</span>
                  </td>
                  <td>
                    <select
                      value={u.role}
                      disabled={self}
                      aria-label={`Role of ${u.email}`}
                      onChange={(e) =>
                        action.mutate({
                          id: u.id,
                          kind: "role",
                          value: e.target.value,
                        })
                      }
                    >
                      <option value="member">member</option>
                      <option value="admin">admin</option>
                      <option value="auditor">auditor</option>
                    </select>
                  </td>
                  <td>
                    <span
                      className={`badge badge-${u.status === "active" ? "ok" : u.status === "invited" ? "warn" : "revoked"}`}
                    >
                      {u.status}
                    </span>
                  </td>
                  <td className="hint">
                    {u.sso_provider ? `SSO (${u.sso_provider})` : "password"}
                    {u.totp ? " · TOTP" : ""}
                    {u.passkeys
                      ? ` · ${u.passkeys} passkey${u.passkeys === 1 ? "" : "s"}`
                      : ""}
                  </td>
                  <td className="hint">
                    {u.last_login_at
                      ? formatRelative(u.last_login_at)
                      : "never"}
                  </td>
                  <td>
                    <div className="row wrap">
                      {u.status === "invited" && (
                        <button
                          type="button"
                          className="btn btn-small"
                          onClick={() =>
                            action.mutate({ id: u.id, kind: "reinvite" })
                          }
                        >
                          New invite link
                        </button>
                      )}
                      {!self && (
                        <button
                          type="button"
                          className="btn btn-small btn-ghost"
                          onClick={() =>
                            action.mutate({
                              id: u.id,
                              kind: "status",
                              value:
                                u.status === "disabled" ? "active" : "disabled",
                            })
                          }
                        >
                          {u.status === "disabled" ? "Enable" : "Disable"}
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn btn-small btn-ghost"
                        onClick={() =>
                          confirm(
                            `Sign ${u.email ?? u.name} out everywhere?`,
                          ) && action.mutate({ id: u.id, kind: "sign-out" })
                        }
                      >
                        Sign out
                      </button>
                      {(u.totp || u.passkeys > 0) && (
                        <button
                          type="button"
                          className="btn btn-small btn-danger"
                          onClick={() =>
                            confirm(
                              `Remove ${u.email ?? u.name}'s authenticator and passkeys?`,
                            ) && action.mutate({ id: u.id, kind: "reset-mfa" })
                          }
                        >
                          Reset MFA
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Groups() {
  const qc = useQueryClient();
  const groups = useQuery({
    queryKey: ["groups"],
    queryFn: () => unwrap(api.GET("/api/groups")),
  });
  const people = useQuery({
    queryKey: ["directory"],
    queryFn: () => unwrap(api.GET("/api/directory/users")),
  });
  const [name, setName] = useState("");
  const [editing, setEditing] = useState<{
    id: number;
    members: number[];
  } | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["groups"] });
  const create = useMutation({
    mutationFn: () =>
      unwrap(api.POST("/api/groups", { body: { name, description: "" } })),
    onSuccess: () => {
      setName("");
      refresh();
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) =>
      unwrap(api.DELETE("/api/groups/{id}", { params: { path: { id } } })),
    onSuccess: refresh,
  });
  const saveMembers = useMutation({
    mutationFn: (e: { id: number; members: number[] }) =>
      unwrap(
        api.PUT("/api/groups/{id}/members", {
          params: { path: { id: e.id } },
          body: { user_ids: e.members },
        }),
      ),
    onSuccess: () => {
      setEditing(null);
      refresh();
    },
  });
  const startEdit = async (id: number) => {
    const m = await unwrap(
      api.GET("/api/groups/{id}/members", { params: { path: { id } } }),
    );
    setEditing({ id, members: m.user_ids });
  };
  return (
    <div className="stack">
      <form
        className="card inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Group name, e.g. Finance"
          aria-label="New group name"
          required
          className="grow"
        />
        <button className="btn btn-primary">Create group</button>
      </form>
      <ErrorNote error={create.error ?? remove.error ?? saveMembers.error} />
      {groups.data?.map((g) => (
        <div key={g.id} className="card stack">
          <div className="row spread">
            <b>{g.name}</b>
            <div className="row">
              <span className="hint">{g.members} members</span>
              <button
                type="button"
                className="btn btn-small"
                onClick={() => startEdit(g.id)}
              >
                Members
              </button>
              <button
                type="button"
                className="btn btn-small btn-ghost"
                onClick={() =>
                  confirm(`Delete group ${g.name}?`) && remove.mutate(g.id)
                }
              >
                Delete
              </button>
            </div>
          </div>
          {editing?.id === g.id && (
            <div className="stack">
              <div className="member-grid">
                {people.data?.map((u) => (
                  <label key={u.id} className="check">
                    <input
                      type="checkbox"
                      checked={editing.members.includes(u.id)}
                      onChange={(e) =>
                        setEditing({
                          ...editing,
                          members: e.target.checked
                            ? [...editing.members, u.id]
                            : editing.members.filter((x) => x !== u.id),
                        })
                      }
                    />
                    {u.name} <span className="hint">{u.email}</span>
                  </label>
                ))}
              </div>
              <div className="row">
                <button
                  type="button"
                  className="btn btn-primary btn-small"
                  onClick={() => saveMembers.mutate(editing)}
                >
                  Save members
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-small"
                  onClick={() => setEditing(null)}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function OrgPolicies() {
  const qc = useQueryClient();
  const current = useQuery({
    queryKey: ["org-settings"],
    queryFn: () => unwrap(api.GET("/api/org/settings")),
  });
  const gens = useQuery({
    queryKey: ["slug-generators"],
    queryFn: () => unwrap(api.GET("/api/slug-generators")),
  });
  const [draft, setDraft] = useState<Schemas["OrgSettings"] | null>(null);
  const s = draft ?? current.data;
  const save = useMutation({
    mutationFn: (v: Schemas["OrgSettings"]) =>
      unwrap(api.PUT("/api/org/settings", { body: v })),
    onSuccess: (v) => {
      qc.setQueryData(["org-settings"], v);
      setDraft(null);
    },
  });
  if (!s) return <p className="hint">Loading…</p>;
  const set = (patch: Partial<Schemas["OrgSettings"]>) =>
    setDraft({ ...s, ...patch });
  const num = (v: string) => (v.trim() ? Number(v) : null);
  return (
    <form
      className="card stack"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate(s);
      }}
    >
      <p className="hint">
        These rules apply to every new or edited share and are enforced by the
        server. Changes are audited.
      </p>
      <label className="check">
        <input
          type="checkbox"
          checked={s.require_mfa}
          onChange={(e) => set({ require_mfa: e.target.checked })}
        />
        Require a passkey or authenticator app before people can share (SSO
        accounts rely on the identity provider)
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={s.force_e2e}
          onChange={(e) => set({ force_e2e: e.target.checked })}
        />
        Require end-to-end encryption
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={!s.allow_public_shares}
          onChange={(e) => set({ allow_public_shares: !e.target.checked })}
        />
        Forbid "anyone with the link" shares (every share needs an access rule)
      </label>
      <div className="grid-2">
        <label className="field">
          Longest lifetime (days) <span className="hint">empty = no limit</span>
          <input
            type="number"
            min={1}
            max={366}
            value={s.max_expiry_days ?? ""}
            onChange={(e) => set({ max_expiry_days: num(e.target.value) })}
          />
        </label>
        <label className="field">
          Highest view limit <span className="hint">empty = no limit</span>
          <input
            type="number"
            min={1}
            max={10000}
            value={s.max_views ?? ""}
            onChange={(e) => set({ max_views: num(e.target.value) })}
          />
        </label>
      </div>
      <label className="field">
        Allowed recipient domains{" "}
        <span className="hint">for email rules; empty = any</span>
        <input
          value={s.allowed_recipient_domains.join(", ")}
          onChange={(e) =>
            set({
              allowed_recipient_domains: e.target.value
                .split(/[\s,]+/)
                .filter(Boolean),
            })
          }
          placeholder="company.com, partner.com"
        />
      </label>
      <fieldset className="stack plain">
        <legend>Allowed link styles (none ticked = all)</legend>
        <div className="row wrap">
          {gens.data?.map((g) => (
            <label key={g.id} className="check">
              <input
                type="checkbox"
                checked={s.allowed_slug_generators.includes(g.id)}
                onChange={(e) =>
                  set({
                    allowed_slug_generators: e.target.checked
                      ? [...s.allowed_slug_generators, g.id]
                      : s.allowed_slug_generators.filter((x) => x !== g.id),
                  })
                }
              />
              {g.label}
            </label>
          ))}
        </div>
      </fieldset>
      <ErrorNote error={save.error} />
      <div className="row">
        <button className="btn btn-primary" disabled={!draft || save.isPending}>
          Save policies
        </button>
        {save.isSuccess && !draft && (
          <span className="badge badge-ok">saved</span>
        )}
      </div>
    </form>
  );
}

function AllShares() {
  const qc = useQueryClient();
  const shares = useQuery({
    queryKey: ["admin-shares"],
    queryFn: () => unwrap(api.GET("/api/admin/shares")),
  });
  const revoke = useMutation({
    mutationFn: (id: string) =>
      unwrap(
        api.POST("/api/admin/shares/{id}/revoke", { params: { path: { id } } }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-shares"] }),
  });
  return (
    <div className="stack">
      <p className="hint">
        Settings and status only. Content is never visible to admins.
      </p>
      <ErrorNote error={revoke.error} />
      <div className="card scroll-x">
        <table className="log admin-table">
          <thead>
            <tr>
              <th>Share</th>
              <th>Owner</th>
              <th>Status</th>
              <th>Access</th>
              <th>Views</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {shares.data?.map(({ share: s, owner }) => (
              <tr key={s.id}>
                <td>
                  <b>{s.title ?? s.slug}</b>
                  <br />
                  <span className="hint">
                    {s.kind} · {s.enc_mode}
                  </span>
                </td>
                <td>{owner}</td>
                <td>
                  <span className={`badge badge-${s.status}`}>{s.status}</span>
                </td>
                <td className="hint">{describePolicy(s.policy)}</td>
                <td>
                  {s.views}
                  {s.max_views ? ` / ${s.max_views}` : ""}
                </td>
                <td className="hint">{formatRelative(s.created_at)}</td>
                <td>
                  {s.status === "active" && (
                    <button
                      type="button"
                      className="btn btn-small btn-danger"
                      onClick={() =>
                        confirm(`Revoke "${s.title ?? s.slug}"?`) &&
                        revoke.mutate(s.id)
                      }
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
