# AGENTS.md

Guidance for AI coding agents (and humans) working on ShareSomething.

## What this is

A self-hosted app for sharing text, links, credentials and files. Each share has its own
security settings: encryption mode (browser E2E or server-side), passphrase, expiry, view limit
(read once), owner MFA, and a Cloudflare-Access-style policy (include / require / exclude rules
on everyone, owner, IP/CIDR, country, email, email domain). There is one owner account. Recipients
are anonymous, or sign in with an emailed code or an OIDC/GitHub account when a share's rules
name specific people.

- `backend/`: Rust (axum 0.8, sqlx 0.8 + SQLite, utoipa 5). Single binary that also serves the
  embedded frontend (`rust-embed` of `frontend/dist`).
- `frontend/`: React 19 + TypeScript + Vite, TanStack Query, `openapi-fetch` with generated types.
- `deploy/`: compose files for cloudflared and Caddy. `Dockerfile` builds a distroless image.

## Commands

```sh
# Backend
cargo test                         # unit + HTTP integration tests (backend/src/tests.rs)
cargo clippy --all-targets         # must be warning-free
cargo fmt                          # max_width = 140 (rustfmt.toml)
SS_BASE_URL=http://localhost:5173 SS_DATA_DIR=./data cargo run      # dev server on :8080
SS_DATA_DIR=./data cargo run -- admin init                         # create owner (password + TOTP)

# Frontend (in frontend/)
npm run dev                        # Vite on :5173, proxies /api to :8080
npm test                           # vitest (E2E crypto)
npm run typecheck && npm run lint
npm run gen:api                    # regenerate src/api/openapi.json + schema.d.ts from the backend
npm run build                      # outputs frontend/dist, embedded by the next cargo build
```

In dev, `SS_BASE_URL` must be the Vite origin (`http://localhost:5173`), because share links are
built from it and the API rejects non-GET requests whose `Origin` doesn't match it.

## Layout (backend/src)

| Path | Purpose |
|---|---|
| `main.rs` | CLI (`serve`, `admin`, `openapi`, `healthcheck`) and server start-up |
| `config.rs` | figment config: defaults < TOML file < `SS_*` env (`__` for nesting) |
| `api.rs` | router assembly, OpenAPI doc, security headers, CSRF origin check |
| `auth/owner.rs` | owner login, sessions (cookie `ss_owner`), TOTP step-up; `Owner` extractor |
| `auth/passkey.rs` | owner WebAuthn passkeys (webauthn-rs): register, passwordless login, MFA step-up |
| `auth/recipient.rs` | recipient session (cookie `ss_recipient`) with verified identities; email codes; `Recipient` extractor |
| `auth/oidc.rs` | OIDC (discovery, PKCE, nonce, browser-bound state) and GitHub OAuth sign-in |
| `mailer.rs` | SMTP / log / disabled mailer for one-time codes |
| `shares/policy.rs` | **pure** access evaluator `evaluate(ShareState, AccessContext) -> Decision` |
| `shares/handlers.rs` | owner CRUD + recipient `GET /api/s/{slug}` and `POST /api/s/{slug}/open` |
| `shares/files.rs` | chunk upload (`x-upload-token`), finalize, chunk download (`x-download-token`) |
| `shares/templates.rs` | named, reusable access policies |
| `shares/store.rs` | SQL for shares, rules, atomic `consume_view`, `wipe`, access log |
| `blobs.rs` | on-disk chunk storage `data/blobs/<share>/<idx>.bin`, chunk math |
| `slug/` | pluggable link generators (`SlugGenerator` trait + `SlugRegistry`) |
| `net/client_ip.rs` | trusted-proxy-aware client IP (`none` / `cloudflare` / `forwarded`) |
| `crypto.rs` | server-mode envelope encryption (XChaCha20-Poly1305, HKDF, argon2id) |
| `jobs.rs` | sweeper: wipes expired content, purges old rows and sessions |

Migrations live in `backend/migrations/`. Add a new numbered file; never edit an applied one.

## Security invariants (don't break these)

1. **Every recipient path goes through `policy::evaluate`.** Don't add an endpoint that returns
   share content or metadata (title, kind) without it. Hide details unless the decision is `Allow`.
2. **Views are consumed only via `store::consume_view`** (conditional `UPDATE ... RETURNING`) and only
   *after* the passphrase/verifier check passes, so a typo can't burn a read-once share and
   concurrent opens can't both win the last view.
3. **`GET` never consumes a view.** Link-preview bots must not burn shares; content is released only
   by `POST /open` after an explicit Reveal click.
4. **E2E shares: the server never receives plaintext, the DEK or the passphrase.** The create
   handler rejects `payload`/`passphrase` for `enc_mode = e2e`. Before open, only `enc_meta.kdf` is
   exposed (never `wrapped_key`), so the passphrase can't be brute-forced offline without spending
   views. The fragment key (`#k=`) must never be sent to the server or logged.
5. **Forwarding headers are trusted only from `proxy.trusted_proxies`.** IP and country rules depend
   on it. Don't read `X-Forwarded-For` / `CF-Connecting-IP` anywhere else; use the `ClientInfo` extractor.
6. **Burned, revoked or expired content is wiped** (`ciphertext = NULL`), not just flagged. The row
   stays for the dashboard and the log until the retention purge.
7. Unknown, expired and burned slugs all return the same 404.
8. The CSP forbids inline scripts. Don't add inline `<script>`, and avoid `style` attributes
   (use classes in `index.css`). `'wasm-unsafe-eval'` exists only for hash-wasm (argon2id).
9. Links in shared content are rendered only when they are `http(s)` (checked on both server and client).
10. **File chunks are always encrypted at rest.** In server mode the DEK exists unwrapped only while
    a request runs. Between requests it is stored wrapped under the upload token (until finalize)
    or a recipient's download token, never on its own. A file share isn't openable while
    `upload_pending`.
11. **Email codes are only sent to addresses that could pass the share's policy**
    (`policy::email_could_satisfy`), and `email/start` answers identically either way. Don't add
    responses or timing that reveal which addresses have access.
12. **OIDC:** keep PKCE, the nonce check, the `ss_oidc_state` cookie binding and `safe_next()`
    (relative paths only). Only provider-verified emails become identities, unless the provider
    sets `trust_unverified_email`.
13. Identity rules may only name sign-in methods the server offers (`validate_policy`), so a share
    can't be created that nobody is able to open.
14. **Passkeys:** a passkey sign-in or step-up counts as fresh MFA. Adding or removing a passkey
    needs fresh MFA whenever a second factor exists. Ceremony state is single-use and expires
    after 5 minutes. WebAuthn needs `base_url` to be a domain name (https, or http://localhost);
    otherwise passkeys are disabled.
15. **CSRF check:** `Origin` must equal `base_url`'s origin. The one exception is `Origin: null`
    together with `Sec-Fetch-Site: same-origin`, which is what browsers send for our own form posts
    under `Referrer-Policy: no-referrer` (streamed file downloads). Don't loosen it further.
16. Large downloads must not be buffered in memory. Server-mode files stream through a form POST
    (`/files/{idx}/download`). E2E files stream through the File System Access API when the browser
    has it, and only fall back to a Blob otherwise.

## Common tasks

**Add a link (slug) style.** Implement `SlugGenerator` in a new `backend/src/slug/<name>.rs`, add
it to `registry::builtins`, and describe its options with `OptionField`s. The UI renders them
automatically. The registry conformance test (`slug/registry.rs`) runs against every
non-user-supplied generator, so keep the default entropy at 30 bits or more. Output may only
contain `[A-Za-z0-9._-]`.

**Add or change an API endpoint.** Annotate the handler with `#[utoipa::path(...)]` (paths are
relative to `/api`), register it with `routes!(...)` in the module's `router()`, derive `ToSchema`
on DTOs, then run `npm run gen:api` in `frontend/` and commit the regenerated `schema.d.ts` /
`openapi.json`. Add an integration test in `backend/src/tests.rs`.

**Add a policy rule type.** Add a variant to `Rule`, cover it in `normalise()`, `type_name()` and
`rule_match()`, add table tests in `policy.rs`, then update `frontend/src/lib/policy.ts`,
`components/PolicyEditor.tsx` and `lib/format.ts` (`describeRule`).

**Change the E2E format.** Bump `v` in `E2eMeta` and keep decrypting old versions. Shares created
by older clients must still open.

## Conventions

- Rust: return `AppResult<T>`; use `AppError::Access(code, msg)` for recipient-facing 403s with a
  stable `code` that the frontend switches on. Keep handlers thin and pure logic unit-testable.
- Times are Unix seconds (`i64`) everywhere (`util::now()`).
- Frontend: call the API through `api` + `unwrap()` from `src/api/client.ts`. Don't hand-write
  request or response types; use the generated `Schemas`.
- Tests are required for: policy decisions, anything touching view counting or burn, crypto
  formats, and client-IP resolution.
- Commits go directly on `main` in small, working increments. The message explains the why.

## Testing notes

- `backend/src/tests.rs` drives the real router: `TestApp::with_email` captures mail, and
  `mock_idp` is an in-process OpenID provider (RS256 key in `src/testdata/`, test-only) plus
  GitHub endpoints.
- Every OpenAPI `operationId` must be unique (there's a test for it). Set `operation_id = "..."`
  when two modules have handlers with the same function name.

## Build notes

- `webauthn-rs` depends on OpenSSL; `openssl` is built with the `vendored` feature so the musl
  binary stays static (the Docker build stage needs `perl make linux-headers`).
- Tests use `webauthn-authenticator-rs` (soft passkey) for real WebAuthn ceremonies.

## Roadmap

All five planned phases are done. Ideas for later: a service-worker streaming path for E2E
downloads in browsers without the File System Access API, TOTP enrollment from the UI, and share
editing (title/expiry/policy) from the dashboard.
