# ShareSomething

Self-hosted sharing of text, links and credentials, where **every share gets its own security
settings** instead of one global setting.

- Move an API key between your own PCs: **only me**, behind password + fresh TOTP, read once.
- Send a Wi-Fi password to a guest: short link `/s/wifi-guest`, passphrase told in person, expires tonight.
- Share a doc link with your team: anyone from the office IP range, unlimited views, for 30 days.

## Features

- **Per-share encryption**
  - *End-to-end*: encrypted in the browser (AES-256-GCM). The key travels in the link's `#fragment`
    or is derived from a passphrase (argon2id). The server only stores ciphertext.
  - *Server-side*: per-share key wrapped with a master key, with the passphrase optionally mixed in.
- **Burn after reading / N views and expiry.** Content is wiped, not just hidden. Link previews from
  chat apps can't burn a share, because opening needs an explicit *Reveal*.
- **Access policies**, modelled on Cloudflare Access: *Allow if* (any) / *Require* (all) / *Block if*
  rules on everyone, owner, IP/CIDR, country, email and email domain.
- **Owner MFA per share**: require a fresh authenticator code to open a specific share.
- **Pluggable link styles**: `k7m2qx9d`, `monkey-space-sun-earth`, `bafoki-turesa`, or your own
  `wifi-guest`, with an entropy hint for each.
- **Access log** per share (time, IP, country, outcome).
- **Built for running behind cloudflared or a reverse proxy**: trusted-proxy aware client IP,
  single static binary, distroless image, a SQLite file in `/data`.

## Run it

### Docker + Cloudflare Tunnel

```sh
# Create a tunnel in Cloudflare Zero Trust with a public hostname -> http://sharesomething:8080
# then set SS_BASE_URL in deploy/compose.cloudflared.yml to that hostname.
TUNNEL_TOKEN=... docker compose -f deploy/compose.cloudflared.yml up -d
docker compose -f deploy/compose.cloudflared.yml exec sharesomething sharesomething admin init
```

### Docker + Caddy

Edit `deploy/Caddyfile` and `SS_BASE_URL`, then:

```sh
docker compose -f deploy/compose.caddy.yml up -d
docker compose -f deploy/compose.caddy.yml exec sharesomething sharesomething admin init
```

### Plain container

```sh
docker build -t sharesomething .
docker run -d --name sharesomething -p 8080:8080 -v ss-data:/data \
  -e SS_BASE_URL=https://share.example.com sharesomething
docker exec -it sharesomething sharesomething admin init
```

`admin init` asks for a password and shows a QR code for your authenticator app. For scripted
setups, set `SS_ADMIN_PASSWORD` and run it without a TTY; the TOTP secret is then printed without
asking for a confirmation code. Other commands: `admin set-password` and `admin reset-totp [--disable]`.

## Configuration

Environment variables (`SS_*`) or a TOML file (`--config`). See
[`config.example.toml`](config.example.toml) for every option. The important ones:

| Variable | Meaning |
|---|---|
| `SS_BASE_URL` | Public URL. Used for links and the CSRF origin check, and enables Secure cookies when https |
| `SS_PROXY__MODE` | `none`, `cloudflare` (CF-Connecting-IP) or `forwarded` (X-Forwarded-For) |
| `SS_PROXY__TRUSTED_PROXIES` | CIDRs allowed to set those headers, e.g. the tunnel's docker network |
| `SS_MASTER_KEY` | Base64 32-byte key for server-side encryption (otherwise generated in `/data/master.key`) |
| `SS_DATA_DIR` | Where the SQLite database lives (`/data` in the image) |

**Back up `/data`**, including `master.key` if you didn't set `SS_MASTER_KEY`. Without the master key,
server-mode shares can't be decrypted. E2E shares never depend on it.

## Security model in short

- E2E shares: the server never sees plaintext, the key or the passphrase. A passphrase-derived
  *verifier* lets the server refuse wrong passphrases before spending a view, so a typo doesn't burn a
  read-once share. Too many wrong attempts destroy the share.
- Forwarding headers are ignored unless the TCP peer is a trusted proxy, so IP rules can't be
  bypassed by spoofing `X-Forwarded-For`.
- Owner sessions use HttpOnly, SameSite=Strict cookies plus an Origin check. TOTP codes can't be replayed.
- Strict CSP, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on all API responses.

## Development

```sh
# terminal 1: backend
SS_DATA_DIR=./data SS_ADMIN_PASSWORD='dev-password-123' cargo run -- admin init
SS_DATA_DIR=./data SS_BASE_URL=http://localhost:5173 cargo run

# terminal 2: frontend
cd frontend && npm install && npm run dev      # http://localhost:5173
```

Tests: `cargo test` and `cd frontend && npm test`. After changing API types, run `npm run gen:api`.
See [AGENTS.md](AGENTS.md) for the architecture, invariants and how to extend things.

## Roadmap

- File shares (chunked encrypted upload and download)
- Recipient sign-in: email one-time code for email/domain rules, OIDC (Google, GitHub, Microsoft, generic)
- Passkeys for the owner, reusable policy templates
