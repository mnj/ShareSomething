# Audit trail and SIEM integration

ShareSomething records every security-relevant action: sign-ins, MFA, share lifecycle, every open
and refusal, recipient verification, exports and configuration events. The records go into an
**append-only, hash-chained audit trail**, and can be streamed to your SIEM in real time.

- **Complete:** every audited action goes through a single code path. If the audit write fails,
  the action fails.
- **Tamper-evident:** each record carries `hash = SHA-256(prev_hash ‖ canonical_json(record))`.
  Editing, deleting or reordering records breaks the chain at the first affected record.
- **No secrets:** share contents, passphrases, keys, tokens and codes are never recorded. Records
  contain ids, titles, identities, IP addresses, user agents, outcomes and policy metadata.
- **At-least-once delivery:** each shipper keeps a durable cursor, so outages and restarts never
  lose events. Duplicates after a crash carry the same `event.sequence`, so your SIEM can de-duplicate on it.

## Viewing and exporting

Admins and **auditors** (a read-only role) use **Audit** in the web UI. There they can filter by
category, outcome, actor and date, see whether the hash chain verifies, check each shipper's delivery
status, and export as CSV or JSON lines.

The same is available through the API:

| Endpoint | Purpose |
|---|---|
| `GET /api/audit?action=share.&outcome=denied&actor=…&from=…&to=…&before=…&limit=…` | Query, newest first, cursor-paginated |
| `GET /api/audit/export?format=csv\|jsonl` (same filters) | Streamed export, oldest first. The export itself is audited (`audit.exported`) |
| `GET /api/audit/verify` | Re-verify the hash chain |
| `GET /api/audit/shippers` | Delivery status per shipper (cursor, backlog, failures, last error) |

CSV exports neutralise spreadsheet formulas, so cells starting with `=`, `+`, `-` or `@` are prefixed with `'`.

From the command line (it can also run from cron and alert on a non-zero exit):

```sh
sharesomething audit verify     # prints a JSON report, exits 1 if the chain is broken
```

## Event schema (`schema_version: 1`)

Shipped events use an [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)-style
document, so they map naturally onto Elastic, Splunk CIM, Sentinel and others:

```json
{
  "@timestamp": "2026-10-18T09:12:44Z",
  "schema_version": 1,
  "message": "share.opened by bob@acme.com on share \"Q3 report\" (success)",
  "event": {
    "kind": "event", "dataset": "sharesomething.audit", "action": "share.opened",
    "category": ["file"], "outcome": "success", "sequence": 4211, "created": "2026-10-18T09:12:44Z"
  },
  "user": { "name": "bob@acme.com" },
  "source": { "ip": "203.0.113.9", "geo": { "country_iso_code": "DK" } },
  "user_agent": { "original": "Mozilla/5.0 …" },
  "observer": { "vendor": "ShareSomething", "product": "ShareSomething", "version": "0.1.0", "hostname": "share.acme.com" },
  "sharesomething": {
    "outcome": "success",
    "actor": { "type": "recipient", "id": null, "label": "bob@acme.com" },
    "target": { "type": "share", "id": "8f0c…", "label": "Q3 report" },
    "details": { "burned": true, "views": 1, "max_views": 1, "owner_id": 3, "country": "DK" },
    "hash": "…", "prev_hash": "…"
  }
}
```

- `event.outcome` is ECS-style (`success`/`failure`). `sharesomething.outcome` keeps the precise
  value: `success`, `denied` (refused by policy or authentication) or `error`.
- `actor.type` is `user` (an account), `recipient` (someone opening a share, identified by a verified
  email if they signed in) or `system` (`server`, `sweeper`, `cli`).

### Actions

| Action | When | Notable details |
|---|---|---|
| `system.started` | Server start | version, mode, shippers |
| `auth.login` / `auth.login_failed` | Account sign-in | `method` (password, password+totp, passkey); `reason` (bad_credentials, bad_totp, account_disabled) |
| `auth.logout` | Sign-out | |
| `auth.mfa.step_up` / `auth.mfa.step_up_failed` | Fresh-MFA confirmation | `method` |
| `auth.passkey.added` / `auth.passkey.removed` | Passkey changes | passkey id/name |
| `auth.totp.enabled` / `auth.totp.disabled` / `auth.password.changed` | Credential changes (web or CLI) | |
| `user.created` / `user.updated` | Account administration | role |
| `share.created` / `share.updated` | Share lifecycle | kind, encryption, limits, the full access **policy**, changed fields |
| `share.revoked` / `share.deleted` / `share.purged` | Removal (manual, or by retention) | |
| `share.opened` | Content released | `burned`, `views`, `max_views` |
| `share.denied` | Open refused | `reason`: policy, sign_in_required, owner_login_required, owner_mfa_required |
| `share.passphrase_failed` / `share.destroyed` | Wrong passphrase / destroyed after too many | attempts |
| `share.file_uploaded` / `share.file_downloaded` | File transfer | file index, bytes, via (chunks/stream) |
| `recipient.code_requested` | Email code asked for | `sent` (false = address had no access; the visitor isn't told) |
| `recipient.verified` / `recipient.verify_failed` | Recipient sign-in (email code / OIDC / GitHub) | `method`, `reason` |
| `recipient.signed_out` | | |
| `template.saved` / `template.deleted` | Saved access policies | policy |
| `audit.exported` / `audit.pruned` | Audit access and retention | filters / deleted range |
| `siem.delivery_failed` / `siem.delivery_recovered` | A shipper failed 3 times in a row / recovered | error |

Use these as SIEM detections, for example:
- many `auth.login_failed` from one `source.ip`
- `share.denied` with reason `policy` from unexpected countries
- `recipient.code_requested` with `sent=false` bursts (probing for allowed addresses)
- any `audit.pruned` or `siem.delivery_failed`

## Shipping to a SIEM

Add one or more `[[audit.shippers]]` blocks to the config file, or set
`SS_AUDIT__SHIPPERS='[{...}, ...]'`. Each shipper has its own delivery cursor and runs independently.

Common options: `name` (required, unique, and the key of the cursor), `batch_size` (default 200), and
`backfill` (default `true`: ship history from the beginning; `false`: start at the current end).

### Splunk (HTTP Event Collector)

```toml
[[audit.shippers]]
name = "splunk"
type = "http"
preset = "splunk_hec"
url = "https://splunk.acme.com:8088/services/collector/event"
token = "00000000-0000-0000-0000-000000000000"
```
Events arrive with `sourcetype = sharesomething:audit` and `source = sharesomething`.

### Elasticsearch / OpenSearch / Elastic Security

```toml
[[audit.shippers]]
name = "elastic"
type = "http"
preset = "elastic"
url = "https://es.acme.com:9200/logs-sharesomething.audit-default/_bulk"
token = "base64-api-key"            # sent as "Authorization: ApiKey …"
```
Item-level bulk errors count as failures and are retried.

### Microsoft Sentinel, QRadar, ArcSight, LogRhythm (syslog + CEF)

```toml
[[audit.shippers]]
name = "sentinel"
type = "syslog"
address = "cef-forwarder.acme.com:6514"   # e.g. the Azure Monitor Agent CEF forwarder
transport = "tls"                         # udp | tcp | tls (RFC 5425-style octet counting)
format = "cef"                            # or "json"
ca_file = "/data/acme-root-ca.pem"        # optional: trust an internal CA
facility = 16                             # local0 (default)
```
In CEF:
- **Fields:** `act` = action, `outcome`, `suser` = actor, `src` = IP,
  `requestClientApplication` = user agent, `cs1..cs6` = actor type, target type/id/label,
  details JSON and record hash. `externalId` is the sequence number.
- **Severity:** 3 for routine events, 6 for refusals, 8 for errors.

### Graylog, Wazuh, rsyslog, Vector, Fluent Bit (syslog JSON)

```toml
[[audit.shippers]]
name = "graylog"
type = "syslog"
address = "graylog.acme.com:1514"
transport = "tcp"
format = "json"
```

### Generic webhook (with HMAC)

```toml
[[audit.shippers]]
name = "webhook"
type = "http"
url = "https://ingest.acme.com/sharesomething"
token = "bearer-token"                     # optional: "Authorization: Bearer …"
hmac_secret = "shared-secret"              # optional: X-ShareSomething-Signature: sha256=<hex of body>
headers = { "X-Tenant" = "acme" }
```
The body is newline-delimited JSON (one ECS document per line).

### Container log pipelines / files

```toml
[[audit.shippers]]
name = "stdout"
type = "stdout"                            # JSON lines on stdout for Docker/Kubernetes collectors

[[audit.shippers]]
name = "file"
type = "file"
path = "/data/audit/events.jsonl"
max_bytes = 104857600                      # rotate at 100 MiB
keep = 5                                   # events.jsonl.1 … .5
```

## Retention

The audit trail is kept forever by default. To prune it, set:

```toml
[audit]
retention_days = 400
hostname = "share.acme.com"                # optional; defaults to the base_url host
```

Pruning deletes records older than the cut-off. The newest record is always kept, so the remaining
chain still verifies, and the pruning is itself recorded (`audit.pruned`). Ship to a SIEM if you
need longer retention than the instance keeps.
