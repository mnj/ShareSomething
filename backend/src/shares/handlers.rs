use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use subtle::ConstantTimeEq;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    approvals,
    model::*,
    policy::{self, AccessContext, Decision, PolicyRule, Rule, RuleGroup, UserCtx},
    store::{self, ShareRow, Wipe},
};
use crate::{
    app::AppState,
    audit::{Action, Event},
    auth::{
        recipient::{Recipient, available_methods},
        users::{CurrentUser, user_has_mfa},
    },
    blobs,
    crypto::{self, CryptoError, ServerMeta},
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    notify,
    slug::GeneratorInfo,
    util::{now, random_token, sha256},
};

const MAX_EXPIRY_SECS: i64 = 366 * 24 * 3600;
const MAX_VIEWS: i64 = 10_000;
const MAX_META_BYTES: usize = 8 * 1024;
const MAX_SLUG_ATTEMPTS: usize = 10;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_shares, create_share))
        .routes(routes!(get_share, update_share, delete_share))
        .routes(routes!(share_log))
        .routes(routes!(list_generators))
        .routes(routes!(preview_slug))
        .routes(routes!(share_info))
        .routes(routes!(open_share))
}

// ---------------------------------------------------------------------------------------------
// Owner API
// ---------------------------------------------------------------------------------------------

fn summary(state: &AppState, row: &ShareRow, policy: Vec<PolicyRule>) -> ShareSummary {
    let opts: Value = serde_json::from_str(&row.slug_opts).unwrap_or_default();
    ShareSummary {
        id: row.id.clone(),
        slug: row.slug.clone(),
        slug_generator: row.slug_generator.clone(),
        url: state.share_url(&row.slug),
        kind: row.kind(),
        title: row.title.clone(),
        enc_mode: row.enc_mode(),
        passphrase_required: row.passphrase_required,
        failed_attempts: row.failed_attempts,
        require_owner_mfa: row.require_owner_mfa,
        max_views: row.max_views,
        views: row.views,
        expires_at: row.expires_at,
        created_at: row.created_at,
        status: row.status(now()),
        policy,
        entropy_bits: state.slugs.get(&row.slug_generator).map(|g| g.entropy_bits(&opts)).unwrap_or(0.0),
        upload_pending: row.upload_pending,
        redirect_secs: row.redirect_secs,
        available_from: row.available_from,
        require_approval: row.require_approval,
        notify_on_open: row.notify_on_open,
        split_k: row.split_k,
        split_n: row.split_n,
    }
}

const MAX_REDIRECT_SECS: i64 = 60;

/// Auto-redirect only makes sense for link shares. `allow_off` permits -1 (turn off, for edits).
fn validate_redirect(kind: ShareKind, secs: Option<i64>, allow_off: bool) -> AppResult<()> {
    match secs {
        None => Ok(()),
        Some(-1) if allow_off => Ok(()),
        Some(_) if kind != ShareKind::Link => Err(AppError::BadRequest("redirect only applies to link shares".into())),
        Some(s) if (0..=MAX_REDIRECT_SECS).contains(&s) => Ok(()),
        Some(_) => Err(AppError::BadRequest(format!(
            "redirect delay must be 0-{MAX_REDIRECT_SECS} seconds"
        ))),
    }
}

/// Split keys are combined in the browser, so they only exist for E2E shares, and the metadata the
/// browser needs (k, n and a key check value) must be there and consistent.
fn validate_split(split: SplitSpec, mode: EncMode, meta: &Option<Value>, passphrase: bool) -> AppResult<()> {
    if mode != EncMode::E2e || passphrase {
        return Err(AppError::BadRequest(
            "split keys need end-to-end encryption without a passphrase".into(),
        ));
    }
    if !(2..=10).contains(&split.n) || !(2..=split.n).contains(&split.k) {
        return Err(AppError::BadRequest("split keys need 2 <= k <= n <= 10".into()));
    }
    let m = meta.as_ref().and_then(|m| m.get("split"));
    let ok = m.is_some_and(|m| {
        m.get("k").and_then(Value::as_i64) == Some(split.k)
            && m.get("n").and_then(Value::as_i64) == Some(split.n)
            && m.get("check").and_then(Value::as_str).is_some_and(|c| (8..=64).contains(&c.len()))
    });
    if !ok {
        return Err(AppError::BadRequest(
            "enc_meta.split must match k and n and carry a key check".into(),
        ));
    }
    Ok(())
}

/// Checks declared file sizes against the configured limits.
fn validate_file_specs(state: &AppState, kind: ShareKind, files: Option<&[FileSpec]>) -> AppResult<Vec<u64>> {
    match (kind, files) {
        (ShareKind::Files, Some(files)) => {
            if files.is_empty() || files.len() > state.cfg.max_files {
                return Err(AppError::BadRequest(format!("a file share holds 1..{} files", state.cfg.max_files)));
            }
            let total: u64 = files.iter().map(|f| f.size).sum();
            if total > state.cfg.max_upload_bytes {
                return Err(AppError::BadRequest(format!(
                    "files exceed the {} MiB limit",
                    state.cfg.max_upload_bytes / (1024 * 1024)
                )));
            }
            Ok(files.iter().map(|f| f.size).collect())
        }
        (ShareKind::Files, None) => Err(AppError::BadRequest("files is required for file shares".into())),
        (_, Some(_)) => Err(AppError::BadRequest("files only applies to file shares".into())),
        (_, None) => Ok(vec![]),
    }
}

pub(super) fn validate_policy(state: &AppState, rules: Vec<PolicyRule>) -> AppResult<Vec<PolicyRule>> {
    if rules.len() > 50 {
        return Err(AppError::BadRequest("too many policy rules".into()));
    }
    let rules = rules
        .into_iter()
        .map(|r| r.rule.normalise().map(|rule| PolicyRule { group: r.group, rule }))
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::BadRequest)?;
    if !rules.iter().any(|r| r.group == RuleGroup::Include) {
        return Err(AppError::BadRequest(
            "policy needs at least one include rule (use 'everyone' for a public link)".into(),
        ));
    }
    if rules.iter().any(|r| r.rule == Rule::Everyone && r.group != RuleGroup::Include) {
        return Err(AppError::BadRequest("'everyone' only makes sense as an include rule".into()));
    }
    // Identity rules must be satisfiable with the sign-in methods this server offers.
    for r in &rules {
        let methods = match &r.rule {
            Rule::Email { methods, .. } | Rule::EmailDomain { methods, .. } => methods,
            _ => continue,
        };
        for m in methods {
            let offered = match m.strip_prefix("oidc:") {
                Some(p) => state.oidc.has(p),
                None => m == "email_otp" && state.mailer.enabled(),
            };
            if !offered {
                return Err(AppError::BadRequest(format!(
                    "sign-in method '{m}' is not configured on this server"
                )));
            }
        }
        if methods.is_empty() && available_methods(state).is_empty() {
            return Err(AppError::BadRequest(
                "email rules need a recipient sign-in method; configure email codes or an OIDC provider".into(),
            ));
        }
    }
    Ok(rules)
}

async fn validate_mfa_toggle(state: &AppState, user: &CurrentUser, require_owner_mfa: bool) -> AppResult<()> {
    if require_owner_mfa && !user_has_mfa(state, user.id).await? {
        return Err(AppError::BadRequest(
            "set up TOTP or a passkey for the owner account before requiring owner MFA".into(),
        ));
    }
    Ok(())
}

fn validate_title(title: Option<String>) -> AppResult<Option<String>> {
    let title = title.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    if title.as_ref().is_some_and(|t| t.chars().count() > 200) {
        return Err(AppError::BadRequest("title max 200 characters".into()));
    }
    Ok(title)
}

fn decode_b64(field: &str, s: &str) -> AppResult<Vec<u8>> {
    B64.decode(s.trim())
        .map_err(|_| AppError::BadRequest(format!("{field} must be base64")))
}

/// Loads a share owned by `user` (other users' shares look like they don't exist).
async fn owned(state: &AppState, user: &CurrentUser, id: &str) -> AppResult<ShareRow> {
    store::by_id(&state.db, id)
        .await?
        .filter(|r| r.owner_id == user.id)
        .ok_or(AppError::NotFound)
}

/// List your shares (newest first).
#[utoipa::path(get, path = "/shares", tag = "shares", responses((status = 200, body = Vec<ShareSummary>)))]
async fn list_shares(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<Vec<ShareSummary>>> {
    let rows = store::list_owned(&state.db, user.id).await?;
    let mut rules: HashMap<String, Vec<PolicyRule>> = HashMap::new();
    for (id, r) in store::all_rules(&state.db).await? {
        rules.entry(id).or_default().push(r);
    }
    Ok(Json(
        rows.iter()
            .map(|r| summary(&state, r, rules.remove(&r.id).unwrap_or_default()))
            .collect(),
    ))
}

/// Create a share.
#[utoipa::path(post, path = "/shares", tag = "shares", request_body = CreateShareRequest,
    responses((status = 201, body = CreateShareResponse), (status = 400, body = crate::error::ErrorBody), (status = 409, body = crate::error::ErrorBody)))]
async fn create_share(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<CreateShareRequest>,
) -> AppResult<(StatusCode, Json<CreateShareResponse>)> {
    user.can_share()?;
    let title = validate_title(req.title)?;
    let file_sizes = validate_file_specs(&state, req.kind, req.files.as_deref())?;
    validate_redirect(req.kind, req.redirect_secs, false)?;
    if let Some(at) = req.available_from {
        let until = req.expires_in_secs.map(|s| now() + s);
        if at > now() + MAX_EXPIRY_SECS || until.is_some_and(|u| at >= u) {
            return Err(AppError::BadRequest(
                "the share must unlock before it expires (and within a year)".into(),
            ));
        }
    }
    if let Some(split) = req.split {
        validate_split(split, req.enc_mode, &req.enc_meta, req.passphrase_verifier.is_some())?;
    }
    let rules = validate_policy(&state, req.policy)?;
    validate_mfa_toggle(&state, &user, req.require_owner_mfa).await?;
    if req.max_views.is_some_and(|m| !(1..=MAX_VIEWS).contains(&m)) {
        return Err(AppError::BadRequest(format!("max_views must be 1..{MAX_VIEWS}")));
    }
    if req.expires_in_secs.is_some_and(|s| !(60..=MAX_EXPIRY_SECS).contains(&s)) {
        return Err(AppError::BadRequest("expiry must be between 1 minute and 1 year".into()));
    }
    let generator = req.slug.generator.unwrap_or_else(|| state.slugs.default_id().to_string());
    let generator_impl = state
        .slugs
        .get(&generator)
        .ok_or_else(|| AppError::BadRequest(format!("unknown slug generator '{generator}'")))?;
    let user_supplied = generator_impl.describe().user_supplied;

    let id = uuid::Uuid::new_v4().to_string();
    let max_bytes = state.cfg.max_text_bytes;

    // Encrypt / accept the content.
    let (ciphertext, enc_meta, passphrase_required, verifier, dek) = match req.enc_mode {
        EncMode::Server => {
            if req.ciphertext.is_some() || req.enc_meta.is_some() || req.passphrase_verifier.is_some() {
                return Err(AppError::BadRequest(
                    "ciphertext/enc_meta/passphrase_verifier are for e2e shares".into(),
                ));
            }
            let payload = req
                .payload
                .ok_or_else(|| AppError::BadRequest("payload is required for server-encrypted shares".into()))?;
            if payload.kind() != req.kind {
                return Err(AppError::BadRequest("payload kind does not match share kind".into()));
            }
            payload.validate(max_bytes).map_err(AppError::BadRequest)?;
            if let SharePayload::Files { files, .. } = &payload
                && files.iter().map(|f| f.size).ne(file_sizes.iter().copied())
            {
                return Err(AppError::BadRequest("manifest sizes don't match files".into()));
            }
            let passphrase = req.passphrase.filter(|p| !p.is_empty());
            if passphrase.as_ref().is_some_and(|p| p.len() > 1024) {
                return Err(AppError::BadRequest("passphrase too long".into()));
            }
            let plaintext = serde_json::to_vec(&payload).map_err(anyhow::Error::from)?;
            let (master, sid, pw) = (state.master.clone(), id.clone(), passphrase.clone());
            let (ct, meta, dek) = tokio::task::spawn_blocking(move || crypto::seal(&master, &sid, &plaintext, pw.as_deref()))
                .await
                .map_err(anyhow::Error::from)?;
            (
                ct,
                serde_json::to_string(&meta).map_err(anyhow::Error::from)?,
                passphrase.is_some(),
                None,
                Some(dek),
            )
        }
        EncMode::E2e => {
            if req.payload.is_some() || req.passphrase.is_some() {
                return Err(AppError::BadRequest(
                    "plaintext payload/passphrase must not be sent for e2e shares".into(),
                ));
            }
            let ct = decode_b64(
                "ciphertext",
                req.ciphertext
                    .as_deref()
                    .ok_or_else(|| AppError::BadRequest("ciphertext is required".into()))?,
            )?;
            if ct.len() < 12 + 16 || ct.len() > max_bytes + 1024 {
                return Err(AppError::BadRequest("ciphertext size out of range".into()));
            }
            let meta = req.enc_meta.ok_or_else(|| AppError::BadRequest("enc_meta is required".into()))?;
            let meta = serde_json::to_string(&meta).map_err(anyhow::Error::from)?;
            if !meta.starts_with('{') || meta.len() > MAX_META_BYTES {
                return Err(AppError::BadRequest("enc_meta must be a JSON object under 8 KiB".into()));
            }
            let verifier = req
                .passphrase_verifier
                .as_deref()
                .map(|v| decode_b64("passphrase_verifier", v))
                .transpose()?;
            if verifier.as_ref().is_some_and(|v| v.len() != 32) {
                return Err(AppError::BadRequest("passphrase_verifier must be 32 bytes".into()));
            }
            (ct, meta, verifier.is_some(), verifier.map(|v| sha256(&v)), None)
        }
    };

    let expires_at = req.expires_in_secs.map(|s| now() + s);
    let is_files = req.kind == ShareKind::Files;
    let upload_token = is_files.then(random_token);
    let upload_dek = upload_token
        .as_deref()
        .zip(dek.as_ref())
        .map(|(t, dek)| crypto::wrap_for_token(t, &id, dek));
    let slug_opts = serde_json::to_string(&req.slug.options).map_err(anyhow::Error::from)?;
    let mut tx = state.db.begin().await?;
    let mut slug = None;
    for _ in 0..if user_supplied { 1 } else { MAX_SLUG_ATTEMPTS } {
        let candidate = state
            .slugs
            .generate(&generator, &req.slug.options)
            .map_err(|e| AppError::BadRequest(e.to_string()))?;
        let res = sqlx::query(
            "INSERT INTO shares (id, slug, slug_generator, slug_opts, kind, title, enc_mode, enc_meta, ciphertext,
                passphrase_required, passphrase_verifier, require_owner_mfa, max_views, expires_at, created_at,
                upload_pending, upload_dek, upload_token_hash, redirect_secs, owner_id,
                available_from, require_approval, notify_on_open, split_k, split_n)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&candidate)
        .bind(&generator)
        .bind(&slug_opts)
        .bind(req.kind.as_str())
        .bind(&title)
        .bind(req.enc_mode.as_str())
        .bind(&enc_meta)
        .bind(&ciphertext)
        .bind(passphrase_required)
        .bind(&verifier)
        .bind(req.require_owner_mfa)
        .bind(req.max_views)
        .bind(expires_at)
        .bind(now())
        .bind(is_files)
        .bind(&upload_dek)
        .bind(upload_token.as_deref().map(|t| sha256(t.as_bytes())))
        .bind(req.redirect_secs)
        .bind(user.id)
        .bind(req.available_from)
        .bind(req.require_approval)
        .bind(req.notify_on_open)
        .bind(req.split.map(|s| s.k))
        .bind(req.split.map(|s| s.n))
        .execute(&mut *tx)
        .await;
        match res {
            Ok(_) => {
                slug = Some(candidate);
                break;
            }
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => continue,
            Err(e) => return Err(e.into()),
        }
    }
    if slug.is_none() {
        return Err(AppError::Conflict(if user_supplied {
            "that link is already taken".into()
        } else {
            "could not find a free link; use a longer one".into()
        }));
    }
    store::replace_rules(&mut tx, &id, &rules).await?;
    let mut files = Vec::with_capacity(file_sizes.len());
    for (idx, size) in file_sizes.into_iter().enumerate() {
        let chunk_count = blobs::chunk_count(size);
        sqlx::query("INSERT INTO share_files (share_id, idx, size, chunk_count) VALUES (?, ?, ?, ?)")
            .bind(&id)
            .bind(idx as i64)
            .bind(size as i64)
            .bind(chunk_count as i64)
            .execute(&mut *tx)
            .await?;
        files.push(FileUploadInfo {
            idx: idx as u32,
            size,
            chunk_count,
            chunk_size: blobs::CHUNK_SIZE as u64,
        });
    }
    tx.commit().await?;

    let row = store::by_id(&state.db, &id).await?.ok_or(AppError::NotFound)?;
    state
        .audit
        .record(
            row.event(Action::ShareCreated)
                .user(user.id, &user.label)
                .client(&client)
                .detail("kind", row.kind())
                .detail("enc_mode", row.enc_mode())
                .detail("slug_generator", &row.slug_generator)
                .detail("max_views", row.max_views)
                .detail("expires_at", row.expires_at)
                .detail("passphrase", row.passphrase_required)
                .detail("require_owner_mfa", row.require_owner_mfa)
                .detail("available_from", row.available_from)
                .detail("require_approval", row.require_approval)
                .detail("split", row.split_k.zip(row.split_n).map(|(k, n)| format!("{k}-of-{n}")))
                .detail("policy", &rules),
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateShareResponse {
            share: summary(&state, &row, rules),
            upload_token,
            files,
        }),
    ))
}

pub(super) async fn get_share_summary(state: &AppState, user: &CurrentUser, id: &str) -> AppResult<ShareSummary> {
    let row = owned(state, user, id).await?;
    let rules = store::rules(&state.db, id).await?;
    Ok(summary(state, &row, rules))
}

/// Get one share's settings.
#[utoipa::path(get, path = "/shares/{id}", tag = "shares", params(("id" = String, Path)),
    responses((status = 200, body = ShareSummary), (status = 404, body = crate::error::ErrorBody)))]
async fn get_share(State(state): State<AppState>, user: CurrentUser, Path(id): Path<String>) -> AppResult<Json<ShareSummary>> {
    Ok(Json(get_share_summary(&state, &user, &id).await?))
}

/// Change a share's title, limits or policy, or revoke it.
#[utoipa::path(patch, path = "/shares/{id}", tag = "shares", params(("id" = String, Path)), request_body = UpdateShareRequest,
    responses((status = 200, body = ShareSummary), (status = 404, body = crate::error::ErrorBody)))]
async fn update_share(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateShareRequest>,
) -> AppResult<Json<ShareSummary>> {
    let row = owned(&state, &user, &id).await?;
    let policy = req.policy.map(|p| validate_policy(&state, p)).transpose()?;
    if let Some(m) = req.require_owner_mfa {
        validate_mfa_toggle(&state, &user, m).await?;
    }
    validate_redirect(row.kind(), req.redirect_secs, true)?;
    let edits = req.title.is_some()
        || req.expires_at.is_some()
        || req.max_views.is_some()
        || req.require_owner_mfa.is_some()
        || req.redirect_secs.is_some()
        || req.available_from.is_some()
        || req.require_approval.is_some()
        || req.notify_on_open.is_some()
        || policy.is_some();
    if req.available_from.is_some_and(|t| t != 0 && t > now() + MAX_EXPIRY_SECS) {
        return Err(AppError::BadRequest("the time-lock can be at most a year ahead".into()));
    }
    if edits && (row.ciphertext.is_none() || row.revoked_at.is_some() || row.burned_at.is_some()) {
        return Err(AppError::Conflict("this share's content is gone; it can't be changed".into()));
    }
    if req.max_views.is_some_and(|m| !(0..=MAX_VIEWS).contains(&m)) {
        return Err(AppError::BadRequest(format!("max_views must be 0..{MAX_VIEWS}")));
    }
    if req.max_views.is_some_and(|m| m != 0 && m <= row.views) {
        return Err(AppError::BadRequest(format!(
            "the view limit must be more than the {} views already used",
            row.views
        )));
    }
    if req
        .expires_at
        .is_some_and(|t| t != 0 && (t <= now() || t > now() + MAX_EXPIRY_SECS))
    {
        return Err(AppError::BadRequest("expires_at must be in the future (max 1 year) or 0".into()));
    }

    let mut changed: Vec<&str> = vec![];
    for (name, set) in [
        ("title", req.title.is_some()),
        ("expires_at", req.expires_at.is_some()),
        ("max_views", req.max_views.is_some()),
        ("require_owner_mfa", req.require_owner_mfa.is_some()),
        ("redirect_secs", req.redirect_secs.is_some()),
        ("available_from", req.available_from.is_some()),
        ("require_approval", req.require_approval.is_some()),
        ("notify_on_open", req.notify_on_open.is_some()),
        ("policy", policy.is_some()),
    ] {
        if set {
            changed.push(name);
        }
    }
    let mut tx = state.db.begin().await?;
    if let Some(title) = req.title.clone() {
        sqlx::query("UPDATE shares SET title = ? WHERE id = ?")
            .bind(validate_title(Some(title))?)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(t) = req.expires_at {
        sqlx::query("UPDATE shares SET expires_at = ? WHERE id = ?")
            .bind((t != 0).then_some(t))
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(m) = req.max_views {
        sqlx::query("UPDATE shares SET max_views = ? WHERE id = ?")
            .bind((m != 0).then_some(m))
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(m) = req.require_owner_mfa {
        sqlx::query("UPDATE shares SET require_owner_mfa = ? WHERE id = ?")
            .bind(m)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(t) = req.available_from {
        sqlx::query("UPDATE shares SET available_from = ? WHERE id = ?")
            .bind((t != 0).then_some(t))
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = req.require_approval {
        sqlx::query("UPDATE shares SET require_approval = ? WHERE id = ?")
            .bind(v)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = req.notify_on_open {
        sqlx::query("UPDATE shares SET notify_on_open = ? WHERE id = ?")
            .bind(v)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(secs) = req.redirect_secs {
        sqlx::query("UPDATE shares SET redirect_secs = ? WHERE id = ?")
            .bind((secs >= 0).then_some(secs))
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(rules) = &policy {
        store::replace_rules(&mut tx, &id, rules).await?;
    }
    let revoking = req.revoke && row.revoked_at.is_none();
    if revoking {
        store::wipe(&mut *tx, &id, Wipe::Revoked).await?;
    }
    tx.commit().await?;
    if req.revoke {
        store::destroy_files(&state, &id).await?;
    }
    if !changed.is_empty() {
        let mut e = row
            .event(Action::ShareUpdated)
            .user(user.id, &user.label)
            .client(&client)
            .detail("changed", &changed);
        if let Some(p) = &policy {
            e = e.detail("policy", p);
        }
        if let Some(v) = req.max_views {
            e = e.detail("max_views", v);
        }
        if let Some(v) = req.expires_at {
            e = e.detail("expires_at", v);
        }
        state.audit.record(e).await?;
    }
    if revoking {
        state
            .audit
            .record(row.event(Action::ShareRevoked).user(user.id, &user.label).client(&client))
            .await?;
    }
    Ok(Json(get_share_summary(&state, &user, &id).await?))
}

/// Permanently delete a share (its audit records are kept).
#[utoipa::path(delete, path = "/shares/{id}", tag = "shares", params(("id" = String, Path)),
    responses((status = 204), (status = 404, body = crate::error::ErrorBody)))]
async fn delete_share(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let row = owned(&state, &user, &id).await?;
    sqlx::query("DELETE FROM shares WHERE id = ?").bind(&id).execute(&state.db).await?;
    state.blobs.remove_share(&id).await;
    state
        .audit
        .record(row.event(Action::ShareDeleted).user(user.id, &user.label).client(&client))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Access log for a share, newest first.
#[utoipa::path(get, path = "/shares/{id}/log", tag = "shares", params(("id" = String, Path)),
    responses((status = 200, body = Vec<AccessLogEntry>)))]
async fn share_log(State(state): State<AppState>, user: CurrentUser, Path(id): Path<String>) -> AppResult<Json<Vec<AccessLogEntry>>> {
    owned(&state, &user, &id).await?;
    let filter = crate::audit::api::AuditFilter {
        target_type: Some("share".into()),
        target_id: Some(id),
        limit: Some(500),
        ..Default::default()
    };
    let page = crate::audit::api::query(&state.db, &filter).await?;
    Ok(Json(page.events.into_iter().map(AccessLogEntry::from).collect()))
}

/// Enabled link generators and their options.
#[utoipa::path(get, path = "/slug-generators", tag = "shares", responses((status = 200, body = Vec<GeneratorInfo>)))]
async fn list_generators(State(state): State<AppState>, _user: CurrentUser) -> Json<Vec<GeneratorInfo>> {
    Json(state.slugs.list())
}

/// Generate an example link without reserving it.
#[utoipa::path(post, path = "/slug-generators/{id}/preview", tag = "shares", params(("id" = String, Path)), request_body = PreviewRequest,
    responses((status = 200, body = PreviewResponse), (status = 400, body = crate::error::ErrorBody)))]
async fn preview_slug(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<PreviewRequest>,
) -> AppResult<Json<PreviewResponse>> {
    let slug = state
        .slugs
        .generate(&id, &req.options)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let entropy_bits = state.slugs.get(&id).map(|g| g.entropy_bits(&req.options)).unwrap_or(0.0);
    Ok(Json(PreviewResponse {
        url: state.share_url(&slug),
        slug,
        entropy_bits,
    }))
}

// ---------------------------------------------------------------------------------------------
// Recipient API
// ---------------------------------------------------------------------------------------------

fn access_context(client: &ClientInfo, user: Option<&CurrentUser>, recipient: &Recipient) -> AccessContext {
    AccessContext {
        now: now(),
        ip: client.ip,
        country: client.country.clone(),
        user: user.map(|u| UserCtx {
            id: u.id,
            mfa_at: u.mfa_at,
        }),
        identities: recipient.identities.clone(),
    }
}

/// Attributes a share-visit event to whoever the visitor is: a signed-in user or a recipient.
fn visitor(e: Event, client: &ClientInfo, user: Option<&CurrentUser>, recipient: &Recipient) -> Event {
    let e = e.client(client);
    match user {
        Some(u) => e.user(u.id, &u.label),
        None => e.recipient(recipient.label()),
    }
}

/// Stable, SIEM-friendly reason for a refused open.
fn decision_reason(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allowed",
        Decision::Unavailable => "unavailable",
        Decision::Denied => "policy",
        Decision::NeedOwnerLogin => "owner_login_required",
        Decision::NeedOwnerMfa => "owner_mfa_required",
        Decision::NeedRecipientAuth(_) => "sign_in_required",
        Decision::NotYet(_) => "time_locked",
    }
}

/// Narrows a rule's acceptable methods (empty = any) to those this server actually offers.
fn offered_methods(state: &AppState, wanted: &[String]) -> Vec<String> {
    available_methods(state)
        .into_iter()
        .map(|m| m.id)
        .filter(|id| wanted.is_empty() || wanted.contains(id))
        .collect()
}

/// Public part of the E2E metadata needed before opening (never the wrapped key).
fn public_kdf(row: &ShareRow) -> Option<Value> {
    if row.enc_mode() != EncMode::E2e || !row.passphrase_required {
        return None;
    }
    serde_json::from_str::<Value>(&row.enc_meta).ok()?.get("kdf").cloned()
}

/// Split-key parameters the browser needs before opening: k, n and the key check value.
fn public_split(row: &ShareRow) -> Option<Value> {
    row.split_k?;
    serde_json::from_str::<Value>(&row.enc_meta).ok()?.get("split").cloned()
}

fn decision_error(d: &Decision) -> AppError {
    match d {
        Decision::Allow => unreachable!(),
        Decision::Unavailable => AppError::NotFound,
        Decision::Denied => AppError::Access("denied", "you don't have access to this share".into()),
        Decision::NeedOwnerLogin => AppError::Access("need_owner_login", "sign in as the owner to open this share".into()),
        Decision::NeedOwnerMfa => AppError::Access("need_owner_mfa", "confirm your authenticator code to open this share".into()),
        Decision::NeedRecipientAuth(_) => AppError::Access("need_auth", "sign in to open this share".into()),
        Decision::NotYet(at) => AppError::Access(
            "not_yet",
            format!("this share is available from {}", crate::audit::format::rfc3339(*at)),
        ),
    }
}

/// What a visitor needs to do to open a share. Unknown, expired and burned shares all return 404.
#[utoipa::path(get, path = "/s/{slug}", tag = "recipient", params(("slug" = String, Path)),
    responses((status = 200, body = ShareInfo), (status = 404, body = crate::error::ErrorBody)))]
async fn share_info(
    State(state): State<AppState>,
    client: ClientInfo,
    user: Option<CurrentUser>,
    recipient: Recipient,
    Path(slug): Path<String>,
) -> AppResult<Json<ShareInfo>> {
    if !state.limits.lookup.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let row = store::by_slug(&state.db, &slug).await?.ok_or(AppError::NotFound)?;
    let rules = store::rules(&state.db, &row.id).await?;
    let decision = policy::evaluate(&row.state(rules), &access_context(&client, user.as_ref(), &recipient));

    let (status, auth_methods) = match &decision {
        Decision::Unavailable => return Err(AppError::NotFound),
        Decision::Allow if row.passphrase_required => (AccessStatus::NeedPassphrase, vec![]),
        Decision::Allow => (AccessStatus::Ready, vec![]),
        Decision::Denied => (AccessStatus::Denied, vec![]),
        Decision::NeedOwnerLogin => (AccessStatus::NeedOwnerLogin, vec![]),
        Decision::NeedOwnerMfa => (AccessStatus::NeedOwnerMfa, vec![]),
        Decision::NotYet(_) => (AccessStatus::NotYet, vec![]),
        Decision::NeedRecipientAuth(m) => (AccessStatus::NeedAuth, offered_methods(&state, m)),
    };
    // Allowed visitors may see details, also while the share is still time-locked.
    let visible = matches!(decision, Decision::Allow | Decision::NotYet(_));
    Ok(Json(ShareInfo {
        slug: row.slug.clone(),
        status,
        auth_methods,
        kind: visible.then(|| row.kind()),
        title: if visible { row.title.clone() } else { None },
        enc_mode: visible.then(|| row.enc_mode()),
        passphrase_required: visible && row.passphrase_required,
        kdf: if visible { public_kdf(&row) } else { None },
        views_left: if visible { row.views_left() } else { None },
        expires_at: if visible { row.expires_at } else { None },
        redirect_secs: if visible { row.redirect_secs } else { None },
        available_from: if visible { row.available_from } else { None },
        require_approval: visible && row.require_approval,
        split: if visible { public_split(&row) } else { None },
    }))
}

/// Records a wrong passphrase; destroys the share after too many.
async fn wrong_passphrase(
    state: &AppState,
    row: &ShareRow,
    client: &ClientInfo,
    user: Option<&CurrentUser>,
    recipient: &Recipient,
) -> AppError {
    let attempts: Result<(i64,), _> =
        sqlx::query_as("UPDATE shares SET failed_attempts = failed_attempts + 1 WHERE id = ? RETURNING failed_attempts")
            .bind(&row.id)
            .fetch_one(&state.db)
            .await;
    let attempts = attempts.map(|a| a.0).unwrap_or(i64::MAX);
    let limit = state.cfg.max_passphrase_attempts;
    if attempts >= limit {
        if let Err(e) = store::wipe(&state.db, &row.id, Wipe::Revoked).await {
            return e.into();
        }
        if let Err(e) = store::destroy_files(state, &row.id).await {
            return e.into();
        }
        let e = visitor(row.event(Action::ShareDestroyed), client, user, recipient)
            .detail("reason", "too_many_wrong_passphrases")
            .detail("attempts", attempts);
        if let Err(e) = state.audit.record(e).await {
            return e.into();
        }
        tracing::warn!(share = %row.id, "share destroyed after too many wrong passphrases");
        return AppError::NotFound;
    }
    let e = visitor(row.event(Action::SharePassphraseFailed).denied(), client, user, recipient).detail("attempts", attempts);
    if let Err(e) = state.audit.record(e).await {
        return e.into();
    }
    AppError::Access("wrong_passphrase", format!("wrong passphrase ({} attempts left)", limit - attempts))
}

/// Open a share: consumes one view and returns the content.
#[utoipa::path(post, path = "/s/{slug}/open", tag = "recipient", params(("slug" = String, Path)), request_body = OpenRequest,
    responses((status = 200, body = OpenResponse), (status = 403, body = crate::error::ErrorBody), (status = 404, body = crate::error::ErrorBody)))]
async fn open_share(
    State(state): State<AppState>,
    client: ClientInfo,
    user: Option<CurrentUser>,
    recipient: Recipient,
    Path(slug): Path<String>,
    body: Option<Json<OpenRequest>>,
) -> AppResult<Json<OpenResponse>> {
    if !state.limits.open.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let req = body.map(|b| b.0).unwrap_or_default();
    let row = store::by_slug(&state.db, &slug).await?.ok_or(AppError::NotFound)?;
    let rules = store::rules(&state.db, &row.id).await?;
    let decision = policy::evaluate(&row.state(rules), &access_context(&client, user.as_ref(), &recipient));
    if decision != Decision::Allow {
        if decision != Decision::Unavailable {
            let e = visitor(row.event(Action::ShareDenied).denied(), &client, user.as_ref(), &recipient)
                .detail("reason", decision_reason(&decision));
            state.audit.record(e).await?;
        }
        return Err(decision_error(&decision));
    }
    let Some(ciphertext) = row.ciphertext.clone() else {
        return Err(AppError::NotFound);
    };

    // Check the passphrase (and decrypt server-side content) before spending a view.
    let (payload, dek) = match row.enc_mode() {
        EncMode::Server => {
            let pw = req.passphrase.clone().filter(|p| !p.is_empty());
            if row.passphrase_required && pw.is_none() {
                return Err(AppError::Access("need_passphrase", "this share needs a passphrase".into()));
            }
            let meta: ServerMeta = serde_json::from_str(&row.enc_meta).map_err(anyhow::Error::from)?;
            let (master, id) = (state.master.clone(), row.id.clone());
            let result = tokio::task::spawn_blocking(move || crypto::open(&master, &id, &ciphertext, &meta, pw.as_deref()))
                .await
                .map_err(anyhow::Error::from)?;
            match result {
                Ok((pt, dek)) => (
                    Some(serde_json::from_slice::<SharePayload>(&pt).map_err(anyhow::Error::from)?),
                    Some(dek),
                ),
                Err(CryptoError::Decrypt) if row.passphrase_required => {
                    return Err(wrong_passphrase(&state, &row, &client, user.as_ref(), &recipient).await);
                }
                Err(e) => return Err(AppError::Internal(e.into())),
            }
        }
        EncMode::E2e => {
            if let Some(stored) = &row.passphrase_verifier {
                let Some(v) = req.passphrase_verifier.as_deref() else {
                    return Err(AppError::Access("need_passphrase", "this share needs a passphrase".into()));
                };
                let given = sha256(&decode_b64("passphrase_verifier", v)?);
                if !bool::from(given.ct_eq(stored)) {
                    return Err(wrong_passphrase(&state, &row, &client, user.as_ref(), &recipient).await);
                }
            }
            (None, None)
        }
    };

    // Owner approval comes after the passphrase check, so typos never bother the owner.
    let approval = if row.require_approval {
        let label = user.as_ref().map(|u| u.label.clone()).or_else(|| recipient.label());
        let event = visitor(row.event(Action::ShareApprovalRequested), &client, user.as_ref(), &recipient);
        Some(approvals::gate(&state, &row, &req, &client, label, event).await?)
    } else {
        None
    };

    let mut tx = state.db.begin().await?;
    if let Some(id) = &approval
        && !approvals::consume(&mut tx, id).await?
    {
        return Err(AppError::Access(
            "approval_expired",
            "the approval expired or was already used; ask again".into(),
        ));
    }
    let Some(views) = store::consume_view(&mut tx, &row.id).await? else {
        return Err(AppError::NotFound);
    };
    let burned = row.max_views.is_some_and(|m| views >= m);
    if burned {
        store::wipe(&mut *tx, &row.id, Wipe::Burned).await?;
    }
    // File shares: hand out a short-lived token for the chunks, which outlive a burned manifest.
    let download = if row.kind() == ShareKind::Files {
        let token = random_token();
        let expires_at = now() + state.cfg.download_ttl_mins * 60;
        sqlx::query("INSERT INTO download_tokens (token_hash, share_id, wrapped_dek, expires_at) VALUES (?, ?, ?, ?)")
            .bind(sha256(token.as_bytes()))
            .bind(&row.id)
            .bind(dek.map(|d| crypto::wrap_for_token(&token, &row.id, &d)))
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
        Some((token, expires_at))
    } else {
        None
    };
    tx.commit().await?;
    state
        .audit
        .record(
            visitor(row.event(Action::ShareOpened), &client, user.as_ref(), &recipient)
                .detail("burned", burned)
                .detail("views", views)
                .detail("max_views", row.max_views)
                .detail("approval_id", &approval),
        )
        .await?;
    if row.notify_on_open {
        let who = user
            .as_ref()
            .map(|u| u.label.clone())
            .or_else(|| recipient.label())
            .unwrap_or_else(|| "Someone".into());
        let place = client
            .country
            .as_ref()
            .map(|c| format!("{} ({c})", client.ip))
            .unwrap_or_else(|| client.ip.to_string());
        let note = if burned { " It has now been destroyed." } else { "" };
        notify::notify(
            &state,
            row.owner_id,
            notify::Kind::ShareOpened,
            Some(&row.id),
            None,
            &format!("\"{}\" was opened", row.audit_label()),
            &format!("{who} opened \"{}\" from {place}.{note}", row.audit_label()),
        )
        .await?;
    }

    let e2e = row.enc_mode() == EncMode::E2e;
    Ok(Json(OpenResponse {
        kind: row.kind(),
        enc_mode: row.enc_mode(),
        title: row.title.clone(),
        payload,
        ciphertext: e2e.then(|| B64.encode(row.ciphertext.as_deref().unwrap_or_default())),
        enc_meta: if e2e { serde_json::from_str(&row.enc_meta).ok() } else { None },
        views_left: row.max_views.map(|m| (m - views).max(0)),
        burned,
        download_expires_at: download.as_ref().map(|d| d.1),
        download_token: download.map(|d| d.0),
    }))
}
