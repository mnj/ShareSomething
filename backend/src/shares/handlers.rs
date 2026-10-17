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
    model::*,
    policy::{self, AccessContext, Decision, OwnerCtx, PolicyRule, Rule, RuleGroup},
    store::{self, ShareRow, Wipe},
};
use crate::{
    app::AppState,
    auth::owner::{Owner, owner_has_totp},
    blobs,
    crypto::{self, CryptoError, ServerMeta},
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
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
    }
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

fn validate_policy(rules: Vec<PolicyRule>) -> AppResult<Vec<PolicyRule>> {
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
    Ok(rules)
}

async fn validate_mfa_toggle(state: &AppState, require_owner_mfa: bool) -> AppResult<()> {
    if require_owner_mfa && !owner_has_totp(state).await? {
        return Err(AppError::BadRequest(
            "enable TOTP for the owner account before requiring owner MFA".into(),
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

/// List all shares (newest first).
#[utoipa::path(get, path = "/shares", tag = "shares", responses((status = 200, body = Vec<ShareSummary>)))]
async fn list_shares(State(state): State<AppState>, _owner: Owner) -> AppResult<Json<Vec<ShareSummary>>> {
    let rows = store::list(&state.db).await?;
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
    _owner: Owner,
    Json(req): Json<CreateShareRequest>,
) -> AppResult<(StatusCode, Json<CreateShareResponse>)> {
    let title = validate_title(req.title)?;
    let file_sizes = validate_file_specs(&state, req.kind, req.files.as_deref())?;
    let rules = validate_policy(req.policy)?;
    validate_mfa_toggle(&state, req.require_owner_mfa).await?;
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
                upload_pending, upload_dek, upload_token_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    tracing::info!(share = %id, kind = %row.kind, enc = %row.enc_mode, "share created");
    Ok((
        StatusCode::CREATED,
        Json(CreateShareResponse {
            share: summary(&state, &row, rules),
            upload_token,
            files,
        }),
    ))
}

pub(super) async fn get_share_summary(state: &AppState, _owner: Owner, id: &str) -> AppResult<ShareSummary> {
    let row = store::by_id(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let rules = store::rules(&state.db, id).await?;
    Ok(summary(state, &row, rules))
}

/// Get one share's settings.
#[utoipa::path(get, path = "/shares/{id}", tag = "shares", params(("id" = String, Path)),
    responses((status = 200, body = ShareSummary), (status = 404, body = crate::error::ErrorBody)))]
async fn get_share(State(state): State<AppState>, _owner: Owner, Path(id): Path<String>) -> AppResult<Json<ShareSummary>> {
    let row = store::by_id(&state.db, &id).await?.ok_or(AppError::NotFound)?;
    let rules = store::rules(&state.db, &id).await?;
    Ok(Json(summary(&state, &row, rules)))
}

/// Change a share's title, limits or policy, or revoke it.
#[utoipa::path(patch, path = "/shares/{id}", tag = "shares", params(("id" = String, Path)), request_body = UpdateShareRequest,
    responses((status = 200, body = ShareSummary), (status = 404, body = crate::error::ErrorBody)))]
async fn update_share(
    State(state): State<AppState>,
    _owner: Owner,
    Path(id): Path<String>,
    Json(req): Json<UpdateShareRequest>,
) -> AppResult<Json<ShareSummary>> {
    let row = store::by_id(&state.db, &id).await?.ok_or(AppError::NotFound)?;
    let policy = req.policy.map(validate_policy).transpose()?;
    if let Some(m) = req.require_owner_mfa {
        validate_mfa_toggle(&state, m).await?;
    }
    if req.max_views.is_some_and(|m| !(0..=MAX_VIEWS).contains(&m)) {
        return Err(AppError::BadRequest(format!("max_views must be 0..{MAX_VIEWS}")));
    }
    if req
        .expires_at
        .is_some_and(|t| t != 0 && (t <= now() || t > now() + MAX_EXPIRY_SECS))
    {
        return Err(AppError::BadRequest("expires_at must be in the future (max 1 year) or 0".into()));
    }

    let mut tx = state.db.begin().await?;
    if let Some(title) = req.title {
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
    if let Some(rules) = &policy {
        store::replace_rules(&mut tx, &id, rules).await?;
    }
    if req.revoke && row.revoked_at.is_none() {
        store::wipe(&mut *tx, &id, Wipe::Revoked).await?;
        tracing::info!(share = %id, "share revoked");
    }
    tx.commit().await?;
    if req.revoke {
        store::destroy_files(&state, &id).await?;
    }
    get_share(State(state), _owner, Path(id)).await
}

/// Permanently delete a share and its access log.
#[utoipa::path(delete, path = "/shares/{id}", tag = "shares", params(("id" = String, Path)),
    responses((status = 204), (status = 404, body = crate::error::ErrorBody)))]
async fn delete_share(State(state): State<AppState>, _owner: Owner, Path(id): Path<String>) -> AppResult<StatusCode> {
    let res = sqlx::query("DELETE FROM shares WHERE id = ?").bind(&id).execute(&state.db).await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    state.blobs.remove_share(&id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Access log for a share, newest first.
#[utoipa::path(get, path = "/shares/{id}/log", tag = "shares", params(("id" = String, Path)),
    responses((status = 200, body = Vec<AccessLogEntry>)))]
async fn share_log(State(state): State<AppState>, _owner: Owner, Path(id): Path<String>) -> AppResult<Json<Vec<AccessLogEntry>>> {
    let rows: Vec<AccessLogEntry> = sqlx::query_as(
        "SELECT ts, ip, country, identity, user_agent, outcome FROM access_log WHERE share_id = ? ORDER BY ts DESC, id DESC LIMIT 500",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

/// Enabled link generators and their options.
#[utoipa::path(get, path = "/slug-generators", tag = "shares", responses((status = 200, body = Vec<GeneratorInfo>)))]
async fn list_generators(State(state): State<AppState>, _owner: Owner) -> Json<Vec<GeneratorInfo>> {
    Json(state.slugs.list())
}

/// Generate an example link without reserving it.
#[utoipa::path(post, path = "/slug-generators/{id}/preview", tag = "shares", params(("id" = String, Path)), request_body = PreviewRequest,
    responses((status = 200, body = PreviewResponse), (status = 400, body = crate::error::ErrorBody)))]
async fn preview_slug(
    State(state): State<AppState>,
    _owner: Owner,
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

fn access_context(client: &ClientInfo, owner: Option<&Owner>) -> AccessContext {
    AccessContext {
        now: now(),
        ip: client.ip,
        country: client.country.clone(),
        owner: owner.map(|o| OwnerCtx { mfa_at: o.mfa_at }),
        // Recipient sign-in (email OTP / OIDC) arrives in a later phase.
        identities: vec![],
    }
}

fn identity_label(owner: Option<&Owner>) -> Option<&'static str> {
    owner.map(|_| "owner")
}

/// Public part of the E2E metadata needed before opening (never the wrapped key).
fn public_kdf(row: &ShareRow) -> Option<Value> {
    if row.enc_mode() != EncMode::E2e || !row.passphrase_required {
        return None;
    }
    serde_json::from_str::<Value>(&row.enc_meta).ok()?.get("kdf").cloned()
}

fn decision_error(d: &Decision) -> AppError {
    match d {
        Decision::Allow => unreachable!(),
        Decision::Unavailable => AppError::NotFound,
        Decision::Denied => AppError::Access("denied", "you don't have access to this share".into()),
        Decision::NeedOwnerLogin => AppError::Access("need_owner_login", "sign in as the owner to open this share".into()),
        Decision::NeedOwnerMfa => AppError::Access("need_owner_mfa", "confirm your authenticator code to open this share".into()),
        Decision::NeedRecipientAuth(_) => AppError::Access("need_auth", "sign in to open this share".into()),
    }
}

/// What a visitor needs to do to open a share. Unknown, expired and burned shares all return 404.
#[utoipa::path(get, path = "/s/{slug}", tag = "recipient", params(("slug" = String, Path)),
    responses((status = 200, body = ShareInfo), (status = 404, body = crate::error::ErrorBody)))]
async fn share_info(
    State(state): State<AppState>,
    client: ClientInfo,
    owner: Option<Owner>,
    Path(slug): Path<String>,
) -> AppResult<Json<ShareInfo>> {
    if !state.limits.lookup.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let row = store::by_slug(&state.db, &slug).await?.ok_or(AppError::NotFound)?;
    let rules = store::rules(&state.db, &row.id).await?;
    let decision = policy::evaluate(&row.state(rules), &access_context(&client, owner.as_ref()));

    let (status, auth_methods) = match &decision {
        Decision::Unavailable => return Err(AppError::NotFound),
        Decision::Allow if row.passphrase_required => (AccessStatus::NeedPassphrase, vec![]),
        Decision::Allow => (AccessStatus::Ready, vec![]),
        Decision::Denied => (AccessStatus::Denied, vec![]),
        Decision::NeedOwnerLogin => (AccessStatus::NeedOwnerLogin, vec![]),
        Decision::NeedOwnerMfa => (AccessStatus::NeedOwnerMfa, vec![]),
        Decision::NeedRecipientAuth(m) => (AccessStatus::NeedAuth, m.clone()),
    };
    let visible = decision == Decision::Allow;
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
    }))
}

/// Records a wrong passphrase; destroys the share after too many.
async fn wrong_passphrase(state: &AppState, row: &ShareRow, client: &ClientInfo, owner: Option<&Owner>) -> AppError {
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
        store::log_access(&state.db, &row.id, client, identity_label(owner), "destroyed_bad_passphrase").await;
        tracing::warn!(share = %row.id, "share destroyed after too many wrong passphrases");
        return AppError::NotFound;
    }
    store::log_access(&state.db, &row.id, client, identity_label(owner), "wrong_passphrase").await;
    AppError::Access("wrong_passphrase", format!("wrong passphrase ({} attempts left)", limit - attempts))
}

/// Open a share: consumes one view and returns the content.
#[utoipa::path(post, path = "/s/{slug}/open", tag = "recipient", params(("slug" = String, Path)), request_body = OpenRequest,
    responses((status = 200, body = OpenResponse), (status = 403, body = crate::error::ErrorBody), (status = 404, body = crate::error::ErrorBody)))]
async fn open_share(
    State(state): State<AppState>,
    client: ClientInfo,
    owner: Option<Owner>,
    Path(slug): Path<String>,
    body: Option<Json<OpenRequest>>,
) -> AppResult<Json<OpenResponse>> {
    if !state.limits.open.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let req = body.map(|b| b.0).unwrap_or_default();
    let row = store::by_slug(&state.db, &slug).await?.ok_or(AppError::NotFound)?;
    let rules = store::rules(&state.db, &row.id).await?;
    let decision = policy::evaluate(&row.state(rules), &access_context(&client, owner.as_ref()));
    let who = identity_label(owner.as_ref());
    if decision != Decision::Allow {
        if decision != Decision::Unavailable {
            store::log_access(&state.db, &row.id, &client, who, &format!("blocked:{decision:?}").to_lowercase()).await;
        }
        return Err(decision_error(&decision));
    }
    let Some(ciphertext) = row.ciphertext.clone() else {
        return Err(AppError::NotFound);
    };

    // Check the passphrase (and decrypt server-side content) before spending a view.
    let (payload, dek) = match row.enc_mode() {
        EncMode::Server => {
            let pw = req.passphrase.filter(|p| !p.is_empty());
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
                    return Err(wrong_passphrase(&state, &row, &client, owner.as_ref()).await);
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
                    return Err(wrong_passphrase(&state, &row, &client, owner.as_ref()).await);
                }
            }
            (None, None)
        }
    };

    let mut tx = state.db.begin().await?;
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
    store::log_access(&state.db, &row.id, &client, who, if burned { "opened_burned" } else { "opened" }).await;

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
