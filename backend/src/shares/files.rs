//! File shares: chunked upload by the owner, chunked download by recipients.
//!
//! The manifest (names, sizes, note) is the share's normal encrypted payload. File bodies are
//! uploaded in 1 MiB chunks after the share is created and stored encrypted on disk:
//! - E2E: the browser encrypts each chunk; the server stores the ciphertext as-is.
//! - Server: the browser sends plaintext over TLS; the server encrypts each chunk with the share DEK,
//!   which it reads from the upload token (upload) or the download token (download).

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{model::*, store};
use crate::{
    app::AppState,
    auth::owner::Owner,
    blobs::{self, CHUNK_SIZE, E2E_CHUNK_OVERHEAD, SERVER_CHUNK_OVERHEAD},
    crypto,
    error::{AppError, AppResult},
    util::{now, sha256},
};

pub const UPLOAD_TOKEN_HEADER: &str = "x-upload-token";
pub const DOWNLOAD_TOKEN_HEADER: &str = "x-download-token";

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(upload_chunk))
        .routes(routes!(finalize_upload))
        .routes(routes!(download_chunk))
}

fn token_header<'a>(headers: &'a HeaderMap, name: &str) -> AppResult<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Forbidden(format!("missing {name}")))
}

fn stored_chunk_size(mode: EncMode) -> usize {
    CHUNK_SIZE
        + match mode {
            EncMode::E2e => E2E_CHUNK_OVERHEAD,
            EncMode::Server => SERVER_CHUNK_OVERHEAD,
        }
}

fn chunk_overhead(mode: EncMode) -> usize {
    stored_chunk_size(mode) - CHUNK_SIZE
}

/// Loads a share that is still being uploaded and checks the upload token.
async fn pending_share(state: &AppState, id: &str, headers: &HeaderMap) -> AppResult<(store::ShareRow, String)> {
    let token = token_header(headers, UPLOAD_TOKEN_HEADER)?.to_string();
    let row = store::by_id(&state.db, id).await?.ok_or(AppError::NotFound)?;
    if !row.upload_pending {
        return Err(AppError::Conflict("upload already finalised".into()));
    }
    let ok = row
        .upload_token_hash
        .as_deref()
        .is_some_and(|h| bool::from(sha256(token.as_bytes()).ct_eq(h)));
    if !ok {
        return Err(AppError::Forbidden("invalid upload token".into()));
    }
    Ok((row, token))
}

/// Upload chunk `n` of file `idx`. Chunks of a file must be sent in order; re-sending a chunk
/// replaces it and everything after it.
#[utoipa::path(put, path = "/shares/{id}/files/{idx}/chunks/{n}", tag = "files",
    params(("id" = String, Path), ("idx" = u32, Path), ("n" = u64, Path), ("x-upload-token" = String, Header)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 204), (status = 400, body = crate::error::ErrorBody), (status = 409, body = crate::error::ErrorBody)))]
async fn upload_chunk(
    State(state): State<AppState>,
    _owner: Owner,
    Path((id, idx, n)): Path<(String, u32, u64)>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<axum::http::StatusCode> {
    let (row, token) = pending_share(&state, &id, &headers).await?;
    let file = store::files(&state.db, &id)
        .await?
        .into_iter()
        .find(|f| f.idx == idx as i64)
        .ok_or(AppError::NotFound)?;
    let (size, chunks) = (file.size as u64, file.chunk_count as u64);
    if n >= chunks {
        return Err(AppError::BadRequest(format!("chunk {n} out of range (file has {chunks})")));
    }
    if n > file.uploaded_chunks as u64 {
        return Err(AppError::Conflict(format!("upload chunk {} first", file.uploaded_chunks)));
    }
    let plain_len = blobs::plain_chunk_len(size, n);
    let last = n + 1 == chunks;
    let mode = row.enc_mode();
    let stored = match mode {
        EncMode::E2e => {
            if body.len() != plain_len + E2E_CHUNK_OVERHEAD {
                return Err(AppError::BadRequest(format!(
                    "chunk must be {} bytes",
                    plain_len + E2E_CHUNK_OVERHEAD
                )));
            }
            body.to_vec()
        }
        EncMode::Server => {
            if body.len() != plain_len {
                return Err(AppError::BadRequest(format!("chunk must be {plain_len} bytes")));
            }
            let wrapped = row
                .upload_dek
                .as_deref()
                .ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing upload key")))?;
            let dek = crypto::unwrap_with_token(&token, &id, wrapped).map_err(|_| AppError::Forbidden("invalid upload token".into()))?;
            crypto::seal_raw(&dek, &crypto::chunk_aad(&id, idx, n as u32, last), &body)
        }
    };
    state
        .blobs
        .write_chunk(&id, idx, n, stored_chunk_size(mode), &stored)
        .await
        .map_err(anyhow::Error::from)?;
    sqlx::query("UPDATE share_files SET uploaded_chunks = ? WHERE share_id = ? AND idx = ?")
        .bind((n + 1) as i64)
        .bind(&id)
        .bind(idx as i64)
        .execute(&state.db)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Mark a file share's upload as complete; it becomes openable.
#[utoipa::path(post, path = "/shares/{id}/finalize", tag = "files",
    params(("id" = String, Path), ("x-upload-token" = String, Header)),
    responses((status = 200, body = ShareSummary), (status = 409, body = crate::error::ErrorBody)))]
async fn finalize_upload(
    State(state): State<AppState>,
    owner: Owner,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<ShareSummary>> {
    let (row, _) = pending_share(&state, &id, &headers).await?;
    let overhead = chunk_overhead(row.enc_mode()) as u64;
    for f in store::files(&state.db, &id).await? {
        let expected = f.size as u64 + f.chunk_count as u64 * overhead;
        let actual = state.blobs.file_len(&id, f.idx as u32).await.unwrap_or(0);
        if f.uploaded_chunks != f.chunk_count || actual != expected {
            return Err(AppError::Conflict(format!("file {} is incomplete", f.idx)));
        }
    }
    sqlx::query("UPDATE shares SET upload_pending = 0, upload_dek = NULL, upload_token_hash = NULL WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    tracing::info!(share = %id, "file upload finalised");
    super::handlers::get_share_summary(&state, owner, &id).await.map(Json)
}

/// Download chunk `n` of file `idx` with the token from a successful open.
/// E2E shares return ciphertext (decrypt in the browser); server shares return plaintext.
#[utoipa::path(get, path = "/s/{slug}/files/{idx}/chunks/{n}", tag = "recipient",
    params(("slug" = String, Path), ("idx" = u32, Path), ("n" = u64, Path), ("x-download-token" = String, Header)),
    responses((status = 200, content_type = "application/octet-stream", body = Vec<u8>), (status = 403, body = crate::error::ErrorBody)))]
async fn download_chunk(
    State(state): State<AppState>,
    Path((slug, idx, n)): Path<(String, u32, u64)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let token = token_header(&headers, DOWNLOAD_TOKEN_HEADER)?;
    let row = store::by_slug(&state.db, &slug).await?.ok_or(AppError::NotFound)?;
    let grant: Option<(Option<Vec<u8>>,)> =
        sqlx::query_as("SELECT wrapped_dek FROM download_tokens WHERE token_hash = ? AND share_id = ? AND expires_at > ?")
            .bind(sha256(token.as_bytes()))
            .bind(&row.id)
            .bind(now())
            .fetch_optional(&state.db)
            .await?;
    let Some((wrapped_dek,)) = grant else {
        return Err(AppError::Access(
            "download_expired",
            "this download link has expired; open the share again".into(),
        ));
    };
    let file = store::files(&state.db, &row.id)
        .await?
        .into_iter()
        .find(|f| f.idx == idx as i64)
        .ok_or(AppError::NotFound)?;
    let chunks = file.chunk_count as u64;
    if n >= chunks {
        return Err(AppError::NotFound);
    }
    let mode = row.enc_mode();
    let stored = state
        .blobs
        .read_chunk(&row.id, idx, n, stored_chunk_size(mode))
        .await
        .map_err(|_| AppError::NotFound)?;
    let body = match mode {
        EncMode::E2e => stored,
        EncMode::Server => {
            let wrapped = wrapped_dek.ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing download key")))?;
            let dek =
                crypto::unwrap_with_token(token, &row.id, &wrapped).map_err(|_| AppError::Forbidden("invalid download token".into()))?;
            crypto::open_raw(&dek, &crypto::chunk_aad(&row.id, idx, n as u32, n + 1 == chunks), &stored)
                .map_err(|_| AppError::Internal(anyhow::anyhow!("chunk failed to decrypt")))?
        }
    };
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
}
