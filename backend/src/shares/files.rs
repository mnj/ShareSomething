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
    audit::Action,
    auth::users::CurrentUser,
    blobs::{self, CHUNK_SIZE, E2E_CHUNK_OVERHEAD, SERVER_CHUNK_OVERHEAD},
    crypto,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    util::{now, sha256},
};

pub const UPLOAD_TOKEN_HEADER: &str = "x-upload-token";
pub const DOWNLOAD_TOKEN_HEADER: &str = "x-download-token";

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(upload_chunk))
        .routes(routes!(finalize_upload))
        .routes(routes!(download_chunk))
        .routes(routes!(download_stream))
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
async fn pending_share(state: &AppState, user: &CurrentUser, id: &str, headers: &HeaderMap) -> AppResult<(store::ShareRow, String)> {
    let token = token_header(headers, UPLOAD_TOKEN_HEADER)?.to_string();
    let row = store::by_id(&state.db, id)
        .await?
        .filter(|r| r.owner_id == user.id)
        .ok_or(AppError::NotFound)?;
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
    user: CurrentUser,
    Path((id, idx, n)): Path<(String, u32, u64)>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<axum::http::StatusCode> {
    let (row, token) = pending_share(&state, &user, &id, &headers).await?;
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
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<ShareSummary>> {
    let (row, _) = pending_share(&state, &user, &id, &headers).await?;
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
    let files = store::files(&state.db, &id).await?;
    state
        .audit
        .record(
            row.event(Action::ShareFileUploaded)
                .user(user.id, &user.label)
                .client(&client)
                .detail("files", files.len())
                .detail("bytes", files.iter().map(|f| f.size).sum::<i64>()),
        )
        .await?;
    super::handlers::get_share_summary(&state, &user, &id).await.map(Json)
}

/// A valid download grant: the share, the file being fetched and (server mode) the DEK.
struct Grant {
    row: store::ShareRow,
    file: store::FileRow,
    dek: Option<crypto::Dek>,
}

async fn grant(state: &AppState, slug: &str, idx: u32, token: &str) -> AppResult<Grant> {
    let row = store::by_slug(&state.db, slug).await?.ok_or(AppError::NotFound)?;
    let found: Option<(Option<Vec<u8>>,)> =
        sqlx::query_as("SELECT wrapped_dek FROM download_tokens WHERE token_hash = ? AND share_id = ? AND expires_at > ?")
            .bind(sha256(token.as_bytes()))
            .bind(&row.id)
            .bind(now())
            .fetch_optional(&state.db)
            .await?;
    let Some((wrapped_dek,)) = found else {
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
    let dek = match row.enc_mode() {
        EncMode::E2e => None,
        EncMode::Server => {
            let wrapped = wrapped_dek.ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing download key")))?;
            Some(crypto::unwrap_with_token(token, &row.id, &wrapped).map_err(|_| AppError::Forbidden("invalid download token".into()))?)
        }
    };
    Ok(Grant { row, file, dek })
}

/// Reads chunk `n` and, for server mode, decrypts it.
async fn chunk_bytes(state: &AppState, g: &Grant, idx: u32, n: u64) -> AppResult<Vec<u8>> {
    let chunks = g.file.chunk_count as u64;
    let stored = state
        .blobs
        .read_chunk(&g.row.id, idx, n, stored_chunk_size(g.row.enc_mode()))
        .await
        .map_err(|_| AppError::NotFound)?;
    match &g.dek {
        None => Ok(stored),
        Some(dek) => crypto::open_raw(dek, &crypto::chunk_aad(&g.row.id, idx, n as u32, n + 1 == chunks), &stored)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("chunk failed to decrypt"))),
    }
}

/// Download chunk `n` of file `idx` with the token from a successful open.
/// E2E shares return ciphertext (decrypt in the browser); server shares return plaintext.
#[utoipa::path(get, path = "/s/{slug}/files/{idx}/chunks/{n}", tag = "recipient",
    params(("slug" = String, Path), ("idx" = u32, Path), ("n" = u64, Path), ("x-download-token" = String, Header)),
    responses((status = 200, content_type = "application/octet-stream", body = Vec<u8>), (status = 403, body = crate::error::ErrorBody)))]
async fn download_chunk(
    State(state): State<AppState>,
    client: ClientInfo,
    Path((slug, idx, n)): Path<(String, u32, u64)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let token = token_header(&headers, DOWNLOAD_TOKEN_HEADER)?;
    let g = grant(&state, &slug, idx, token).await?;
    if n >= g.file.chunk_count as u64 {
        return Err(AppError::NotFound);
    }
    // One record per file download (at its first chunk), not per chunk.
    if n == 0 {
        state
            .audit
            .record(
                g.row
                    .event(Action::ShareFileDownloaded)
                    .recipient(None)
                    .client(&client)
                    .detail("file_index", idx)
                    .detail("bytes", g.file.size)
                    .detail("via", "chunks"),
            )
            .await?;
    }
    let body = chunk_bytes(&state, &g, idx, n).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct StreamForm {
    /// Download token from the open response.
    pub token: String,
    /// File name for the browser's save dialog.
    pub name: String,
}

/// `Content-Disposition: attachment` with an ASCII fallback and an RFC 5987 UTF-8 name.
fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if (c.is_ascii_graphic() && !matches!(c, '"' | '\\' | ';' | '%')) || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut encoded = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

/// Server-mode only: decrypt and stream a whole file straight into the browser's download
/// manager (submitted as a form, so nothing is buffered in page memory).
#[utoipa::path(post, path = "/s/{slug}/files/{idx}/download", tag = "recipient",
    params(("slug" = String, Path), ("idx" = u32, Path)),
    request_body(content = StreamForm, content_type = "application/x-www-form-urlencoded"),
    responses((status = 200, content_type = "application/octet-stream", body = Vec<u8>), (status = 403, body = crate::error::ErrorBody)))]
async fn download_stream(
    State(state): State<AppState>,
    client: ClientInfo,
    Path((slug, idx)): Path<(String, u32)>,
    axum::Form(form): axum::Form<StreamForm>,
) -> AppResult<Response> {
    let g = grant(&state, &slug, idx, &form.token).await?;
    state
        .audit
        .record(
            g.row
                .event(Action::ShareFileDownloaded)
                .recipient(None)
                .client(&client)
                .detail("file_index", idx)
                .detail("bytes", g.file.size)
                .detail("via", "stream"),
        )
        .await?;
    if g.dek.is_none() {
        return Err(AppError::BadRequest(
            "end-to-end encrypted files are decrypted in the browser".into(),
        ));
    }
    let size = g.file.size;
    let chunks = g.file.chunk_count as u64;
    let stream = futures_util::stream::unfold((state, g, 0u64), move |(state, g, n)| async move {
        if n >= chunks {
            return None;
        }
        let item = chunk_bytes(&state, &g, idx, n).await.map(axum::body::Bytes::from).map_err(|e| {
            tracing::error!(error = %e, "streamed download failed");
            std::io::Error::other("download failed")
        });
        Some((item, (state, g, n + 1)))
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, size.to_string()),
            (header::CONTENT_DISPOSITION, content_disposition(&form.name)),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    #[test]
    fn content_disposition_is_safe() {
        let cd = super::content_disposition("r\u{e9}sum\u{e9} \"x\";\r\n.pdf");
        assert!(!cd.contains('\r') && !cd.contains('\n'));
        assert!(cd.starts_with("attachment; filename=\"r_sum_ _x____.pdf\""), "{cd}");
        assert!(cd.ends_with("filename*=UTF-8''r%C3%A9sum%C3%A9%20%22x%22%3B%0D%0A.pdf"), "{cd}");
    }
}
