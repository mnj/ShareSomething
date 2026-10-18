//! Audit trail API for admins and auditors: query, export (JSONL/CSV), verify the chain and see
//! SIEM delivery status.

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Sqlite};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{Action, Record, VerifyReport, format, ship::ShipperStatus};
use crate::{
    app::AppState,
    auth::users::CurrentUser,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
};

#[derive(Debug, Default, Clone, Deserialize, Serialize, IntoParams)]
pub struct AuditFilter {
    /// Only records with `seq` below this (pagination cursor from `next_before`).
    pub before: Option<i64>,
    /// Page size, max 500 (default 100).
    pub limit: Option<i64>,
    /// Action, or a prefix ending in `.` such as `auth.` or `share.`.
    pub action: Option<String>,
    /// Actor label (email/identity) or id, exact match.
    pub actor: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    /// `success`, `denied` or `error`.
    pub outcome: Option<String>,
    /// Unix seconds, inclusive.
    pub from: Option<i64>,
    /// Unix seconds, exclusive.
    pub to: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditPage {
    pub events: Vec<Record>,
    /// Pass as `before` to fetch the next (older) page.
    pub next_before: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ExportParams {
    /// `jsonl` (ECS documents, default) or `csv`.
    pub format: Option<String>,
}

fn require_auditor(user: &CurrentUser) -> AppResult<()> {
    if !user.can_audit() {
        return Err(AppError::Forbidden("audit access requires the admin or auditor role".into()));
    }
    Ok(())
}

fn push_filters<'a>(qb: &mut QueryBuilder<'a, Sqlite>, f: &'a AuditFilter) {
    qb.push(" WHERE 1 = 1");
    if let Some(v) = f.before {
        qb.push(" AND seq < ").push_bind(v);
    }
    if let Some(v) = f.action.as_deref().filter(|v| !v.is_empty()) {
        if let Some(prefix) = v.strip_suffix('.') {
            qb.push(" AND (action = ")
                .push_bind(prefix)
                .push(" OR substr(action, 1, ")
                .push_bind(v.len() as i64)
                .push(") = ")
                .push_bind(v)
                .push(")");
        } else {
            qb.push(" AND action = ").push_bind(v);
        }
    }
    if let Some(v) = f.actor.as_deref().filter(|v| !v.is_empty()) {
        qb.push(" AND (actor_label = ")
            .push_bind(v)
            .push(" OR actor_id = ")
            .push_bind(v)
            .push(")");
    }
    if let Some(v) = f.target_type.as_deref().filter(|v| !v.is_empty()) {
        qb.push(" AND target_type = ").push_bind(v);
    }
    if let Some(v) = f.target_id.as_deref().filter(|v| !v.is_empty()) {
        qb.push(" AND target_id = ").push_bind(v);
    }
    if let Some(v) = f.outcome.as_deref().filter(|v| !v.is_empty()) {
        qb.push(" AND outcome = ").push_bind(v);
    }
    if let Some(v) = f.from {
        qb.push(" AND ts >= ").push_bind(v);
    }
    if let Some(v) = f.to {
        qb.push(" AND ts < ").push_bind(v);
    }
}

pub async fn query(db: &sqlx::SqlitePool, f: &AuditFilter) -> sqlx::Result<AuditPage> {
    let limit = f.limit.unwrap_or(100).clamp(1, 500);
    let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM audit_events");
    push_filters(&mut qb, f);
    qb.push(" ORDER BY seq DESC LIMIT ").push_bind(limit + 1);
    let mut events: Vec<Record> = qb.build_query_as().fetch_all(db).await?;
    let more = events.len() as i64 > limit;
    events.truncate(limit as usize);
    let next_before = if more { events.last().map(|r| r.seq) } else { None };
    Ok(AuditPage { events, next_before })
}

/// Query the audit trail (newest first).
#[utoipa::path(get, path = "/audit", tag = "audit", operation_id = "audit_list", params(AuditFilter),
    responses((status = 200, body = AuditPage), (status = 403, body = crate::error::ErrorBody)))]
async fn list(State(state): State<AppState>, user: CurrentUser, Query(f): Query<AuditFilter>) -> AppResult<Json<AuditPage>> {
    require_auditor(&user)?;
    Ok(Json(query(&state.db, &f).await?))
}

/// Spreadsheet apps execute cells starting with these; neutralise them in CSV exports.
fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

const CSV_HEADER: &str = "seq,time,action,outcome,actor_type,actor_id,actor,ip,user_agent,target_type,target_id,target,details,hash\n";

fn csv_row(r: &Record) -> String {
    let o = |v: &Option<String>| csv_cell(v.as_deref().unwrap_or(""));
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        r.seq,
        csv_cell(&format::rfc3339(r.ts)),
        csv_cell(&r.action),
        csv_cell(&r.outcome),
        csv_cell(&r.actor_type),
        o(&r.actor_id),
        o(&r.actor_label),
        o(&r.ip),
        o(&r.user_agent),
        o(&r.target_type),
        o(&r.target_id),
        o(&r.target_label),
        csv_cell(&r.details),
        csv_cell(&super::hex(&r.hash)),
    )
}

/// Export matching records (oldest first) as JSON lines (ECS) or CSV. The export itself is audited.
#[utoipa::path(get, path = "/audit/export", tag = "audit", operation_id = "audit_export", params(AuditFilter, ExportParams),
    responses((status = 200, description = "JSONL or CSV stream"), (status = 403, body = crate::error::ErrorBody)))]
async fn export(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Query(f): Query<AuditFilter>,
    Query(p): Query<ExportParams>,
) -> AppResult<Response> {
    require_auditor(&user)?;
    let csv = match p.format.as_deref().unwrap_or("jsonl") {
        "csv" => true,
        "jsonl" => false,
        _ => return Err(AppError::BadRequest("format must be jsonl or csv".into())),
    };
    state
        .audit
        .record(
            user.event(Action::AuditExported)
                .client(&client)
                .detail("format", if csv { "csv" } else { "jsonl" })
                .detail("filter", &f),
        )
        .await?;
    let observer = state.observer();
    let db = state.db.clone();
    // Stream oldest-first in pages, so exports of any size use constant memory.
    let stream = futures_util::stream::unfold((0i64, true, f), move |(after, first, f)| {
        let (db, observer) = (db.clone(), observer.clone());
        async move {
            let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM audit_events");
            let page_filter = AuditFilter { before: None, ..f.clone() };
            push_filters(&mut qb, &page_filter);
            if let Some(b) = f.before {
                qb.push(" AND seq < ").push_bind(b);
            }
            qb.push(" AND seq > ").push_bind(after).push(" ORDER BY seq LIMIT 1000");
            let rows: Vec<Record> = match qb.build_query_as().fetch_all(&db).await {
                Ok(r) => r,
                Err(e) => return Some((Err(std::io::Error::other(e)), (after, false, f))),
            };
            if rows.is_empty() && !first {
                return None;
            }
            let mut out = String::new();
            if first && csv {
                out.push_str(CSV_HEADER);
            }
            for r in &rows {
                if csv {
                    out.push_str(&csv_row(r));
                } else {
                    out.push_str(&format::ecs(r, &observer).to_string());
                    out.push('\n');
                }
            }
            let next = rows.last().map(|r| r.seq).unwrap_or(i64::MAX);
            Some((Ok::<_, std::io::Error>(Bytes::from(out)), (next, false, f)))
        }
    });
    let (ctype, ext) = if csv {
        ("text/csv; charset=utf-8", "csv")
    } else {
        ("application/x-ndjson", "jsonl")
    };
    Ok((
        [
            (header::CONTENT_TYPE, ctype.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"sharesomething-audit.{ext}\""),
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

/// Re-verify the hash chain of the whole audit trail.
#[utoipa::path(get, path = "/audit/verify", tag = "audit", operation_id = "audit_verify",
    responses((status = 200, body = VerifyReport), (status = 403, body = crate::error::ErrorBody)))]
async fn verify(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<VerifyReport>> {
    require_auditor(&user)?;
    Ok(Json(super::verify(&state.db).await?))
}

/// Delivery status of each configured SIEM shipper.
#[utoipa::path(get, path = "/audit/shippers", tag = "audit", operation_id = "audit_shippers",
    responses((status = 200, body = Vec<ShipperStatus>), (status = 403, body = crate::error::ErrorBody)))]
async fn shippers(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<Vec<ShipperStatus>>> {
    require_auditor(&user)?;
    Ok(Json(super::ship::status(&state.db, &state.cfg.audit.shippers).await?))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(export))
        .routes(routes!(verify))
        .routes(routes!(shippers))
}

#[cfg(test)]
mod tests {
    #[test]
    fn csv_neutralises_formulas_and_quotes() {
        assert_eq!(super::csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(super::csv_cell("bob@acme.com"), "\"bob@acme.com\"");
        assert_eq!(super::csv_cell("-1"), "\"'-1\"");
    }
}
