//! Router assembly: API routes, OpenAPI document, security middleware and static frontend.

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderName, HeaderValue, Method, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::{app::AppState, audit, auth, error::AppError, shares, static_files};

#[derive(OpenApi)]
#[openapi(info(title = "ShareSomething API", version = "0.1.0"))]
struct ApiDoc;

pub fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi()).nest(
        "/api",
        auth::users::router()
            .merge(auth::passkey::router())
            .merge(auth::recipient::router())
            .merge(auth::oidc::router())
            .merge(shares::handlers::router())
            .merge(shares::files::router())
            .merge(shares::templates::router())
            .merge(audit::api::router())
            .merge(shares::approvals::router())
            .merge(crate::notify::router())
            .merge(crate::org::router()),
    )
}

pub fn openapi_json() -> String {
    api_router().split_for_parts().1.to_pretty_json().expect("openapi serialises")
}

const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; \
    connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn router(state: AppState) -> Router {
    let (api, _) = api_router().split_for_parts();
    // Big enough for a text payload (base64) or one file chunk.
    let body_limit = (state.cfg.max_text_bytes * 2).max(crate::blobs::CHUNK_SIZE) + 64 * 1024;
    let mut app = api
        .layer(middleware::from_fn_with_state(state.clone(), origin_check))
        .layer(middleware::from_fn_with_state(state.clone(), api_rate_limit))
        .layer(DefaultBodyLimit::max(body_limit))
        .route("/healthz", get(healthz))
        .route(
            "/api/openapi.json",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], openapi_json()) }),
        )
        .fallback(static_files::serve)
        .with_state(state.clone());

    let headers: &[(&str, &str)] = &[
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        ("permissions-policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    ];
    for (k, v) in headers {
        app = app.layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static(k),
            HeaderValue::from_static(v),
        ));
    }
    if state.cfg.cookie_secure() {
        app = app.layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        ));
    }
    app.layer(middleware::from_fn(no_store_api)).layer(TraceLayer::new_for_http())
}

async fn healthz(State(state): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "ok".into_response(),
        Err(e) => AppError::Internal(e.into()).into_response(),
    }
}

/// API responses may carry secrets: never cache them.
async fn no_store_api(req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    if is_api {
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// Per-IP request budget for the API. Chunk uploads/downloads are excluded: they're already
/// bound to an unguessable token, and a large file legitimately needs thousands of them.
async fn api_rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Result<Response, AppError> {
    let path = req.uri().path();
    if !path.contains("/chunks/") && !path.ends_with("/download") {
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0.ip());
        if let Some(peer) = peer {
            let client = state.proxy.resolve(peer, req.headers());
            if !state.limits.api.check(&client.ip.to_string()) {
                return Err(AppError::TooManyRequests);
            }
        }
    }
    Ok(next.run(req).await)
}

/// CSRF defence in depth on top of SameSite=Strict cookies: state-changing requests must come
/// from our own origin.
async fn origin_check(State(state): State<AppState>, req: Request, next: Next) -> Result<Response, AppError> {
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let h = req.headers();
        let fetch_site = h.get("sec-fetch-site").and_then(|v| v.to_str().ok());
        let origin_ok = match h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            Some(o) if o == state.cfg.origin() => true,
            // With `Referrer-Policy: no-referrer`, browsers send `Origin: null` on our own form
            // posts (streamed file downloads). Sec-Fetch-Site can't be set by page script, so
            // trust "null" only when the browser itself vouches for a same-origin request.
            Some("null") => fetch_site == Some("same-origin"),
            Some(_) => false,
            None => fetch_site.is_none_or(|s| s == "same-origin" || s == "none"),
        };
        if !origin_ok {
            return Err(AppError::Forbidden("cross-origin request rejected".into()));
        }
    }
    Ok(next.run(req).await)
}
