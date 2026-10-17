//! End-to-end API tests against a real router and a temporary SQLite database.

use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{
    app::AppState,
    auth::{owner::hash_password, totp},
    config::{Config, ProxyMode},
    crypto::MasterKey,
    util::now,
};

const PASSWORD: &str = "correct horse battery staple";
const ORIGIN: &str = "http://localhost:8080";

struct TestApp {
    app: Router,
    state: AppState,
    totp_secret: String,
    _dir: TempDir,
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Sent = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

struct Resp {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
}

impl TestApp {
    async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    async fn with_config(f: impl FnOnce(&mut Config)) -> Self {
        Self::build(f, None).await
    }

    /// App whose outgoing email is captured in memory.
    async fn with_email(f: impl FnOnce(&mut Config)) -> (Self, Sent) {
        let sent = Sent::default();
        (Self::build(f, Some(crate::mailer::Mailer::Capture(sent.clone()))).await, sent)
    }

    async fn build(f: impl FnOnce(&mut Config), mailer: Option<crate::mailer::Mailer>) -> Self {
        let dir = std::env::temp_dir().join(format!("ss-test-{}", uuid::Uuid::new_v4()));
        let mut cfg = Config {
            data_dir: dir.clone(),
            ..Config::default()
        };
        f(&mut cfg);
        let db = crate::db::connect(&dir).await.unwrap();
        let totp_secret = totp::new_secret();
        sqlx::query("INSERT INTO owner (id, password_hash, totp_secret, created_at) VALUES (1, ?, ?, ?)")
            .bind(hash_password(PASSWORD).unwrap())
            .bind(&totp_secret)
            .bind(now())
            .execute(&db)
            .await
            .unwrap();
        let mut state = AppState::new(cfg, db, MasterKey::new([42; 32])).unwrap();
        if let Some(m) = mailer {
            state.set_mailer(m);
        }
        Self {
            app: crate::api::router(state.clone()),
            state,
            totp_secret,
            _dir: TempDir(dir),
        }
    }

    async fn req(&self, method: &str, uri: &str, body: Option<Value>, cookie: Option<&str>, peer: &str, extra: &[(&str, &str)]) -> Resp {
        self.req_full(method, uri, body, cookie, peer, extra).await.0
    }

    /// Like `req`, also returning response headers (for redirects and cookies).
    async fn req_full(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        cookie: Option<&str>,
        peer: &str,
        extra: &[(&str, &str)],
    ) -> (Resp, axum::http::HeaderMap) {
        let mut b = Request::builder().method(method).uri(uri);
        if !extra.iter().any(|(k, _)| k.eq_ignore_ascii_case("origin")) {
            b = b.header(header::ORIGIN, ORIGIN);
        }
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let mut req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        req.extensions_mut()
            .insert(ConnectInfo(format!("{peer}:5000").parse::<SocketAddr>().unwrap()));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let cookie = headers
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (Resp { status, body, cookie }, headers)
    }

    async fn get(&self, uri: &str, cookie: Option<&str>) -> Resp {
        self.req("GET", uri, None, cookie, "198.51.100.1", &[]).await
    }

    async fn post(&self, uri: &str, body: Value, cookie: Option<&str>) -> Resp {
        self.req("POST", uri, Some(body), cookie, "198.51.100.1", &[]).await
    }

    async fn login(&self) -> String {
        let code = totp::code_at(&self.totp_secret, now());
        let r = self
            .post("/api/auth/login", json!({"password": PASSWORD, "totp": code}), None)
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        r.cookie.unwrap()
    }

    async fn create(&self, cookie: &str, body: Value) -> Value {
        self.create_full(cookie, body).await["share"].clone()
    }

    async fn create_full(&self, cookie: &str, body: Value) -> Value {
        let r = self.post("/api/shares", body, Some(cookie)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body
    }

    /// Raw-bytes request (file chunks); returns status and body bytes.
    async fn raw(&self, method: &str, uri: &str, body: Vec<u8>, cookie: Option<&str>, headers: &[(&str, &str)]) -> (StatusCode, Vec<u8>) {
        let mut b = Request::builder().method(method).uri(uri).header(header::ORIGIN, ORIGIN);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(Body::from(body)).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("198.51.100.1:5000".parse::<SocketAddr>().unwrap()));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        (status, res.into_body().collect().await.unwrap().to_bytes().to_vec())
    }
}

fn public_text(text: &str) -> Value {
    json!({
        "kind": "text", "enc_mode": "server", "slug": {},
        "policy": [{"group": "include", "type": "everyone"}],
        "payload": {"kind": "text", "text": text},
    })
}

#[tokio::test]
async fn login_requires_totp_and_rejects_replay() {
    let t = TestApp::new().await;
    let r = t.post("/api/auth/login", json!({"password": PASSWORD}), None).await;
    assert_eq!(
        (r.status, r.body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("totp_required"))
    );
    let r = t
        .post("/api/auth/login", json!({"password": "wrong", "totp": "123456"}), None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let code = totp::code_at(&t.totp_secret, now());
    let r = t.post("/api/auth/login", json!({"password": PASSWORD, "totp": code}), None).await;
    assert_eq!(r.status, StatusCode::OK);
    let cookie = r.cookie.unwrap();
    assert_eq!(t.get("/api/auth/me", Some(&cookie)).await.body["authenticated"], true);
    // Same code again is a replay.
    let r = t.post("/api/auth/login", json!({"password": PASSWORD, "totp": code}), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    assert_eq!(t.get("/api/shares", None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.get("/api/shares", Some(&cookie)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn read_once_server_share_burns() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("hello there");
    body["max_views"] = json!(1);
    body["title"] = json!("greeting");
    let share = t.create(&c, body).await;
    let slug = share["slug"].as_str().unwrap();
    assert_eq!(slug.len(), 8);

    let info = t.get(&format!("/api/s/{slug}"), None).await;
    assert_eq!(info.body["status"], "ready");
    assert_eq!(info.body["title"], "greeting");
    assert_eq!(info.body["views_left"], 1);
    // Looking does not consume a view.
    assert_eq!(t.get(&format!("/api/s/{slug}"), None).await.body["views_left"], 1);

    let open = t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    assert_eq!(open.status, StatusCode::OK, "{}", open.body);
    assert_eq!(open.body["payload"]["text"], "hello there");
    assert_eq!(open.body["burned"], true);

    assert_eq!(
        t.post(&format!("/api/s/{slug}/open"), json!({}), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(t.get(&format!("/api/s/{slug}"), None).await.status, StatusCode::NOT_FOUND);

    let list = t.get("/api/shares", Some(&c)).await;
    assert_eq!(list.body[0]["status"], "burned");
    let (ct,): (Option<Vec<u8>>,) = sqlx::query_as("SELECT ciphertext FROM shares")
        .fetch_one(&t.state.db)
        .await
        .unwrap();
    assert!(ct.is_none(), "content must be wiped after burn");
    let log = t.get(&format!("/api/shares/{}/log", share["id"].as_str().unwrap()), Some(&c)).await;
    assert_eq!(log.body[0]["outcome"], "opened_burned");
}

#[tokio::test]
async fn concurrent_opens_release_exactly_once() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("only once");
    body["max_views"] = json!(1);
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();

    let uri = format!("/api/s/{slug}/open");
    let results = futures::future::join_all((0..16).map(|_| t.post(&uri, json!({}), None))).await;
    let results: Vec<_> = results.iter().map(|r| r.status).collect();
    let ok = results.iter().filter(|s| **s == StatusCode::OK).count();
    assert_eq!(ok, 1, "statuses: {results:?}");
}

#[tokio::test]
async fn server_passphrase_checked_before_view_is_spent() {
    let t = TestApp::with_config(|c| c.max_passphrase_attempts = 3).await;
    let c = t.login().await;
    let mut body = public_text("wifi: hunter2");
    body["max_views"] = json!(1);
    body["passphrase"] = json!("open sesame");
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();

    assert_eq!(t.get(&format!("/api/s/{slug}"), None).await.body["status"], "need_passphrase");
    let r = t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    assert_eq!(r.body["error"], "need_passphrase");
    let r = t.post(&format!("/api/s/{slug}/open"), json!({"passphrase": "nope"}), None).await;
    assert_eq!(r.body["error"], "wrong_passphrase");
    let r = t
        .post(&format!("/api/s/{slug}/open"), json!({"passphrase": "open sesame"}), None)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["payload"]["text"], "wifi: hunter2");
}

#[tokio::test]
async fn too_many_wrong_passphrases_destroy_share() {
    let t = TestApp::with_config(|c| c.max_passphrase_attempts = 2).await;
    let c = t.login().await;
    let mut body = public_text("x");
    body["passphrase"] = json!("right");
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();
    let uri = format!("/api/s/{slug}/open");
    assert_eq!(
        t.post(&uri, json!({"passphrase": "a"}), None).await.body["error"],
        "wrong_passphrase"
    );
    assert_eq!(t.post(&uri, json!({"passphrase": "b"}), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        t.post(&uri, json!({"passphrase": "right"}), None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn e2e_share_with_verifier() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let verifier = [9u8; 32];
    let body = json!({
        "kind": "credential", "enc_mode": "e2e", "slug": {"generator": "words", "options": {"count": 3}},
        "policy": [{"group": "include", "type": "everyone"}],
        "ciphertext": B64.encode([1u8; 64]),
        "enc_meta": {"v": 1, "key": "passphrase", "kdf": {"alg": "argon2id", "salt": "c2FsdA=="}, "wrapped_key": "secret-ish"},
        "passphrase_verifier": B64.encode(verifier),
    });
    let share = t.create(&c, body).await;
    let slug = share["slug"].as_str().unwrap();
    assert_eq!(slug.split('-').count(), 3);

    let info = t.get(&format!("/api/s/{slug}"), None).await;
    assert_eq!(info.body["status"], "need_passphrase");
    assert_eq!(info.body["kdf"]["alg"], "argon2id");
    assert!(
        !info.body.to_string().contains("wrapped_key"),
        "wrapped key must not leak before open"
    );

    let uri = format!("/api/s/{slug}/open");
    assert_eq!(t.post(&uri, json!({}), None).await.body["error"], "need_passphrase");
    assert_eq!(
        t.post(&uri, json!({"passphrase_verifier": B64.encode([8u8; 32])}), None).await.body["error"],
        "wrong_passphrase"
    );
    let r = t.post(&uri, json!({"passphrase_verifier": B64.encode(verifier)}), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["ciphertext"], B64.encode([1u8; 64]));
    assert_eq!(r.body["enc_meta"]["wrapped_key"], "secret-ish");
    assert!(r.body["payload"].is_null());
}

#[tokio::test]
async fn e2e_rejects_plaintext_fields() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("leak");
    body["enc_mode"] = json!("e2e");
    let r = t.post("/api/shares", body, Some(&c)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ip_policy_behind_cloudflare() {
    let t = TestApp::with_config(|c| {
        c.proxy.mode = ProxyMode::Cloudflare;
        c.proxy.trusted_proxies = vec!["127.0.0.1".into()];
    })
    .await;
    let c = t.login().await;
    let mut body = public_text("office only");
    body["policy"] = json!([{"group": "include", "type": "ip", "cidrs": ["10.0.0.0/8"]}]);
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();
    let uri = format!("/api/s/{slug}");

    let via_tunnel = |ip: &'static str| [("cf-connecting-ip", ip)];
    let r = t.req("GET", &uri, None, None, "127.0.0.1", &via_tunnel("10.9.9.9")).await;
    assert_eq!(r.body["status"], "ready");
    let r = t.req("GET", &uri, None, None, "127.0.0.1", &via_tunnel("8.8.8.8")).await;
    assert_eq!(r.body["status"], "denied");
    assert!(r.body["title"].is_null() && r.body["kind"].is_null());
    // Spoofed header from an untrusted peer is ignored.
    let r = t.req("GET", &uri, None, None, "203.0.113.1", &via_tunnel("10.9.9.9")).await;
    assert_eq!(r.body["status"], "denied");
    let r = t
        .req(
            "POST",
            &format!("{uri}/open"),
            Some(json!({})),
            None,
            "203.0.113.1",
            &via_tunnel("10.9.9.9"),
        )
        .await;
    assert_eq!(r.body["error"], "denied");
}

#[tokio::test]
async fn owner_only_with_mfa_step_up() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("api key");
    body["policy"] = json!([{"group": "include", "type": "owner"}]);
    body["require_owner_mfa"] = json!(true);
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();
    let uri = format!("/api/s/{slug}");

    assert_eq!(t.get(&uri, None).await.body["status"], "need_owner_login");
    // Login included a TOTP code, so MFA is fresh.
    assert_eq!(t.get(&uri, Some(&c)).await.body["status"], "ready");
    let r = t.post(&format!("{uri}/open"), json!({}), Some(&c)).await;
    assert_eq!(r.body["payload"]["text"], "api key");

    // Age the step-up and check that a new one is demanded.
    sqlx::query("UPDATE owner_sessions SET mfa_at = ?")
        .bind(now() - 3600)
        .execute(&t.state.db)
        .await
        .unwrap();
    assert_eq!(t.get(&uri, Some(&c)).await.body["status"], "need_owner_mfa");
    let next_code = totp::code_at(&t.totp_secret, now() + 30);
    let r = t.post("/api/auth/step-up", json!({"totp": next_code}), Some(&c)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(t.get(&uri, Some(&c)).await.body["status"], "ready");
}

#[tokio::test]
async fn cross_origin_post_rejected() {
    let t = TestApp::new().await;
    let c = t.login().await;
    // `Origin: null` (no-referrer form posts) only passes with a same-origin Sec-Fetch-Site.
    let post =
        |h: &'static [(&'static str, &'static str)]| t.req("POST", "/api/shares", Some(public_text("x")), Some(&c), "198.51.100.1", h);
    assert_eq!(
        post(&[("origin", "null"), ("sec-fetch-site", "same-origin")]).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        post(&[("origin", "null"), ("sec-fetch-site", "cross-site")]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(&[("origin", "null"), ("sec-fetch-site", "same-site")]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(&[("origin", "null")]).await.status,
        StatusCode::FORBIDDEN,
        "null without fetch metadata"
    );
    let r = t
        .req(
            "POST",
            "/api/shares",
            Some(public_text("x")),
            Some(&c),
            "198.51.100.1",
            &[("origin", "https://evil.example")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .req(
            "POST",
            "/api/shares",
            Some(public_text("x")),
            Some(&c),
            "198.51.100.1",
            &[("origin", ORIGIN)],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
}

#[tokio::test]
async fn custom_slug_conflict_and_validation() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("x");
    body["slug"] = json!({"generator": "custom", "options": {"value": "wifi-guest"}});
    let share = t.create(&c, body.clone()).await;
    assert_eq!(share["url"], "http://localhost:8080/s/wifi-guest");
    assert_eq!(share["entropy_bits"], 0.0);
    assert_eq!(t.post("/api/shares", body.clone(), Some(&c)).await.status, StatusCode::CONFLICT);
    body["slug"]["options"]["value"] = json!("../etc");
    assert_eq!(t.post("/api/shares", body, Some(&c)).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_validation() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("x");
    body["policy"] = json!([{"group": "require", "type": "ip", "cidrs": ["10.0.0.0/8"]}]);
    assert_eq!(t.post("/api/shares", body.clone(), Some(&c)).await.status, StatusCode::BAD_REQUEST);
    body["policy"] = json!([{"group": "include", "type": "ip", "cidrs": ["not-an-ip"]}]);
    assert_eq!(t.post("/api/shares", body, Some(&c)).await.status, StatusCode::BAD_REQUEST);
    let mut link = public_text("x");
    link["kind"] = json!("link");
    link["payload"] = json!({"kind": "link", "url": "javascript:alert(1)"});
    assert_eq!(t.post("/api/shares", link, Some(&c)).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoke_and_sweep() {
    let t = TestApp::with_config(|c| c.retention_days = 0).await;
    let c = t.login().await;
    let share = t.create(&c, public_text("x")).await;
    let id = share["id"].as_str().unwrap();
    let r = t
        .req(
            "PATCH",
            &format!("/api/shares/{id}"),
            Some(json!({"revoke": true})),
            Some(&c),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.body["status"], "revoked");
    assert_eq!(
        t.get(&format!("/api/s/{}", share["slug"].as_str().unwrap()), None).await.status,
        StatusCode::NOT_FOUND
    );

    sqlx::query("UPDATE shares SET revoked_at = revoked_at - 10")
        .execute(&t.state.db)
        .await
        .unwrap();
    crate::jobs::sweep(&t.state).await.unwrap();
    assert_eq!(t.get("/api/shares", Some(&c)).await.body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn openapi_and_health() {
    let t = TestApp::new().await;
    assert_eq!(t.get("/healthz", None).await.status, StatusCode::OK);
    let spec: Value = serde_json::from_str(&crate::api::openapi_json()).unwrap();
    for p in [
        "/api/shares",
        "/api/s/{slug}/open",
        "/api/auth/login",
        "/api/slug-generators/{id}/preview",
    ] {
        assert!(spec["paths"].get(p).is_some(), "missing {p}");
    }
    // Duplicate operation ids make openapi-typescript merge unrelated endpoints' types.
    let mut ids: Vec<&str> = spec["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|p| p.as_object().unwrap().values())
        .filter_map(|op| op["operationId"].as_str())
        .collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n, "duplicate operationId in OpenAPI spec");
}

// ---------------------------------------------------------------------------------------------
// File shares
// ---------------------------------------------------------------------------------------------

const CHUNK: usize = crate::blobs::CHUNK_SIZE;

fn file_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn server_files_share(sizes: &[usize]) -> Value {
    let manifest: Vec<Value> = sizes
        .iter()
        .enumerate()
        .map(|(i, s)| json!({"name": format!("f{i}.bin"), "size": s}))
        .collect();
    json!({
        "kind": "files", "enc_mode": "server", "slug": {}, "max_views": 1,
        "policy": [{"group": "include", "type": "everyone"}],
        "payload": {"kind": "files", "files": manifest},
        "files": sizes.iter().map(|s| json!({"size": s})).collect::<Vec<_>>(),
    })
}

async fn upload_all(t: &TestApp, c: &str, created: &Value, files: &[Vec<u8>], e2e_overhead: bool) {
    let id = created["share"]["id"].as_str().unwrap();
    let token = created["upload_token"].as_str().unwrap();
    for (idx, data) in files.iter().enumerate() {
        let chunks = created["files"][idx]["chunk_count"].as_u64().unwrap() as usize;
        for n in 0..chunks {
            let mut part = data[(n * CHUNK).min(data.len())..((n + 1) * CHUNK).min(data.len())].to_vec();
            if e2e_overhead {
                part.extend_from_slice(&[0xEE; 28]); // stand-in for nonce + tag
            }
            let uri = format!("/api/shares/{id}/files/{idx}/chunks/{n}");
            let (st, body) = t.raw("PUT", &uri, part, Some(c), &[("x-upload-token", token)]).await;
            assert_eq!(st, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&body));
        }
    }
}

async fn download(t: &TestApp, slug: &str, token: &str, idx: usize, chunks: usize) -> Vec<u8> {
    let mut out = vec![];
    for n in 0..chunks {
        let (st, body) = t
            .raw(
                "GET",
                &format!("/api/s/{slug}/files/{idx}/chunks/{n}"),
                vec![],
                None,
                &[("x-download-token", token)],
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        out.extend(body);
    }
    out
}

#[tokio::test]
async fn server_file_share_round_trip_and_burn() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let files = vec![file_bytes(CHUNK + CHUNK / 2, 1), vec![]];
    let created = t.create_full(&c, server_files_share(&[files[0].len(), 0])).await;
    assert_eq!(created["share"]["status"], "uploading");
    assert_eq!(created["files"][0]["chunk_count"], 2);
    assert_eq!(created["files"][1]["chunk_count"], 1);
    let slug = created["share"]["slug"].as_str().unwrap().to_string();
    let id = created["share"]["id"].as_str().unwrap().to_string();

    // Not openable until finalised.
    assert_eq!(t.get(&format!("/api/s/{slug}"), None).await.status, StatusCode::NOT_FOUND);
    let fin = format!("/api/shares/{id}/finalize");
    let token = created["upload_token"].as_str().unwrap();
    let (st, _) = t.raw("POST", &fin, vec![], Some(&c), &[("x-upload-token", token)]).await;
    assert_eq!(st, StatusCode::CONFLICT, "incomplete upload must not finalise");

    upload_all(&t, &c, &created, &files, false).await;
    let (st, _) = t.raw("POST", &fin, vec![], Some(&c), &[("x-upload-token", "wrong")]).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, body) = t.raw("POST", &fin, vec![], Some(&c), &[("x-upload-token", token)]).await;
    assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    // Stored blobs are encrypted.
    let blob = std::fs::read(t.state.cfg.data_dir.join("blobs").join(&id).join("0.bin")).unwrap();
    assert_eq!(blob.len(), files[0].len() + 2 * 40);
    assert!(!blob.windows(64).any(|w| w == &files[0][..64]));

    let open = t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    assert_eq!(open.status, StatusCode::OK, "{}", open.body);
    assert_eq!(open.body["burned"], true);
    assert_eq!(open.body["payload"]["files"][0]["name"], "f0.bin");
    let dl = open.body["download_token"].as_str().unwrap();

    // Downloads keep working after the burn, until the token expires.
    assert_eq!(download(&t, &slug, dl, 0, 2).await, files[0]);
    assert_eq!(download(&t, &slug, dl, 1, 1).await, Vec::<u8>::new());
    let (st, _) = t
        .raw(
            "GET",
            &format!("/api/s/{slug}/files/0/chunks/0"),
            vec![],
            None,
            &[("x-download-token", "nope")],
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        t.post(&format!("/api/s/{slug}/open"), json!({}), None).await.status,
        StatusCode::NOT_FOUND
    );

    // Once the token has expired, the sweeper removes the blobs.
    sqlx::query("UPDATE download_tokens SET expires_at = 0")
        .execute(&t.state.db)
        .await
        .unwrap();
    crate::jobs::sweep(&t.state).await.unwrap();
    assert!(!t.state.cfg.data_dir.join("blobs").join(&id).exists());
}

#[tokio::test]
async fn server_file_share_with_passphrase() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let data = file_bytes(1000, 7);
    let mut body = server_files_share(&[data.len()]);
    body["passphrase"] = json!("pw");
    body["max_views"] = json!(2);
    let created = t.create_full(&c, body).await;
    upload_all(&t, &c, &created, std::slice::from_ref(&data), false).await;
    let id = created["share"]["id"].as_str().unwrap();
    let (st, _) = t
        .raw(
            "POST",
            &format!("/api/shares/{id}/finalize"),
            vec![],
            Some(&c),
            &[("x-upload-token", created["upload_token"].as_str().unwrap())],
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let slug = created["share"]["slug"].as_str().unwrap();
    let open = t.post(&format!("/api/s/{slug}/open"), json!({"passphrase": "pw"}), None).await;
    assert_eq!(download(&t, slug, open.body["download_token"].as_str().unwrap(), 0, 1).await, data);
}

#[tokio::test]
async fn upload_validation() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let created = t.create_full(&c, server_files_share(&[CHUNK + 10])).await;
    let id = created["share"]["id"].as_str().unwrap();
    let token = created["upload_token"].as_str().unwrap();
    let (t, c) = (&t, c.as_str());
    let put = |n: usize, len: usize| {
        let uri = format!("/api/shares/{id}/files/0/chunks/{n}");
        async move { t.raw("PUT", &uri, vec![0; len], Some(c), &[("x-upload-token", token)]).await.0 }
    };
    assert_eq!(put(1, 10).await, StatusCode::CONFLICT, "out of order");
    assert_eq!(put(0, 10).await, StatusCode::BAD_REQUEST, "wrong size");
    assert_eq!(put(0, CHUNK).await, StatusCode::NO_CONTENT);
    assert_eq!(put(2, 10).await, StatusCode::BAD_REQUEST, "out of range");
    assert_eq!(put(1, 10).await, StatusCode::NO_CONTENT);
    let (st, _) = t
        .raw(
            "PUT",
            &format!("/api/shares/{id}/files/0/chunks/0"),
            vec![0; CHUNK],
            Some(c),
            &[("x-upload-token", "bad")],
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Manifest must agree with declared sizes, and limits apply.
    let mut bad = server_files_share(&[5]);
    bad["files"] = json!([{"size": 6}]);
    assert_eq!(t.post("/api/shares", bad, Some(c)).await.status, StatusCode::BAD_REQUEST);
    let mut huge = server_files_share(&[1]);
    huge["files"] = json!([{"size": 1u64 << 40}]);
    huge["payload"]["files"][0]["size"] = json!(1u64 << 40);
    assert_eq!(t.post("/api/shares", huge, Some(c)).await.status, StatusCode::BAD_REQUEST);
    let mut text_with_files = public_text("x");
    text_with_files["files"] = json!([{"size": 1}]);
    assert_eq!(
        t.post("/api/shares", text_with_files, Some(c)).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn e2e_file_share_stores_opaque_chunks_and_revoke_deletes_them() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let data = file_bytes(300, 3);
    let created = t
        .create_full(
            &c,
            json!({
                "kind": "files", "enc_mode": "e2e", "slug": {},
                "policy": [{"group": "include", "type": "everyone"}],
                "ciphertext": B64.encode([1u8; 80]), "enc_meta": {"v": 1, "key": "fragment"},
                "files": [{"size": data.len()}],
            }),
        )
        .await;
    upload_all(&t, &c, &created, std::slice::from_ref(&data), true).await;
    let id = created["share"]["id"].as_str().unwrap();
    let (st, _) = t
        .raw(
            "POST",
            &format!("/api/shares/{id}/finalize"),
            vec![],
            Some(&c),
            &[("x-upload-token", created["upload_token"].as_str().unwrap())],
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let slug = created["share"]["slug"].as_str().unwrap();
    let open = t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    let dl = open.body["download_token"].as_str().unwrap().to_string();
    let mut expected = data.clone();
    expected.extend_from_slice(&[0xEE; 28]);
    assert_eq!(download(&t, slug, &dl, 0, 1).await, expected, "e2e chunks are returned untouched");

    let r = t
        .req(
            "PATCH",
            &format!("/api/shares/{id}"),
            Some(json!({"revoke": true})),
            Some(&c),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.body["status"], "revoked");
    assert!(!t.state.cfg.data_dir.join("blobs").join(id).exists());
    let (st, _) = t
        .raw(
            "GET",
            &format!("/api/s/{slug}/files/0/chunks/0"),
            vec![],
            None,
            &[("x-download-token", &dl)],
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "revoke kills outstanding downloads");
}

// ---------------------------------------------------------------------------------------------
// Recipient sign-in
// ---------------------------------------------------------------------------------------------

fn domain_share(domain: &str, methods: Value) -> Value {
    let mut b = public_text("for the team");
    b["policy"] = json!([{"group": "include", "type": "email_domain", "domains": [domain], "methods": methods}]);
    b
}

/// Waits for the background send task and returns the code mailed to `to`.
async fn mailed_code(sent: &Sent, to: &str) -> Option<String> {
    for _ in 0..50 {
        if let Some((_, body)) = sent.lock().unwrap().iter().find(|(t, _)| t == to) {
            return body
                .split_whitespace()
                .find(|w| w.len() == 6 && w.bytes().all(|b| b.is_ascii_digit()))
                .map(String::from);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    None
}

#[tokio::test]
async fn email_otp_unlocks_domain_share() {
    let (t, sent) = TestApp::with_email(|_| {}).await;
    let c = t.login().await;
    let share = t.create(&c, domain_share("acme.com", json!([]))).await;
    let slug = share["slug"].as_str().unwrap();

    let info = t.get(&format!("/api/s/{slug}"), None).await;
    assert_eq!(info.body["status"], "need_auth");
    assert_eq!(info.body["auth_methods"], json!(["email_otp"]));
    assert!(info.body["title"].is_null());

    // Not an allowed address: same answer, but nothing is sent.
    let r = t
        .post("/api/recipient/email/start", json!({"slug": slug, "email": "eve@evil.com"}), None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body["challenge_id"].is_string());
    assert!(mailed_code(&sent, "eve@evil.com").await.is_none());

    let r = t
        .post(
            "/api/recipient/email/start",
            json!({"slug": slug, "email": " Alice@ACME.com "}),
            None,
        )
        .await;
    let challenge = r.body["challenge_id"].as_str().unwrap().to_string();
    let code = mailed_code(&sent, "alice@acme.com").await.expect("code mailed");

    let wrong = if code == "000000" { "111111" } else { "000000" };
    let r = t
        .post(
            "/api/recipient/email/verify",
            json!({"challenge_id": challenge, "code": wrong}),
            None,
        )
        .await;
    assert_eq!(
        (r.status, r.body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_code"))
    );
    let r = t
        .post(
            "/api/recipient/email/verify",
            json!({"challenge_id": challenge, "code": code}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["identities"][0]["email"], "alice@acme.com");
    let rc = r.cookie.expect("recipient cookie");
    assert!(rc.starts_with("ss_recipient="));
    // A code works once.
    let r = t
        .post(
            "/api/recipient/email/verify",
            json!({"challenge_id": challenge, "code": code}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    assert_eq!(t.get(&format!("/api/s/{slug}"), Some(&rc)).await.body["status"], "ready");
    let open = t.post(&format!("/api/s/{slug}/open"), json!({}), Some(&rc)).await;
    assert_eq!(open.body["payload"]["text"], "for the team");
    let log = t.get(&format!("/api/shares/{}/log", share["id"].as_str().unwrap()), Some(&c)).await;
    assert_eq!(log.body[0]["identity"], "alice@acme.com");

    let r = t.post("/api/recipient/logout", json!({}), Some(&rc)).await;
    assert_eq!(r.body["identities"], json!([]));
    assert_eq!(t.get(&format!("/api/s/{slug}"), Some(&rc)).await.body["status"], "need_auth");
}

#[tokio::test]
async fn email_otp_attempt_limit_and_rate_limit() {
    let (t, sent) = TestApp::with_email(|_| {}).await;
    let c = t.login().await;
    let slug = t.create(&c, domain_share("acme.com", json!(["email_otp"]))).await["slug"]
        .as_str()
        .unwrap()
        .to_string();
    let r = t
        .post("/api/recipient/email/start", json!({"slug": slug, "email": "bob@acme.com"}), None)
        .await;
    let challenge = r.body["challenge_id"].as_str().unwrap().to_string();
    let code = mailed_code(&sent, "bob@acme.com").await.unwrap();
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        t.post(
            "/api/recipient/email/verify",
            json!({"challenge_id": challenge, "code": wrong}),
            None,
        )
        .await;
    }
    let r = t
        .post(
            "/api/recipient/email/verify",
            json!({"challenge_id": challenge, "code": code}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "correct code refused after too many attempts");

    // Per-address send limit.
    for _ in 0..2 {
        t.post("/api/recipient/email/start", json!({"slug": slug, "email": "bob@acme.com"}), None)
            .await;
    }
    let r = t
        .post("/api/recipient/email/start", json!({"slug": slug, "email": "bob@acme.com"}), None)
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn identity_rules_need_a_configured_method() {
    let t = TestApp::new().await; // no email, no OIDC
    let c = t.login().await;
    let r = t.post("/api/shares", domain_share("acme.com", json!([])), Some(&c)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    let (t, _) = TestApp::with_email(|_| {}).await;
    let c = t.login().await;
    let r = t
        .post("/api/shares", domain_share("acme.com", json!(["oidc:nope"])), Some(&c))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.get("/api/recipient/methods", None).await.body,
        json!([{"id": "email_otp", "label": "Email code"}])
    );
}

/// Minimal OpenID provider + GitHub OAuth endpoints for tests.
mod mock_idp {
    use std::sync::{Arc, OnceLock};

    use axum::{
        Form, Json, Router,
        extract::State,
        http::HeaderMap,
        routing::{get, post},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use openidconnect::{
        Audience, EmptyAdditionalClaims, EndUserEmail, IssuerUrl, Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
        core::{CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey},
    };
    use serde_json::{Value, json};

    const KEY: &str = include_str!("testdata/oidc_test_key.pem");

    pub struct Mock {
        pub base: OnceLock<String>,
    }

    /// The authorization "code" the test hands to the callback: it tells the mock what to put in the ID token.
    pub fn code(email: &str, nonce: &str, verified: bool) -> String {
        URL_SAFE_NO_PAD.encode(format!("{email}|{nonce}|{verified}"))
    }

    fn key() -> CoreRsaPrivateSigningKey {
        CoreRsaPrivateSigningKey::from_pem(KEY, None).unwrap()
    }

    pub async fn spawn() -> String {
        let mock = Arc::new(Mock { base: OnceLock::new() });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route(
                "/jwks",
                get(|| async { Json(CoreJsonWebKeySet::new(vec![key().as_verification_key()])) }),
            )
            .route("/token", post(token))
            .route(
                "/login/oauth/access_token",
                post(|| async { Json(json!({"access_token": "gho_test", "token_type": "bearer"})) }),
            )
            .route("/user/emails", get(github_emails))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        mock.base.set(base.clone()).unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    async fn discovery(State(m): State<Arc<Mock>>) -> Json<Value> {
        let b = m.base.get().unwrap();
        Json(json!({
            "issuer": b,
            "authorization_endpoint": format!("{b}/authorize"),
            "token_endpoint": format!("{b}/token"),
            "jwks_uri": format!("{b}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }))
    }

    async fn token(State(m): State<Arc<Mock>>, Form(form): Form<std::collections::HashMap<String, String>>) -> Json<Value> {
        assert!(form.contains_key("code_verifier"), "PKCE verifier must be sent");
        let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(&form["code"]).unwrap()).unwrap();
        let mut parts = decoded.split('|');
        let (email, nonce, verified) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap() == "true");
        let now = chrono::Utc::now();
        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(m.base.get().unwrap().clone()).unwrap(),
            vec![Audience::new("client-id".into())],
            now + chrono::Duration::minutes(5),
            now,
            StandardClaims::new(SubjectIdentifier::new("user-1".into()))
                .set_email(Some(EndUserEmail::new(email.into())))
                .set_email_verified(Some(verified)),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(nonce.into())));
        let id_token = CoreIdToken::new(claims, &key(), CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, None, None).unwrap();
        Json(json!({"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": id_token.to_string()}))
    }

    async fn github_emails(headers: HeaderMap) -> Json<Value> {
        assert_eq!(headers.get("authorization").unwrap(), "Bearer gho_test");
        Json(json!([
            {"email": "Dev@Acme.com", "verified": true, "primary": true},
            {"email": "spoof@other.com", "verified": false, "primary": false},
        ]))
    }
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

async fn oidc_app() -> (TestApp, String) {
    let idp = mock_idp::spawn().await;
    let issuer = idp.clone();
    let t = TestApp::with_config(move |c| {
        c.oidc = vec![
            crate::config::OidcProviderConfig {
                id: "mock".into(),
                name: "Mock IdP".into(),
                kind: crate::config::OidcKind::Oidc,
                issuer: Some(issuer.clone()),
                client_id: "client-id".into(),
                client_secret: "secret".into(),
                scopes: vec![],
                trust_unverified_email: false,
                github_web_url: None,
                github_api_url: None,
            },
            crate::config::OidcProviderConfig {
                id: "gh".into(),
                name: "GitHub".into(),
                kind: crate::config::OidcKind::Github,
                issuer: None,
                client_id: "gh-client".into(),
                client_secret: "gh-secret".into(),
                scopes: vec![],
                trust_unverified_email: false,
                github_web_url: Some(issuer.clone()),
                github_api_url: Some(issuer),
            },
        ]
    })
    .await;
    (t, idp)
}

/// Runs start → (IdP) → callback and returns (callback Location, recipient cookie).
async fn sign_in(t: &TestApp, provider: &str, next: &str, email: &str, verified: bool) -> (String, Option<String>) {
    let (r, h) = t
        .req_full(
            "GET",
            &format!("/api/recipient/oidc/{provider}/start?next={next}"),
            None,
            None,
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let to = h.get(header::LOCATION).unwrap().to_str().unwrap().to_string();
    let state_cookie = r.cookie.unwrap();
    let state = query_param(&to, "state").unwrap();
    assert_eq!(query_param(&to, "code_challenge_method").as_deref(), Some("S256"));
    let code = match query_param(&to, "nonce") {
        Some(nonce) => mock_idp::code(email, &nonce, verified),
        None => "github-code".into(),
    };
    let (r, h) = t
        .req_full(
            "GET",
            &format!("/api/recipient/oidc/{provider}/callback?code={code}&state={state}"),
            None,
            Some(&state_cookie),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let cookie = h
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
        .find(|c| c.starts_with("ss_recipient="));
    (h.get(header::LOCATION).unwrap().to_str().unwrap().to_string(), cookie)
}

#[tokio::test]
async fn oidc_sign_in_unlocks_share() {
    let (t, _) = oidc_app().await;
    let c = t.login().await;
    let slug = t.create(&c, domain_share("acme.com", json!(["oidc:mock"]))).await["slug"]
        .as_str()
        .unwrap()
        .to_string();
    let info = t.get(&format!("/api/s/{slug}"), None).await;
    assert_eq!(info.body["auth_methods"], json!(["oidc:mock"]));

    let (to, cookie) = sign_in(&t, "mock", &format!("/s/{slug}"), "Carol@acme.com", true).await;
    assert_eq!(to, format!("/s/{slug}"));
    let cookie = cookie.expect("signed in");
    assert_eq!(t.get(&format!("/api/s/{slug}"), Some(&cookie)).await.body["status"], "ready");
    let me = t.get("/api/recipient/me", Some(&cookie)).await;
    assert_eq!(me.body["identities"], json!([{"email": "carol@acme.com", "method": "oidc:mock"}]));
}

#[tokio::test]
async fn oidc_rejects_unverified_email_bad_state_and_open_redirects() {
    let (t, _) = oidc_app().await;
    let (to, cookie) = sign_in(&t, "mock", "/s/x", "mallory@acme.com", false).await;
    assert_eq!(to, "/s/x?auth_error=no_verified_email");
    assert!(cookie.is_none());

    let (to, _) = sign_in(&t, "mock", "//evil.example/x", "a@acme.com", true).await;
    assert_eq!(to, "/", "external next is replaced");

    // A callback without the browser-bound state cookie is refused (login CSRF).
    let (r, h) = t
        .req_full("GET", "/api/recipient/oidc/mock/start?next=/s/y", None, None, "198.51.100.1", &[])
        .await;
    let state = query_param(h.get(header::LOCATION).unwrap().to_str().unwrap(), "state").unwrap();
    drop(r);
    let (_, h) = t
        .req_full(
            "GET",
            &format!("/api/recipient/oidc/mock/callback?code=x&state={state}"),
            None,
            None,
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(h.get(header::LOCATION).unwrap(), "/?auth_error=expired");
    assert_eq!(t.get("/api/recipient/oidc/unknown/start", None).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn github_sign_in_uses_verified_emails_only() {
    let (t, _) = oidc_app().await;
    let (to, cookie) = sign_in(&t, "gh", "/s/z", "", true).await;
    assert_eq!(to, "/s/z");
    let me = t.get("/api/recipient/me", Some(&cookie.unwrap())).await;
    assert_eq!(me.body["identities"], json!([{"email": "dev@acme.com", "method": "oidc:gh"}]));
}

// ---------------------------------------------------------------------------------------------
// Phase 5: passkeys, policy templates, streaming downloads, API rate limit
// ---------------------------------------------------------------------------------------------

mod passkeys {
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

    use super::*;

    pub fn authenticator() -> WebauthnAuthenticator<SoftPasskey> {
        WebauthnAuthenticator::new(SoftPasskey::new(true))
    }

    fn origin() -> url::Url {
        url::Url::parse(ORIGIN).unwrap()
    }

    pub async fn register(t: &TestApp, c: &str, auth: &mut WebauthnAuthenticator<SoftPasskey>, name: &str) -> Value {
        let start = t.post("/api/auth/passkey/register/start", json!({"name": name}), Some(c)).await;
        assert_eq!(start.status, StatusCode::OK, "{}", start.body);
        let cred = auth
            .do_registration(origin(), serde_json::from_value(start.body["options"].clone()).unwrap())
            .unwrap();
        let fin = t
            .post(
                "/api/auth/passkey/register/finish",
                json!({"ceremony_id": start.body["ceremony_id"], "credential": cred}),
                Some(c),
            )
            .await;
        assert_eq!(fin.status, StatusCode::OK, "{}", fin.body);
        fin.body
    }

    /// Runs a login or step-up ceremony; returns the finish response.
    pub async fn assert_with(t: &TestApp, kind: &str, c: Option<&str>, auth: &mut WebauthnAuthenticator<SoftPasskey>) -> Resp {
        let start = t.post(&format!("/api/auth/passkey/{kind}/start"), json!({}), c).await;
        assert_eq!(start.status, StatusCode::OK, "{}", start.body);
        let cred = auth
            .do_authentication(origin(), serde_json::from_value(start.body["options"].clone()).unwrap())
            .unwrap();
        t.post(
            &format!("/api/auth/passkey/{kind}/finish"),
            json!({"ceremony_id": start.body["ceremony_id"], "credential": cred}),
            c,
        )
        .await
    }

    #[tokio::test]
    async fn register_login_step_up_and_delete() {
        let t = TestApp::new().await;
        let c = t.login().await;
        let mut auth = authenticator();
        let pk = register(&t, &c, &mut auth, "Laptop").await;
        assert_eq!(pk["name"], "Laptop");
        assert_eq!(t.get("/api/auth/me", None).await.body["passkeys"], 1);
        assert_eq!(t.get("/api/auth/passkeys", Some(&c)).await.body.as_array().unwrap().len(), 1);

        // Passwordless sign-in counts as a fresh MFA.
        let r = assert_with(&t, "login", None, &mut auth).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert!(r.body["mfa_valid_until"].as_i64().unwrap() > now());
        let pc = r.cookie.unwrap();
        assert_eq!(t.get("/api/shares", Some(&pc)).await.status, StatusCode::OK);
        let listed = t.get("/api/auth/passkeys", Some(&pc)).await;
        assert!(listed.body[0]["last_used_at"].is_i64(), "use is recorded");

        // Step-up after the MFA has gone stale.
        sqlx::query("UPDATE owner_sessions SET mfa_at = ?")
            .bind(now() - 3600)
            .execute(&t.state.db)
            .await
            .unwrap();
        let id = pk["id"].as_str().unwrap();
        let r = t
            .req("DELETE", &format!("/api/auth/passkeys/{id}"), None, Some(&pc), "198.51.100.1", &[])
            .await;
        assert_eq!(r.body["error"], "need_owner_mfa", "deleting needs a fresh MFA");
        let r = assert_with(&t, "step-up", Some(&pc), &mut auth).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let r = t
            .req("DELETE", &format!("/api/auth/passkeys/{id}"), None, Some(&pc), "198.51.100.1", &[])
            .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        assert_eq!(
            t.post("/api/auth/passkey/login/start", json!({}), None).await.status,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn unknown_authenticator_and_replayed_ceremony_fail() {
        let t = TestApp::new().await;
        let c = t.login().await;
        register(&t, &c, &mut authenticator(), "Phone").await;
        // A different authenticator has no matching credential.
        let start = t.post("/api/auth/passkey/login/start", json!({}), None).await;
        let other = authenticator().do_authentication(
            url::Url::parse(ORIGIN).unwrap(),
            serde_json::from_value(start.body["options"].clone()).unwrap(),
        );
        assert!(other.is_err(), "soft authenticator refuses unknown credentials");
        let fin = t
            .post(
                "/api/auth/passkey/login/finish",
                json!({"ceremony_id": start.body["ceremony_id"], "credential": {"id": "x"}}),
                None,
            )
            .await;
        assert_eq!(fin.status, StatusCode::BAD_REQUEST);
        let again = t
            .post(
                "/api/auth/passkey/login/finish",
                json!({"ceremony_id": start.body["ceremony_id"], "credential": {"id": "x"}}),
                None,
            )
            .await;
        assert_eq!(again.body["error"], "ceremony_expired", "ceremonies are single use");
    }

    #[tokio::test]
    async fn registering_needs_fresh_mfa() {
        let t = TestApp::new().await;
        let c = t.login().await;
        sqlx::query("UPDATE owner_sessions SET mfa_at = NULL")
            .execute(&t.state.db)
            .await
            .unwrap();
        let r = t.post("/api/auth/passkey/register/start", json!({"name": "x"}), Some(&c)).await;
        assert_eq!(r.body["error"], "need_owner_mfa");
    }
}

#[tokio::test]
async fn policy_templates_crud() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let office = json!([{"group": "include", "type": "ip", "cidrs": ["10.1.2.3/8"]}]);
    let r = t
        .post("/api/policy-templates", json!({"name": "Office", "policy": office}), Some(&c))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["policy"][0]["cidrs"][0], "10.0.0.0/8", "rules are normalised");
    let id = r.body["id"].as_str().unwrap().to_string();
    // Same name replaces the rules but keeps the id.
    let r = t
        .post(
            "/api/policy-templates",
            json!({"name": "Office", "policy": [{"group": "include", "type": "owner"}]}),
            Some(&c),
        )
        .await;
    assert_eq!(r.body["id"], id);
    let list = t.get("/api/policy-templates", Some(&c)).await;
    assert_eq!(list.body.as_array().unwrap().len(), 1);
    assert_eq!(list.body[0]["policy"][0]["type"], "owner");
    let bad = t
        .post(
            "/api/policy-templates",
            json!({"name": "Bad", "policy": [{"group": "exclude", "type": "owner"}]}),
            Some(&c),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(t.get("/api/policy-templates", None).await.status, StatusCode::UNAUTHORIZED);
    let r = t
        .req(
            "DELETE",
            &format!("/api/policy-templates/{id}"),
            None,
            Some(&c),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn server_file_streams_as_attachment() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let data = file_bytes(CHUNK * 2 + 77, 9);
    let created = t.create_full(&c, server_files_share(&[data.len()])).await;
    upload_all(&t, &c, &created, std::slice::from_ref(&data), false).await;
    let id = created["share"]["id"].as_str().unwrap();
    let token = created["upload_token"].as_str().unwrap();
    t.raw(
        "POST",
        &format!("/api/shares/{id}/finalize"),
        vec![],
        Some(&c),
        &[("x-upload-token", token)],
    )
    .await;
    let slug = created["share"]["slug"].as_str().unwrap();
    let open = t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    let dl = open.body["download_token"].as_str().unwrap();

    let form = format!("token={dl}&name=r%C3%A9sum%C3%A9.bin");
    let ct = [("content-type", "application/x-www-form-urlencoded")];
    let (st, body) = t
        .raw("POST", &format!("/api/s/{slug}/files/0/download"), form.into_bytes(), None, &ct)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, data);
    let (st, _) = t
        .raw(
            "POST",
            &format!("/api/s/{slug}/files/0/download"),
            b"token=bad&name=x".to_vec(),
            None,
            &ct,
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_requests_are_rate_limited_per_ip() {
    let t = TestApp::new().await;
    let mut last = StatusCode::OK;
    for _ in 0..601 {
        last = t.get("/api/auth/me", None).await.status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // Another client is unaffected.
    let r = t.req("GET", "/api/auth/me", None, None, "198.51.100.2", &[]).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn edit_share_settings() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("editable");
    body["max_views"] = json!(3);
    let share = t.create(&c, body).await;
    let (id, slug) = (share["id"].as_str().unwrap(), share["slug"].as_str().unwrap());
    t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    let uri = format!("/api/shares/{id}");
    let patch = |b: Value| t.req("PATCH", &uri, Some(b), Some(&c), "198.51.100.1", &[]);

    let r = patch(json!({"max_views": 1})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "limit at or below views used");
    let in_a_day = now() + 86_400;
    let r = patch(json!({
        "title": "Renamed", "max_views": 5, "expires_at": in_a_day,
        "policy": [{"group": "include", "type": "ip", "cidrs": ["10.0.0.0/8"]}],
    }))
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        (
            r.body["title"].as_str(),
            r.body["max_views"].as_i64(),
            r.body["expires_at"].as_i64()
        ),
        (Some("Renamed"), Some(5), Some(in_a_day))
    );
    assert_eq!(
        t.get(&format!("/api/s/{slug}"), None).await.body["status"],
        "denied",
        "new policy applies"
    );
    let r = patch(json!({"max_views": 0, "expires_at": 0, "title": ""})).await;
    assert!(r.body["max_views"].is_null() && r.body["expires_at"].is_null() && r.body["title"].is_null());

    patch(json!({"revoke": true})).await;
    assert_eq!(
        patch(json!({"title": "x"})).await.status,
        StatusCode::CONFLICT,
        "revoked shares can't be edited"
    );
}

#[tokio::test]
async fn totp_setup_confirm_and_disable_from_ui() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let setup = t.post("/api/auth/totp/setup", json!({}), Some(&c)).await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.body);
    assert!(setup.body["qr_svg"].as_str().unwrap().starts_with("data:image/svg+xml;base64,"));
    let secret = setup.body["secret"].as_str().unwrap().to_string();
    assert_ne!(secret, t.totp_secret);

    // The old secret stays active until the new one is confirmed.
    let wrong = t.post("/api/auth/totp/confirm", json!({"code": "000000"}), Some(&c)).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let ok = t
        .post("/api/auth/totp/confirm", json!({"code": totp::code_at(&secret, now())}), Some(&c))
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    let (stored,): (Option<String>,) = sqlx::query_as("SELECT totp_secret FROM owner")
        .fetch_one(&t.state.db)
        .await
        .unwrap();
    assert_eq!(stored.as_deref(), Some(secret.as_str()));
    let old = t
        .post(
            "/api/auth/login",
            json!({"password": PASSWORD, "totp": totp::code_at(&t.totp_secret, now() + 30)}),
            None,
        )
        .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED, "old authenticator no longer works");

    // Disabling is refused while an owner-MFA share depends on it and no passkey exists.
    let mut body = public_text("needs mfa");
    body["require_owner_mfa"] = json!(true);
    let share = t.create(&c, body).await;
    let del = t.req("DELETE", "/api/auth/totp", None, Some(&c), "198.51.100.1", &[]).await;
    assert_eq!(del.status, StatusCode::CONFLICT, "{}", del.body);
    t.req(
        "PATCH",
        &format!("/api/shares/{}", share["id"].as_str().unwrap()),
        Some(json!({"revoke": true})),
        Some(&c),
        "198.51.100.1",
        &[],
    )
    .await;
    let del = t.req("DELETE", "/api/auth/totp", None, Some(&c), "198.51.100.1", &[]).await;
    assert_eq!(del.status, StatusCode::OK, "{}", del.body);
    assert_eq!(del.body["totp_enabled"], false);

    // Stale MFA blocks setup while a factor exists.
    let setup = t.post("/api/auth/totp/setup", json!({}), Some(&c)).await;
    assert_eq!(setup.status, StatusCode::OK, "no factor left, so no step-up needed");
    let code = totp::code_at(setup.body["secret"].as_str().unwrap(), now());
    t.post("/api/auth/totp/confirm", json!({"code": code}), Some(&c)).await;
    sqlx::query("UPDATE owner_sessions SET mfa_at = 0")
        .execute(&t.state.db)
        .await
        .unwrap();
    assert_eq!(
        t.post("/api/auth/totp/setup", json!({}), Some(&c)).await.body["error"],
        "need_owner_mfa"
    );
}
