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
        let state = AppState::new(cfg, db, MasterKey::new([42; 32])).unwrap();
        Self {
            app: crate::api::router(state.clone()),
            state,
            totp_secret,
            _dir: TempDir(dir),
        }
    }

    async fn req(&self, method: &str, uri: &str, body: Option<Value>, cookie: Option<&str>, peer: &str, extra: &[(&str, &str)]) -> Resp {
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
        let cookie = res
            .headers()
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Resp { status, body, cookie }
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
        let r = self.post("/api/shares", body, Some(cookie)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body
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
}
