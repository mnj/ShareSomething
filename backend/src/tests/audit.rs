//! Phase 1 (v2 foundation): users, ownership isolation, roles, audit trail and SIEM shipping.

use std::sync::{Arc, Mutex};

use axum::{Router, body::Bytes, http::HeaderMap, routing::post};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

use super::*;
use crate::audit::{
    self,
    format::Observer,
    ship::{HttpPreset, ShipperConfig, ShipperKind, SinkHandle, SyslogFormat, SyslogTransport, ship_once},
};

async fn actions(t: &TestApp) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT action FROM audit_events ORDER BY seq")
        .fetch_all(&t.state.db)
        .await
        .unwrap();
    rows.into_iter().map(|r| r.0).collect()
}

async fn last(t: &TestApp, action: &str) -> audit::Record {
    sqlx::query_as("SELECT * FROM audit_events WHERE action = ? ORDER BY seq DESC LIMIT 1")
        .bind(action)
        .fetch_one(&t.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn users_only_see_and_manage_their_own_shares() {
    let t = TestApp::new().await;
    let owner = t.login().await;
    t.add_user("bob@acme.com", "member").await;
    let bob = t.login_as("bob@acme.com").await;

    let share = t.create(&owner, public_text("owner's")).await;
    let id = share["id"].as_str().unwrap();
    assert_eq!(
        t.get("/api/shares", Some(&bob)).await.body,
        json!([]),
        "bob sees none of the owner's shares"
    );
    for (m, uri) in [
        ("GET", format!("/api/shares/{id}")),
        ("GET", format!("/api/shares/{id}/log")),
        ("DELETE", format!("/api/shares/{id}")),
    ] {
        assert_eq!(
            t.req(m, &uri, None, Some(&bob), "198.51.100.1", &[]).await.status,
            StatusCode::NOT_FOUND,
            "{m} {uri}"
        );
    }
    let r = t
        .req(
            "PATCH",
            &format!("/api/shares/{id}"),
            Some(json!({"revoke": true})),
            Some(&bob),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // The `owner` rule means *this share's* owner: another signed-in user is refused, not asked to log in.
    let mut only_me = public_text("private");
    only_me["policy"] = json!([{"group": "include", "type": "owner"}]);
    let slug = t.create(&owner, only_me).await["slug"].as_str().unwrap().to_string();
    assert_eq!(t.get(&format!("/api/s/{slug}"), Some(&bob)).await.body["status"], "denied");
    assert_eq!(t.get(&format!("/api/s/{slug}"), Some(&owner)).await.body["status"], "ready");

    // Bob's own share works for bob.
    let mut bobs = public_text("bob's");
    bobs["policy"] = json!([{"group": "include", "type": "owner"}]);
    let bslug = t.create(&bob, bobs).await["slug"].as_str().unwrap().to_string();
    assert_eq!(t.get(&format!("/api/s/{bslug}"), Some(&bob)).await.body["status"], "ready");
    assert_eq!(t.get(&format!("/api/s/{bslug}"), Some(&owner)).await.body["status"], "denied");
    assert_eq!(t.get("/api/shares", Some(&bob)).await.body.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn roles_gate_audit_access_and_sharing() {
    let t = TestApp::new().await;
    let admin = t.login().await;
    t.add_user("carol@acme.com", "auditor").await;
    t.add_user("dave@acme.com", "member").await;
    let auditor = t.login_as("carol@acme.com").await;
    let member = t.login_as("dave@acme.com").await;

    assert_eq!(t.get("/api/audit", Some(&admin)).await.status, StatusCode::OK);
    assert_eq!(t.get("/api/audit", Some(&auditor)).await.status, StatusCode::OK);
    assert_eq!(t.get("/api/audit", Some(&member)).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.get("/api/audit", None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        t.post("/api/shares", public_text("x"), Some(&auditor)).await.status,
        StatusCode::FORBIDDEN,
        "auditors are read-only"
    );
    let me = t.get("/api/auth/me", Some(&auditor)).await;
    assert_eq!(
        (me.body["user"]["role"].as_str(), me.body["mode"].as_str()),
        (Some("auditor"), Some("single"))
    );
}

#[tokio::test]
async fn disabled_users_cannot_sign_in_or_use_sessions() {
    let t = TestApp::new().await;
    let id = t.add_user("eve@acme.com", "member").await;
    let cookie = t.login_as("eve@acme.com").await;
    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = ?")
        .bind(id)
        .execute(&t.state.db)
        .await
        .unwrap();
    assert_eq!(t.get("/api/shares", Some(&cookie)).await.status, StatusCode::UNAUTHORIZED);
    let r = t
        .post("/api/auth/login", json!({"email": "eve@acme.com", "password": PASSWORD}), None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        last(&t, "auth.login_failed").await.details,
        r#"{"method":"password","reason":"account_disabled"}"#
    );
}

#[tokio::test]
async fn security_events_are_audited_without_secrets() {
    let t = TestApp::new().await;
    t.post("/api/auth/login", json!({"password": "wrong", "totp": "123456"}), None)
        .await;
    let c = t.login().await;
    let mut body = public_text("TOP-SECRET-CONTENT");
    body["passphrase"] = json!("PASSPHRASE-123");
    body["max_views"] = json!(1);
    body["title"] = json!("Payroll");
    let share = t.create(&c, body).await;
    let slug = share["slug"].as_str().unwrap();
    t.post(&format!("/api/s/{slug}/open"), json!({"passphrase": "nope"}), None).await;
    t.post(&format!("/api/s/{slug}/open"), json!({"passphrase": "PASSPHRASE-123"}), None)
        .await;

    let got = actions(&t).await;
    for a in [
        "auth.login_failed",
        "auth.login",
        "share.created",
        "share.passphrase_failed",
        "share.opened",
    ] {
        assert!(got.iter().any(|x| x == a), "missing {a} in {got:?}");
    }
    let opened = last(&t, "share.opened").await;
    assert_eq!(opened.target_label.as_deref(), Some("Payroll"));
    assert_eq!(opened.ip.as_deref(), Some("198.51.100.1"));
    assert!(opened.details.contains(r#""burned":true"#), "{}", opened.details);
    let created = last(&t, "share.created").await;
    assert_eq!((created.actor_type.as_str(), created.actor_id.as_deref()), ("user", Some("1")));

    let dump: Vec<(String,)> = sqlx::query_as("SELECT details || coalesce(target_label,'') || coalesce(actor_label,'') FROM audit_events")
        .fetch_all(&t.state.db)
        .await
        .unwrap();
    let dump: String = dump.into_iter().map(|r| r.0).collect();
    assert!(
        !dump.contains("TOP-SECRET-CONTENT") && !dump.contains("PASSPHRASE-123"),
        "secrets leaked into audit: {dump}"
    );

    // The share's activity log in the dashboard is a view of the same records.
    let log = t.get(&format!("/api/shares/{}/log", share["id"].as_str().unwrap()), Some(&c)).await;
    let outcomes: Vec<&str> = log
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["outcome"].as_str().unwrap())
        .collect();
    assert_eq!(outcomes, ["opened_burned", "wrong_passphrase", "created"]);
}

#[tokio::test]
async fn audit_api_filters_verifies_and_exports() {
    let t = TestApp::new().await;
    let c = t.login().await;
    for i in 0..3 {
        t.create(&c, public_text(&format!("s{i}"))).await;
    }
    let page = t.get("/api/audit?action=share.&limit=2", Some(&c)).await;
    assert_eq!(page.body["events"].as_array().unwrap().len(), 2);
    assert!(
        page.body["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["action"] == "share.created")
    );
    let before = page.body["next_before"].as_i64().unwrap();
    let page2 = t.get(&format!("/api/audit?action=share.&limit=2&before={before}"), Some(&c)).await;
    assert_eq!(page2.body["events"].as_array().unwrap().len(), 1);
    assert!(page2.body["next_before"].is_null());

    let v = t.get("/api/audit/verify", Some(&c)).await;
    assert_eq!(v.body["ok"], true, "{}", v.body);

    let (st, csv) = t
        .raw("GET", "/api/audit/export?format=csv&action=share.created", vec![], Some(&c), &[])
        .await;
    assert_eq!(st, StatusCode::OK);
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.starts_with("seq,time,action"), "{csv}");
    assert_eq!(csv.lines().count(), 4, "header + 3 shares:\n{csv}");
    let (_, jsonl) = t.raw("GET", "/api/audit/export?format=jsonl", vec![], Some(&c), &[]).await;
    let first: Value = serde_json::from_str(String::from_utf8(jsonl).unwrap().lines().next().unwrap()).unwrap();
    assert_eq!(first["event"]["dataset"], "sharesomething.audit");
    assert!(actions(&t).await.contains(&"audit.exported".to_string()), "exports are audited");

    sqlx::query("UPDATE audit_events SET outcome = 'success' WHERE action = 'auth.login'")
        .execute(&t.state.db)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_events SET actor_label = 'someone else' WHERE seq = 2")
        .execute(&t.state.db)
        .await
        .unwrap();
    let v = t.get("/api/audit/verify", Some(&c)).await;
    assert_eq!((v.body["ok"].as_bool(), v.body["first_bad_seq"].as_i64()), (Some(false), Some(2)));
}

#[tokio::test]
async fn legacy_access_log_is_imported_into_the_chain() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let id = t.create(&c, public_text("x")).await["id"].as_str().unwrap().to_string();
    sqlx::query("INSERT INTO access_log (share_id, ts, ip, identity, outcome) VALUES (?, 100, '10.0.0.1', NULL, 'opened_burned'), (?, 101, '10.0.0.2', 'a@b.c', 'blocked:denied')")
        .bind(&id)
        .bind(&id)
        .execute(&t.state.db)
        .await
        .unwrap();
    t.state.audit.import_legacy_access_log().await.unwrap();
    let gone: Option<(String,)> = sqlx::query_as("SELECT name FROM sqlite_master WHERE name = 'access_log'")
        .fetch_optional(&t.state.db)
        .await
        .unwrap();
    assert!(gone.is_none());
    let log = t.get(&format!("/api/shares/{id}/log"), Some(&c)).await;
    let outcomes: Vec<&str> = log
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["outcome"].as_str().unwrap())
        .collect();
    assert!(
        outcomes.contains(&"opened_burned") && outcomes.contains(&"blocked:denied"),
        "{outcomes:?}"
    );
    assert!(audit::verify(&t.state.db).await.unwrap().ok);
}

// ---------------------------------------------------------------------------------------------
// SIEM shipping
// ---------------------------------------------------------------------------------------------

fn observer() -> Observer {
    Observer {
        hostname: "share.test".into(),
        version: "test",
    }
}

fn shipper(name: &str, kind: ShipperKind) -> ShipperConfig {
    ShipperConfig {
        name: name.into(),
        kind,
        batch_size: 2,
        backfill: true,
    }
}

async fn seed(t: &TestApp, n: usize) {
    for _ in 0..n {
        t.state
            .audit
            .record(audit::Event::new(audit::Action::AuthLogin).user(1, "Owner"))
            .await
            .unwrap();
    }
}

async fn drain(t: &TestApp, cfg: &ShipperConfig, sink: &mut SinkHandle) -> usize {
    let mut total = 0;
    loop {
        let n = ship_once(&t.state.db, cfg, sink, &observer()).await.unwrap();
        if n == 0 {
            return total;
        }
        total += n;
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<(HeaderMap, String)>>>);

async fn http_sink(fail_first: usize) -> (String, Captured) {
    let cap = Captured::default();
    let remaining = Arc::new(Mutex::new(fail_first));
    let c2 = cap.clone();
    let app = Router::new().route(
        "/ingest",
        post(move |headers: HeaderMap, body: Bytes| {
            let (cap, remaining) = (c2.clone(), remaining.clone());
            async move {
                let mut r = remaining.lock().unwrap();
                if *r > 0 {
                    *r -= 1;
                    return (StatusCode::SERVICE_UNAVAILABLE, "down".to_string());
                }
                cap.0.lock().unwrap().push((headers, String::from_utf8(body.to_vec()).unwrap()));
                (StatusCode::OK, r#"{"errors":false}"#.to_string())
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/ingest", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, cap)
}

#[tokio::test]
async fn http_shipper_is_at_least_once_with_hmac_and_backlog() {
    let t = TestApp::new().await;
    seed(&t, 3).await;
    let (url, cap) = http_sink(1).await;
    let cfg = shipper(
        "siem",
        ShipperKind::Http {
            url,
            preset: HttpPreset::Generic,
            token: Some("tok".into()),
            headers: Default::default(),
            hmac_secret: Some("k3y".into()),
        },
    );
    let mut sink = SinkHandle::new(&cfg.kind).unwrap();
    // First attempt hits an outage: nothing is lost, the cursor stays put.
    assert!(ship_once(&t.state.db, &cfg, &mut sink, &observer()).await.is_err());
    let total = drain(&t, &cfg, &mut sink).await;
    let head: (i64,) = sqlx::query_as("SELECT MAX(seq) FROM audit_events")
        .fetch_one(&t.state.db)
        .await
        .unwrap();
    assert_eq!(total as i64, head.0, "every record delivered after recovery");

    let batches = cap.0.lock().unwrap().clone();
    let seqs: Vec<i64> = batches
        .iter()
        .flat_map(|(_, b)| {
            b.lines()
                .map(|l| serde_json::from_str::<Value>(l).unwrap()["event"]["sequence"].as_i64().unwrap())
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(seqs, (1..=head.0).collect::<Vec<_>>(), "in order, no gaps or duplicates");
    let (headers, body) = &batches[0];
    assert_eq!(headers["authorization"], "Bearer tok");
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"k3y").unwrap();
    mac.update(body.as_bytes());
    assert_eq!(
        headers["x-sharesomething-signature"],
        format!("sha256={}", audit::hex(&mac.finalize().into_bytes()))
    );

    // A restart resumes from the stored cursor (nothing re-sent).
    let mut fresh = SinkHandle::new(&cfg.kind).unwrap();
    assert_eq!(drain(&t, &cfg, &mut fresh).await, 0);
    let st = audit::ship::status(&t.state.db, std::slice::from_ref(&cfg)).await.unwrap();
    assert_eq!((st[0].behind, st[0].failures), (0, 0));
}

#[tokio::test]
async fn splunk_and_elastic_presets() {
    let t = TestApp::new().await;
    seed(&t, 1).await;
    for (preset, auth) in [
        (HttpPreset::SplunkHec, "Splunk hec-token"),
        (HttpPreset::Elastic, "ApiKey hec-token"),
    ] {
        let (url, cap) = http_sink(0).await;
        let cfg = shipper(
            &format!("{preset:?}"),
            ShipperKind::Http {
                url,
                preset,
                token: Some("hec-token".into()),
                headers: Default::default(),
                hmac_secret: None,
            },
        );
        let mut sink = SinkHandle::new(&cfg.kind).unwrap();
        drain(&t, &cfg, &mut sink).await;
        let (headers, body) = cap.0.lock().unwrap()[0].clone();
        assert_eq!(headers["authorization"], auth);
        let first: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        match preset {
            HttpPreset::SplunkHec => {
                assert_eq!(first["sourcetype"], "sharesomething:audit");
                assert_eq!(first["event"]["event"]["dataset"], "sharesomething.audit");
                assert_eq!(first["event"]["event"]["action"], "auth.login");
                assert!(first["time"].is_i64());
            }
            _ => assert_eq!(first, json!({"create": {}})),
        }
    }
}

/// Reads RFC 6587 octet-counted frames from a TCP syslog stream.
async fn read_frames<R: tokio::io::AsyncRead + Unpin>(r: R, n: usize) -> Vec<String> {
    let mut r = tokio::io::BufReader::new(r);
    let mut out = vec![];
    for _ in 0..n {
        let mut len = vec![];
        r.read_until(b' ', &mut len).await.unwrap();
        let len: usize = String::from_utf8(len).unwrap().trim().parse().unwrap();
        let mut buf = vec![0; len];
        r.read_exact(&mut buf).await.unwrap();
        out.push(String::from_utf8(buf).unwrap());
    }
    out
}

#[tokio::test]
async fn syslog_tcp_cef_and_udp_json() {
    let t = TestApp::new().await;
    seed(&t, 2).await;
    let n = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&t.state.db)
        .await
        .unwrap()
        .0 as usize;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move { read_frames(listener.accept().await.unwrap().0, n).await });
    let cfg = shipper(
        "qradar",
        ShipperKind::Syslog {
            address,
            transport: SyslogTransport::Tcp,
            format: SyslogFormat::Cef,
            ca_file: None,
            app_name: None,
            facility: Some(10),
        },
    );
    drain(&t, &cfg, &mut SinkHandle::new(&cfg.kind).unwrap()).await;
    let frames = server.await.unwrap();
    assert!(frames[0].starts_with("<86>1 "), "authpriv(10)*8+info(6): {}", frames[0]);
    assert!(
        frames
            .iter()
            .all(|f| f.contains(" sharesomething - ") && f.contains("CEF:0|ShareSomething|")),
        "{frames:?}"
    );

    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap().to_string();
    let cfg = shipper(
        "udp",
        ShipperKind::Syslog {
            address,
            transport: SyslogTransport::Udp,
            format: SyslogFormat::Json,
            ca_file: None,
            app_name: Some("ss".into()),
            facility: None,
        },
    );
    drain(&t, &cfg, &mut SinkHandle::new(&cfg.kind).unwrap()).await;
    let mut buf = vec![0; 65536];
    let len = udp.recv(&mut buf).await.unwrap();
    let msg = String::from_utf8_lossy(&buf[..len]).to_string();
    let json_part = &msg[msg.find('{').unwrap()..];
    assert_eq!(serde_json::from_str::<Value>(json_part).unwrap()["event"]["sequence"], 1, "{msg}");
}

#[tokio::test]
async fn syslog_over_tls_with_private_ca() {
    let t = TestApp::new().await;
    seed(&t, 1).await;
    let n = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&t.state.db)
        .await
        .unwrap()
        .0 as usize;

    // A private CA and a server certificate for "localhost", like an internal SIEM collector.
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let srv_key = rcgen::KeyPair::generate().unwrap();
    let srv = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&srv_key, &ca, &ca_key)
        .unwrap();
    let dir = t.state.cfg.data_dir.clone();
    std::fs::create_dir_all(&dir).unwrap();
    let ca_file = dir.join("siem-ca.pem");
    std::fs::write(&ca_file, ca.pem()).unwrap();

    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![srv.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(srv_key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        // Keep accepting until a client completes the handshake (the untrusted attempt fails it).
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            if let Ok(tls) = acceptor.accept(tcp).await {
                return read_frames(tls, n).await;
            }
        }
    });

    let kind = |ca_file| ShipperKind::Syslog {
        address: format!("localhost:{port}"),
        transport: SyslogTransport::Tls,
        format: SyslogFormat::Json,
        ca_file,
        app_name: None,
        facility: None,
    };
    // Without trusting the private CA the connection is refused (no silent downgrade).
    let untrusted = shipper("tls-untrusted", kind(None));
    assert!(
        ship_once(&t.state.db, &untrusted, &mut SinkHandle::new(&untrusted.kind).unwrap(), &observer())
            .await
            .is_err()
    );
    let cfg = shipper("tls", kind(Some(ca_file)));
    drain(&t, &cfg, &mut SinkHandle::new(&cfg.kind).unwrap()).await;
    let frames = server.await.unwrap();
    assert_eq!(frames.len(), n);
}

#[tokio::test]
async fn file_and_stdout_shippers() {
    let t = TestApp::new().await;
    seed(&t, 3).await;
    let path = t.state.cfg.data_dir.join("audit").join("events.jsonl");
    let cfg = shipper(
        "file",
        ShipperKind::File {
            path: path.clone(),
            max_bytes: Some(1),
            keep: Some(2),
        },
    );
    drain(&t, &cfg, &mut SinkHandle::new(&cfg.kind).unwrap()).await;
    // Tiny max_bytes forces rotation between batches.
    assert!(path.exists() && path.with_extension("jsonl.1").exists());
    let lines = std::fs::read_to_string(&path).unwrap();
    assert!(serde_json::from_str::<Value>(lines.lines().next().unwrap()).is_ok());
    let cfg = shipper("stdout", ShipperKind::Stdout);
    assert!(drain(&t, &cfg, &mut SinkHandle::new(&cfg.kind).unwrap()).await > 0);
}

#[test]
fn shippers_parse_from_toml_and_env_style() {
    let toml = r#"
        [[audit.shippers]]
        name = "splunk"
        type = "http"
        preset = "splunk_hec"
        url = "https://splunk:8088/services/collector/event"
        token = "abc"

        [[audit.shippers]]
        name = "qradar"
        type = "syslog"
        address = "qradar.corp:6514"
        transport = "tls"
        format = "cef"
    "#;
    let dir = std::env::temp_dir().join(format!("ss-cfg-{}.toml", uuid::Uuid::new_v4()));
    std::fs::write(&dir, toml).unwrap();
    let cfg = Config::load(Some(&dir)).unwrap();
    assert_eq!(cfg.audit.shippers.len(), 2);
    assert!(matches!(
        cfg.audit.shippers[0].kind,
        ShipperKind::Http {
            preset: HttpPreset::SplunkHec,
            ..
        }
    ));
    assert!(matches!(
        cfg.audit.shippers[1].kind,
        ShipperKind::Syslog {
            transport: SyslogTransport::Tls,
            format: SyslogFormat::Cef,
            ..
        }
    ));
    assert_eq!(cfg.audit.shippers[1].batch_size, 200);
    let _ = std::fs::remove_file(dir);
}
