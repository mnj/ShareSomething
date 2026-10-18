//! Phase 2 share modes: time-lock, owner approval, notifications, split keys.

use super::*;

#[tokio::test]
async fn time_locked_share_opens_only_after_unlock() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("release notes");
    body["available_from"] = json!(now() + 3600);
    body["max_views"] = json!(1);
    let share = t.create(&c, body).await;
    let (id, slug) = (share["id"].as_str().unwrap(), share["slug"].as_str().unwrap());

    let info = t.get(&format!("/api/s/{slug}"), None).await;
    assert_eq!(info.body["status"], "not_yet");
    assert!(info.body["available_from"].as_i64().unwrap() > now());
    let r = t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("not_yet")));
    let summary = t.get(&format!("/api/shares/{id}"), Some(&c)).await;
    assert_eq!(summary.body["views"], 0, "a time-locked open spends nothing");

    // Unlock now (as if the time had come).
    t.req(
        "PATCH",
        &format!("/api/shares/{id}"),
        Some(json!({"available_from": 0})),
        Some(&c),
        "198.51.100.1",
        &[],
    )
    .await;
    assert_eq!(
        t.post(&format!("/api/s/{slug}/open"), json!({}), None).await.body["payload"]["text"],
        "release notes"
    );

    let mut bad = public_text("x");
    bad["available_from"] = json!(now() + 7200);
    bad["expires_in_secs"] = json!(3600);
    assert_eq!(
        t.post("/api/shares", bad, Some(&c)).await.status,
        StatusCode::BAD_REQUEST,
        "must unlock before expiry"
    );
}

#[tokio::test]
async fn owner_approval_round_trip() {
    let (t, sent) = TestApp::with_email(|_| {}).await;
    let c = t.login().await;
    t.req(
        "PUT",
        "/api/auth/profile",
        Some(json!({"email": "owner@acme.com"})),
        Some(&c),
        "198.51.100.1",
        &[],
    )
    .await;
    let mut body = public_text("break-glass password");
    body["require_approval"] = json!(true);
    body["max_views"] = json!(1);
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();
    let open = format!("/api/s/{slug}/open");

    assert_eq!(t.get(&format!("/api/s/{slug}"), None).await.body["require_approval"], true);
    let r = t.post(&open, json!({}), None).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("need_approval")));
    let (aid, secret) = (
        r.body["approval_id"].as_str().unwrap().to_string(),
        r.body["approval_secret"].as_str().unwrap().to_string(),
    );

    // Waiting: same id, no new secret, nothing spent.
    let r = t.post(&open, json!({"approval_id": aid, "approval_secret": secret}), None).await;
    assert_eq!(
        (r.body["error"].as_str(), r.body["approval_id"].as_str()),
        (Some("need_approval"), Some(aid.as_str()))
    );
    assert!(r.body["approval_secret"].is_null());
    // Someone who knows the id but not the secret just files their own request.
    let r = t.post(&open, json!({"approval_id": aid, "approval_secret": "guess"}), None).await;
    assert_ne!(r.body["approval_id"].as_str(), Some(aid.as_str()));

    // The owner sees the requests, is notified, and approves one.
    let list = t.get("/api/approvals", Some(&c)).await;
    assert_eq!(list.body.as_array().unwrap().len(), 2);
    assert_eq!(list.body[0]["ip"], "198.51.100.1");
    let notes = t.get("/api/notifications", Some(&c)).await;
    assert_eq!(notes.body["unread"], 2);
    assert_eq!(notes.body["items"][0]["kind"], "approval_requested");
    for _ in 0..50 {
        if sent
            .lock()
            .unwrap()
            .iter()
            .any(|(to, b)| to == "owner@acme.com" && b.contains("wants to open"))
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(sent.lock().unwrap().iter().any(|(to, _)| to == "owner@acme.com"), "owner emailed");

    let r = t
        .post(&format!("/api/approvals/{aid}/decide"), json!({"approve": true}), Some(&c))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let r = t.post(&open, json!({"approval_id": aid, "approval_secret": secret}), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["payload"]["text"], "break-glass password");
    assert_eq!(
        t.get("/api/notifications", Some(&c)).await.body["unread"],
        1,
        "decided request's notification is cleared"
    );

    let got: Vec<String> =
        sqlx::query_as::<_, (String,)>("SELECT action FROM audit_events WHERE action LIKE 'share.approval.%' ORDER BY seq")
            .fetch_all(&t.state.db)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.0)
            .collect();
    assert_eq!(
        got,
        ["share.approval.requested", "share.approval.requested", "share.approval.approved"]
    );
}

#[tokio::test]
async fn approval_denial_mfa_and_flood_limits() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let mut body = public_text("x");
    body["require_approval"] = json!(true);
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();
    let open = format!("/api/s/{slug}/open");
    let r = t.post(&open, json!({}), None).await;
    let (aid, secret) = (
        r.body["approval_id"].as_str().unwrap().to_string(),
        r.body["approval_secret"].as_str().unwrap().to_string(),
    );

    // Deciding needs a fresh MFA when the owner has one.
    sqlx::query("UPDATE user_sessions SET mfa_at = 0")
        .execute(&t.state.db)
        .await
        .unwrap();
    let r = t
        .post(&format!("/api/approvals/{aid}/decide"), json!({"approve": false}), Some(&c))
        .await;
    assert_eq!(r.body["error"], "need_owner_mfa");
    sqlx::query("UPDATE user_sessions SET mfa_at = ?")
        .bind(now())
        .execute(&t.state.db)
        .await
        .unwrap();
    t.post(&format!("/api/approvals/{aid}/decide"), json!({"approve": false}), Some(&c))
        .await;
    let r = t.post(&open, json!({"approval_id": aid, "approval_secret": secret}), None).await;
    assert_eq!(r.body["error"], "approval_denied");

    // Other users can't decide someone else's approvals.
    t.add_user("mallory@acme.com", "member").await;
    let m = t.login_as("mallory@acme.com").await;
    let r = t.post(&open, json!({}), None).await;
    let other = r.body["approval_id"].as_str().unwrap().to_string();
    assert_eq!(
        t.post(&format!("/api/approvals/{other}/decide"), json!({"approve": true}), Some(&m))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    for _ in 0..9 {
        t.post(&open, json!({}), None).await;
    }
    assert_eq!(
        t.post(&open, json!({}), None).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "pending requests are capped"
    );
}

#[tokio::test]
async fn open_notifications_and_profile() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let r = t
        .req(
            "PUT",
            "/api/auth/profile",
            Some(json!({"notify_webhook": "http://10.0.0.5/hook"})),
            Some(&c),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "webhooks must be https");
    let r = t
        .req(
            "PUT",
            "/api/auth/profile",
            Some(json!({"name": "Mike", "notify_webhook": "https://hooks.example.com/x"})),
            Some(&c),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.body["user"]["name"], "Mike");
    assert_eq!(r.body["user"]["notify_webhook"], "https://hooks.example.com/x");

    let mut body = public_text("hello");
    body["notify_on_open"] = json!(true);
    body["title"] = json!("Contract");
    let slug = t.create(&c, body).await["slug"].as_str().unwrap().to_string();
    t.post(&format!("/api/s/{slug}/open"), json!({}), None).await;
    let n = t.get("/api/notifications", Some(&c)).await;
    assert_eq!(n.body["items"][0]["kind"], "share_opened");
    assert!(
        n.body["items"][0]["message"]
            .as_str()
            .unwrap()
            .contains("opened \"Contract\" from 198.51.100.1")
    );
    assert_eq!(t.post("/api/notifications/read", json!({}), Some(&c)).await.body["unread"], 0);
}

#[tokio::test]
async fn split_key_shares_validate_and_expose_parameters() {
    let t = TestApp::new().await;
    let c = t.login().await;
    let split = |k: i64, n: i64, meta: Value| {
        json!({
            "kind": "text", "enc_mode": "e2e", "slug": {}, "split": {"k": k, "n": n},
            "policy": [{"group": "include", "type": "everyone"}],
            "ciphertext": B64.encode([1u8; 64]), "enc_meta": meta,
        })
    };
    let meta = json!({"v": 1, "alg": "A256GCM", "key": "split", "split": {"k": 2, "n": 3, "check": "abcdef0123456789"}});
    let share = t.create(&c, split(2, 3, meta.clone())).await;
    assert_eq!((share["split_k"].as_i64(), share["split_n"].as_i64()), (Some(2), Some(3)));
    let info = t.get(&format!("/api/s/{}", share["slug"].as_str().unwrap()), None).await;
    assert_eq!(info.body["split"], json!({"k": 2, "n": 3, "check": "abcdef0123456789"}));

    assert_eq!(
        t.post("/api/shares", split(4, 3, meta.clone()), Some(&c)).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post("/api/shares", split(2, 4, meta.clone()), Some(&c)).await.status,
        StatusCode::BAD_REQUEST,
        "meta must match"
    );
    let mut server = public_text("x");
    server["split"] = json!({"k": 2, "n": 3});
    assert_eq!(
        t.post("/api/shares", server, Some(&c)).await.status,
        StatusCode::BAD_REQUEST,
        "server mode can't split"
    );
}
