//! Phase 3: team mode (invites, admin guards, groups, team rules, org policies, SSO members).

use super::*;
use crate::config::{InstanceMode, OidcKind, OidcProviderConfig};

/// A team-mode app whose first admin is admin@acme.com (password + TOTP).
async fn team(f: impl FnOnce(&mut Config)) -> (TestApp, String) {
    let t = TestApp::with_config(|c| {
        c.mode = InstanceMode::Team;
        c.team.allowed_domains = vec!["acme.com".into()];
        f(c)
    })
    .await;
    sqlx::query("UPDATE users SET email = 'admin@acme.com' WHERE id = 1")
        .execute(&t.state.db)
        .await
        .unwrap();
    let code = totp::code_at(&t.totp_secret, now());
    let r = t
        .post(
            "/api/auth/login",
            json!({"email": "admin@acme.com", "password": PASSWORD, "totp": code}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    (t, r.cookie.unwrap())
}

async fn invite_and_join(t: &TestApp, admin: &str, email: &str, role: &str) -> (i64, String) {
    let r = t.post("/api/admin/users", json!({"email": email, "role": role}), Some(admin)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let url = r.body["invite_url"].as_str().unwrap();
    let token = url.rsplit('/').next().unwrap();
    let r = t
        .post(&format!("/api/invites/{token}/accept"), json!({"password": PASSWORD}), None)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    (r.body["user"]["id"].as_i64().unwrap(), r.cookie.unwrap())
}

fn share_for(policy: Value) -> Value {
    json!({
        "kind": "text", "enc_mode": "e2e", "slug": {}, "max_views": 2, "expires_in_secs": 3600,
        "policy": policy,
        "ciphertext": B64.encode([1u8; 64]), "enc_meta": {"v": 1, "key": "fragment"},
    })
}

#[tokio::test]
async fn invite_lifecycle() {
    let (t, admin) = team(|_| {}).await;
    assert_eq!(
        t.post("/api/auth/login", json!({"password": PASSWORD}), None).await.body["error"],
        "bad_request",
        "team login needs an email"
    );

    let r = t
        .post("/api/admin/users", json!({"email": "Bob@Acme.com", "role": "member"}), Some(&admin))
        .await;
    let token = r.body["invite_url"].as_str().unwrap().rsplit('/').next().unwrap().to_string();
    assert_eq!(r.body["user"]["status"], "invited");
    assert_eq!(
        t.post("/api/admin/users", json!({"email": "bob@acme.com", "role": "member"}), Some(&admin))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.get(&format!("/api/invites/{token}"), None).await.body["email"], "bob@acme.com");
    // Invited accounts have no password yet.
    let r = t
        .post("/api/auth/login", json!({"email": "bob@acme.com", "password": PASSWORD}), None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        t.post(&format!("/api/invites/{token}/accept"), json!({"password": "short"}), None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let r = t
        .post(
            &format!("/api/invites/{token}/accept"),
            json!({"password": PASSWORD, "name": "Bob B"}),
            None,
        )
        .await;
    assert_eq!(
        (r.body["user"]["email"].as_str(), r.body["user"]["name"].as_str()),
        (Some("bob@acme.com"), Some("Bob B"))
    );
    assert_eq!(
        t.post(&format!("/api/invites/{token}/accept"), json!({"password": PASSWORD}), None)
            .await
            .status,
        StatusCode::NOT_FOUND,
        "single use"
    );
    assert!(!t.login_as("bob@acme.com").await.is_empty());
}

#[tokio::test]
async fn admin_guards_and_account_controls() {
    let (t, admin) = team(|_| {}).await;
    let (bob_id, bob) = invite_and_join(&t, &admin, "bob@acme.com", "member").await;
    assert_eq!(
        t.get("/api/admin/users", Some(&bob)).await.status,
        StatusCode::FORBIDDEN,
        "members aren't admins"
    );

    let t = &t;
    let patch = |id: i64, body: Value, c: &str| {
        let (uri, c) = (format!("/api/admin/users/{id}"), c.to_string());
        async move { t.req("PATCH", &uri, Some(body), Some(&c), "198.51.100.1", &[]).await }
    };
    assert_eq!(
        patch(1, json!({"status": "disabled"}), &admin).await.status,
        StatusCode::CONFLICT,
        "can't disable yourself"
    );
    assert_eq!(
        patch(1, json!({"role": "member"}), &admin).await.status,
        StatusCode::CONFLICT,
        "can't demote yourself"
    );

    // Promote bob, then the original admin may be demoted by bob (two admins exist).
    assert_eq!(patch(bob_id, json!({"role": "admin"}), &admin).await.body["role"], "admin");
    assert_eq!(patch(1, json!({"role": "member"}), &bob).await.body["role"], "member");
    // Bob is now the last admin.
    let admin_again = t.login_as("bob@acme.com").await;
    assert_eq!(
        patch(bob_id, json!({"role": "member"}), &admin_again).await.status,
        StatusCode::CONFLICT
    );

    // Disabling kills sessions and blocks sign-in; sign-out and MFA reset are audited.
    let (carol_id, carol) = invite_and_join(t, &admin_again, "carol@acme.com", "member").await;
    assert_eq!(
        t.post(&format!("/api/admin/users/{carol_id}/sign-out"), json!({}), Some(&admin_again))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(t.get("/api/shares", Some(&carol)).await.status, StatusCode::UNAUTHORIZED);
    let carol = t.login_as("carol@acme.com").await;
    patch(carol_id, json!({"status": "disabled"}), &admin_again).await;
    assert_eq!(t.get("/api/shares", Some(&carol)).await.status, StatusCode::UNAUTHORIZED);
    let r = t
        .post(&format!("/api/admin/users/{carol_id}/reset-mfa"), json!({}), Some(&admin_again))
        .await;
    assert_eq!(r.body["passkeys"], 0);
    let actions: Vec<(String,)> = sqlx::query_as("SELECT action FROM audit_events WHERE action LIKE 'user.%'")
        .fetch_all(&t.state.db)
        .await
        .unwrap();
    let actions: Vec<String> = actions.into_iter().map(|a| a.0).collect();
    for a in [
        "user.invited",
        "user.invite_accepted",
        "user.updated",
        "user.sessions_revoked",
        "user.mfa_reset",
    ] {
        assert!(actions.contains(&a.to_string()), "missing {a}");
    }
}

#[tokio::test]
async fn groups_and_team_rules() {
    let (t, admin) = team(|_| {}).await;
    let (bob, bob_c) = invite_and_join(&t, &admin, "bob@acme.com", "member").await;
    let (_carol, carol_c) = invite_and_join(&t, &admin, "carol@acme.com", "member").await;
    let (dave, dave_c) = invite_and_join(&t, &admin, "dave@acme.com", "member").await;

    let g = t.post("/api/groups", json!({"name": "Finance"}), Some(&admin)).await;
    let gid = g.body["id"].as_i64().unwrap();
    assert_eq!(
        t.post("/api/groups", json!({"name": "x"}), Some(&bob_c)).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .req(
            "PUT",
            &format!("/api/groups/{gid}/members"),
            Some(json!({"user_ids": [bob, dave]})),
            Some(&admin),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.body["members"], 2);

    let slug = t
        .create(&bob_c, share_for(json!([{"group": "include", "type": "group", "groups": [gid]}])))
        .await["slug"]
        .as_str()
        .unwrap()
        .to_string();
    let t = &t;
    let info = |c: Option<String>| {
        let uri = format!("/api/s/{slug}");
        async move { t.get(&uri, c.as_deref()).await.body["status"].as_str().unwrap().to_string() }
    };
    assert_eq!(info(None).await, "need_login");
    assert_eq!(info(Some(carol_c.clone())).await, "denied");
    assert_eq!(info(Some(dave_c.clone())).await, "ready");

    let slug2 = t
        .create(&carol_c, share_for(json!([{"group": "include", "type": "user", "users": [dave]}])))
        .await["slug"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(t.get(&format!("/api/s/{slug2}"), Some(&dave_c)).await.body["status"], "ready");
    assert_eq!(t.get(&format!("/api/s/{slug2}"), Some(&bob_c)).await.body["status"], "denied");
    assert_eq!(
        t.post(
            "/api/shares",
            share_for(json!([{"group": "include", "type": "group", "groups": [999]}])),
            Some(&bob_c)
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );

    // Directory and groups are readable by members, for the rule editor.
    assert_eq!(
        t.get("/api/directory/users", Some(&carol_c)).await.body.as_array().unwrap().len(),
        4
    );
    assert_eq!(t.get("/api/groups", Some(&carol_c)).await.body[0]["name"], "Finance");
}

#[tokio::test]
async fn org_policies_are_enforced() {
    // Email rules need a sign-in method to be valid at all; the log mailer provides one.
    let (t, admin) = team(|c| c.email.mode = crate::config::EmailMode::Log).await;
    let (_, bob) = invite_and_join(&t, &admin, "bob@acme.com", "member").await;
    let settings = json!({
        "force_e2e": true, "allow_public_shares": false, "max_views": 3, "max_expiry_days": 7,
        "allowed_recipient_domains": ["acme.com"],
    });
    assert_eq!(
        t.req("PUT", "/api/org/settings", Some(settings.clone()), Some(&bob), "198.51.100.1", &[])
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.req("PUT", "/api/org/settings", Some(settings), Some(&admin), "198.51.100.1", &[])
            .await
            .status,
        StatusCode::OK
    );

    let member_rule = json!([{"group": "include", "type": "member"}]);
    let ok = t.post("/api/shares", share_for(member_rule.clone()), Some(&bob)).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{}", ok.body);
    let t = &t;
    let refuse = |body: Value| {
        let bob = bob.clone();
        async move {
            let r = t.post("/api/shares", body, Some(&bob)).await;
            (r.status, r.body["error"].as_str().unwrap_or_default().to_string())
        }
    };
    let mut server = public_text("x");
    server["policy"] = member_rule.clone();
    assert_eq!(
        refuse(server).await,
        (StatusCode::FORBIDDEN, "org_policy".into()),
        "server mode refused"
    );
    assert_eq!(
        refuse(share_for(json!([{"group": "include", "type": "everyone"}]))).await.1,
        "org_policy",
        "public refused"
    );
    let mut many = share_for(member_rule.clone());
    many["max_views"] = json!(10);
    assert_eq!(refuse(many).await.1, "org_policy");
    let mut forever = share_for(member_rule.clone());
    forever["expires_in_secs"] = Value::Null;
    assert_eq!(refuse(forever).await.1, "org_policy");
    assert_eq!(
        refuse(share_for(json!([{"group": "include", "type": "email", "emails": ["x@gmail.com"]}])))
            .await
            .1,
        "org_policy"
    );

    let id = ok.body["share"]["id"].as_str().unwrap();
    let r = t
        .req(
            "PATCH",
            &format!("/api/shares/{id}"),
            Some(json!({"max_views": 0})),
            Some(&bob),
            "198.51.100.1",
            &[],
        )
        .await;
    assert_eq!(r.body["error"], "org_policy", "edits are checked too");
    assert!(
        sqlx::query("SELECT 1 FROM audit_events WHERE action = 'org.settings_changed'")
            .fetch_optional(&t.state.db)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn org_required_mfa_blocks_sharing_until_set_up() {
    let (t, admin) = team(|_| {}).await;
    let (_, bob) = invite_and_join(&t, &admin, "bob@acme.com", "member").await;
    t.req(
        "PUT",
        "/api/org/settings",
        Some(json!({"require_mfa": true})),
        Some(&admin),
        "198.51.100.1",
        &[],
    )
    .await;
    assert_eq!(t.get("/api/auth/me", Some(&bob)).await.body["mfa_setup_required"], true);
    assert_eq!(
        t.post(
            "/api/shares",
            share_for(json!([{"group": "include", "type": "member"}])),
            Some(&bob)
        )
        .await
        .body["error"],
        "mfa_setup_required"
    );
    // The admin has TOTP, so they're fine.
    assert_eq!(t.get("/api/auth/me", Some(&admin)).await.body["mfa_setup_required"], false);
}

#[tokio::test]
async fn admins_see_metadata_of_all_shares_and_can_revoke() {
    let (t, admin) = team(|_| {}).await;
    let (_, bob) = invite_and_join(&t, &admin, "bob@acme.com", "member").await;
    let mut body = share_for(json!([{"group": "include", "type": "member"}]));
    body["title"] = json!("Vendor creds");
    let share = t.create(&bob, body).await;
    let all = t.get("/api/admin/shares", Some(&admin)).await;
    assert_eq!(all.body[0]["owner"], "bob@acme.com");
    assert_eq!(all.body[0]["share"]["title"], "Vendor creds");
    assert!(!all.body.to_string().contains("ciphertext"), "metadata only");
    assert_eq!(t.get("/api/admin/shares", Some(&bob)).await.status, StatusCode::FORBIDDEN);
    let id = share["id"].as_str().unwrap();
    assert_eq!(
        t.post(&format!("/api/admin/shares/{id}/revoke"), json!({}), Some(&admin))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(t.get(&format!("/api/shares/{id}"), Some(&bob)).await.body["status"], "revoked");
}

#[tokio::test]
async fn org_wide_templates() {
    let (t, admin) = team(|_| {}).await;
    let (_, bob) = invite_and_join(&t, &admin, "bob@acme.com", "member").await;
    let policy = json!([{"group": "include", "type": "member"}]);
    let r = t
        .post(
            "/api/policy-templates",
            json!({"name": "Staff only", "policy": policy, "org": true}),
            Some(&admin),
        )
        .await;
    let id = r.body["id"].as_str().unwrap().to_string();
    assert_eq!(
        t.post(
            "/api/policy-templates",
            json!({"name": "x", "policy": policy, "org": true}),
            Some(&bob)
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let list = t.get("/api/policy-templates", Some(&bob)).await;
    assert_eq!(
        (list.body[0]["name"].as_str(), list.body[0]["org"].as_bool()),
        (Some("Staff only"), Some(true))
    );
    assert_eq!(
        t.req(
            "DELETE",
            &format!("/api/policy-templates/{id}"),
            None,
            Some(&bob),
            "198.51.100.1",
            &[]
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn sso_member_sign_in_provisions_and_activates() {
    let idp = mock_idp::spawn().await;
    let (t, admin) = team(move |c| {
        c.oidc = vec![OidcProviderConfig {
            id: "corp".into(),
            name: "Corp SSO".into(),
            kind: OidcKind::Oidc,
            issuer: Some(idp),
            client_id: "client-id".into(),
            client_secret: "secret".into(),
            scopes: vec![],
            trust_unverified_email: false,
            member_login: true,
            github_web_url: None,
            github_api_url: None,
        }]
    })
    .await;
    assert_eq!(
        t.get("/api/auth/sso-providers", None).await.body,
        json!([{"id": "corp", "name": "Corp SSO"}])
    );

    let t = &t;
    let login = |email: &'static str| async move {
        let (r, h) = t
            .req_full(
                "GET",
                "/api/recipient/oidc/corp/start?purpose=member&next=/",
                None,
                None,
                "198.51.100.1",
                &[],
            )
            .await;
        let to = h.get(header::LOCATION).unwrap().to_str().unwrap().to_string();
        let code = mock_idp::code(email, &query_param(&to, "nonce").unwrap(), true);
        let state = query_param(&to, "state").unwrap();
        let (_, h) = t
            .req_full(
                "GET",
                &format!("/api/recipient/oidc/corp/callback?code={code}&state={state}"),
                None,
                Some(&r.cookie.unwrap()),
                "198.51.100.1",
                &[],
            )
            .await;
        let cookie = h
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
            .find(|c| c.starts_with("ss_session="));
        (h.get(header::LOCATION).unwrap().to_str().unwrap().to_string(), cookie)
    };

    // New domain user is provisioned as a member.
    let (to, cookie) = login("erin@acme.com").await;
    assert_eq!(to, "/");
    let me = t.get("/api/auth/me", Some(&cookie.unwrap())).await;
    assert_eq!(
        (me.body["user"]["email"].as_str(), me.body["user"]["role"].as_str()),
        (Some("erin@acme.com"), Some("member"))
    );

    // Outsiders aren't provisioned.
    assert_eq!(login("mallory@evil.com").await.0, "/login?sso_error=not_a_member");

    // Invited users are activated by their first SSO sign-in (no password needed).
    t.post(
        "/api/admin/users",
        json!({"email": "frank@acme.com", "role": "auditor"}),
        Some(&admin),
    )
    .await;
    let (_, cookie) = login("frank@acme.com").await;
    assert_eq!(t.get("/api/auth/me", Some(&cookie.unwrap())).await.body["user"]["role"], "auditor");

    // Disabled accounts can't sign in through SSO either.
    sqlx::query("UPDATE users SET status = 'disabled' WHERE email = 'erin@acme.com'")
        .execute(&t.state.db)
        .await
        .unwrap();
    assert_eq!(login("erin@acme.com").await.0, "/login?sso_error=account_disabled");
    // Recipient-purpose start for member login isn't offered for providers without member_login,
    // and member login isn't available in single mode at all.
    let single = TestApp::new().await;
    assert_eq!(single.get("/api/auth/sso-providers", None).await.body, json!([]));
}
