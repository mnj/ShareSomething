//! Wire formats for shipping audit records: ECS-compatible JSON, CEF and RFC 5424 syslog.

use serde_json::{Value, json};

use super::{Record, SCHEMA_VERSION, hex};

/// Identifies this ShareSomething instance in shipped events.
#[derive(Debug, Clone)]
pub struct Observer {
    pub hostname: String,
    pub version: &'static str,
}

pub fn rfc3339(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| ts.to_string())
}

fn details(r: &Record) -> Value {
    serde_json::from_str(&r.details).unwrap_or(Value::Null)
}

/// Elastic Common Schema-style document (also what Splunk, Sentinel and generic webhooks get).
pub fn ecs(r: &Record, o: &Observer) -> Value {
    let d = details(r);
    let mut doc = json!({
        "@timestamp": rfc3339(r.ts),
        "schema_version": SCHEMA_VERSION,
        "message": summary(r),
        "event": {
            "kind": "event",
            "dataset": "sharesomething.audit",
            "action": r.action,
            "category": category(&r.action),
            // ECS knows success/failure/unknown; the precise value is in sharesomething.outcome.
            "outcome": if r.outcome == "success" { "success" } else { "failure" },
            "sequence": r.seq,
            "created": rfc3339(r.ts),
        },
        "observer": { "vendor": "ShareSomething", "product": "ShareSomething", "version": o.version, "hostname": o.hostname },
        "sharesomething": {
            "outcome": r.outcome,
            "actor": { "type": r.actor_type, "id": r.actor_id, "label": r.actor_label },
            "target": { "type": r.target_type, "id": r.target_id, "label": r.target_label },
            "details": d,
            "hash": hex(&r.hash),
            "prev_hash": hex(&r.prev_hash),
        },
    });
    if r.actor_type == "user" {
        doc["user"] = json!({ "id": r.actor_id, "name": r.actor_label });
    } else if let Some(label) = &r.actor_label {
        doc["user"] = json!({ "name": label });
    }
    if let Some(ip) = &r.ip {
        doc["source"] = json!({ "ip": ip });
        if let Some(c) = d.get("country").and_then(Value::as_str) {
            doc["source"]["geo"] = json!({ "country_iso_code": c });
        }
    }
    if let Some(ua) = &r.user_agent {
        doc["user_agent"] = json!({ "original": ua });
    }
    doc
}

fn category(action: &str) -> Value {
    let c: &[&str] = match action.split('.').next().unwrap_or("") {
        "auth" | "recipient" => &["authentication"],
        "user" => &["iam"],
        "share" | "template" => &["file"],
        "audit" | "siem" | "system" => &["configuration"],
        _ => &[],
    };
    json!(c)
}

/// One-line human summary, e.g. `share.opened by alice@x.dk on share "Q3 report" (success)`.
pub fn summary(r: &Record) -> String {
    let who = r.actor_label.as_deref().unwrap_or("anonymous");
    let what = match (&r.target_type, &r.target_label, &r.target_id) {
        (Some(t), Some(l), _) => format!(" on {t} \"{l}\""),
        (Some(t), None, Some(id)) => format!(" on {t} {id}"),
        _ => String::new(),
    };
    format!("{} by {who}{what} ({})", r.action, r.outcome)
}

/// CEF severity: routine 3, refused 6, failures 8.
fn severity(r: &Record) -> u8 {
    match r.outcome.as_str() {
        "success" if r.action.starts_with("siem.") || r.action == "share.destroyed" => 6,
        "success" => 3,
        "denied" => 6,
        _ => 8,
    }
}

fn cef_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn cef_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// ArcSight Common Event Format (QRadar, ArcSight, many others).
pub fn cef(r: &Record, o: &Observer) -> String {
    let mut ext = vec![
        format!("rt={}", r.ts * 1000),
        format!("act={}", cef_value(&r.action)),
        format!("outcome={}", cef_value(&r.outcome)),
        format!("externalId={}", r.seq),
    ];
    if let Some(v) = &r.actor_label {
        ext.push(format!("suser={}", cef_value(v)));
    }
    if let Some(v) = &r.actor_id {
        ext.push(format!("suid={}", cef_value(v)));
    }
    if let Some(v) = &r.ip {
        ext.push(format!("src={}", cef_value(v)));
    }
    if let Some(v) = &r.user_agent {
        ext.push(format!("requestClientApplication={}", cef_value(v)));
    }
    for (i, (label, v)) in [
        ("actorType", Some(&r.actor_type)),
        ("targetType", r.target_type.as_ref()),
        ("targetId", r.target_id.as_ref()),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(v) = v {
            ext.push(format!("cs{n}Label={label} cs{n}={}", cef_value(v), n = i + 1));
        }
    }
    if let Some(v) = &r.target_label {
        ext.push(format!("cs4Label=targetLabel cs4={}", cef_value(v)));
    }
    ext.push(format!("cs5Label=details cs5={}", cef_value(&r.details)));
    ext.push(format!("cs6Label=hash cs6={}", hex(&r.hash)));
    format!(
        "CEF:0|ShareSomething|ShareSomething|{}|{}|{}|{}|{}",
        cef_header(o.version),
        cef_header(&r.action),
        cef_header(&summary(r)),
        severity(r),
        ext.join(" ")
    )
}

/// RFC 5424 syslog line: `<PRI>1 TIMESTAMP HOST APP - MSGID - MSG`.
pub fn syslog(r: &Record, o: &Observer, app_name: &str, facility: u8, msg: &str) -> String {
    // Severity: informational (6), warning (4) for refusals, error (3).
    let sev = match r.outcome.as_str() {
        "success" => 6,
        "denied" => 4,
        _ => 3,
    };
    let host = if o.hostname.is_empty() {
        "-".to_string()
    } else {
        o.hostname.clone()
    };
    let msgid: String = r.action.chars().filter(|c| c.is_ascii_graphic()).take(32).collect();
    format!(
        "<{}>1 {} {} {} - {} - {}",
        facility as u16 * 8 + sev,
        rfc3339(r.ts),
        host,
        app_name,
        msgid,
        msg
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> Record {
        Record {
            seq: 7,
            ts: 1_760_000_000,
            actor_type: "recipient".into(),
            actor_id: None,
            actor_label: Some("bob@acme.com".into()),
            ip: Some("203.0.113.9".into()),
            user_agent: Some("Mozilla/5.0".into()),
            action: "share.denied".into(),
            target_type: Some("share".into()),
            target_id: Some("abc".into()),
            target_label: Some("Q3 | report=final".into()),
            outcome: "denied".into(),
            details: r#"{"country":"DK","reason":"ip"}"#.into(),
            prev_hash: vec![1; 32],
            hash: vec![2; 32],
        }
    }

    fn obs() -> Observer {
        Observer {
            hostname: "share.example.com".into(),
            version: "0.1.0",
        }
    }

    #[test]
    fn ecs_document() {
        let d = ecs(&rec(), &obs());
        assert_eq!(d["@timestamp"], "2025-10-09T08:53:20Z");
        assert_eq!(d["event"]["action"], "share.denied");
        assert_eq!(d["event"]["outcome"], "failure");
        assert_eq!(d["sharesomething"]["outcome"], "denied");
        assert_eq!(d["source"]["geo"]["country_iso_code"], "DK");
        assert_eq!(d["user"]["name"], "bob@acme.com");
        assert_eq!(d["event"]["category"], json!(["file"]));
    }

    #[test]
    fn cef_escapes() {
        let c = cef(&rec(), &obs());
        assert!(c.starts_with("CEF:0|ShareSomething|ShareSomething|0.1.0|share.denied|"), "{c}");
        assert!(c.contains(r#"on share "Q3 \| report=final""#), "header pipes escaped: {c}");
        assert!(c.contains(r"cs4=Q3 | report\=final"), "extension '=' escaped: {c}");
        assert!(c.contains("|6|"), "denied is severity 6");
        assert!(c.contains("src=203.0.113.9") && c.contains("suser=bob@acme.com"));
    }

    #[test]
    fn syslog_line() {
        let s = syslog(&rec(), &obs(), "sharesomething", 16, "hello");
        // local0 (16) * 8 + warning (4) = 132
        assert_eq!(
            s,
            "<132>1 2025-10-09T08:53:20Z share.example.com sharesomething - share.denied - hello"
        );
    }
}
