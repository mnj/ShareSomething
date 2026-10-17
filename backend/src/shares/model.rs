use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use super::policy::PolicyRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ShareKind {
    Text,
    Link,
    Credential,
}

impl ShareKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ShareKind::Text => "text",
            ShareKind::Link => "link",
            ShareKind::Credential => "credential",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "text" => ShareKind::Text,
            "link" => ShareKind::Link,
            "credential" => ShareKind::Credential,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum EncMode {
    /// Encrypted in the browser; the server only ever sees ciphertext.
    E2e,
    /// Encrypted by the server at rest with a per-share key.
    Server,
}

impl EncMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EncMode::E2e => "e2e",
            EncMode::Server => "server",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "e2e" => Some(EncMode::E2e),
            "server" => Some(EncMode::Server),
            _ => None,
        }
    }
}

/// Decrypted share content. For E2E shares the browser encrypts exactly this JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SharePayload {
    Text {
        text: String,
    },
    Link {
        url: String,
        #[serde(default)]
        note: Option<String>,
    },
    Credential {
        fields: Vec<CredentialField>,
        #[serde(default)]
        note: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CredentialField {
    pub label: String,
    pub value: String,
    /// Masked until revealed in the UI.
    #[serde(default)]
    pub secret: bool,
}

impl SharePayload {
    pub fn kind(&self) -> ShareKind {
        match self {
            SharePayload::Text { .. } => ShareKind::Text,
            SharePayload::Link { .. } => ShareKind::Link,
            SharePayload::Credential { .. } => ShareKind::Credential,
        }
    }

    pub fn validate(&self, max_bytes: usize) -> Result<(), String> {
        let note_ok = |n: &Option<String>| n.as_ref().is_none_or(|n| n.len() <= 10_000);
        match self {
            SharePayload::Text { text } => {
                if text.is_empty() || text.len() > max_bytes {
                    return Err(format!("text must be 1..{max_bytes} bytes"));
                }
            }
            SharePayload::Link { url, note } => {
                let parsed = url::Url::parse(url).map_err(|_| "invalid URL".to_string())?;
                if !matches!(parsed.scheme(), "http" | "https") || url.len() > 8192 {
                    return Err("link must be an http(s) URL".into());
                }
                if !note_ok(note) {
                    return Err("note too long".into());
                }
            }
            SharePayload::Credential { fields, note } => {
                if fields.is_empty() || fields.len() > 50 {
                    return Err("credential needs 1..50 fields".into());
                }
                if fields
                    .iter()
                    .any(|f| f.label.trim().is_empty() || f.label.len() > 200 || f.value.len() > 64 * 1024)
                {
                    return Err("credential field labels are required (max 200 chars), values max 64 KiB".into());
                }
                if !note_ok(note) {
                    return Err("note too long".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SlugRequest {
    /// Generator id from `GET /api/slug-generators`; defaults to the configured default.
    pub generator: Option<String>,
    #[serde(default)]
    #[schema(value_type = std::collections::HashMap<String, Value>)]
    pub options: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateShareRequest {
    pub kind: ShareKind,
    pub title: Option<String>,
    pub enc_mode: EncMode,
    pub slug: SlugRequest,
    /// Destroy after this many successful opens (1 = read once).
    pub max_views: Option<i64>,
    pub expires_in_secs: Option<i64>,
    #[serde(default)]
    pub require_owner_mfa: bool,
    pub policy: Vec<PolicyRule>,
    /// Server mode: plaintext content.
    pub payload: Option<SharePayload>,
    /// Server mode: optional passphrase mixed into the key.
    pub passphrase: Option<String>,
    /// E2E mode: base64 ciphertext (nonce || AES-GCM ciphertext of the payload JSON).
    pub ciphertext: Option<String>,
    /// E2E mode: client encryption metadata (algorithm, KDF params, wrapped key).
    #[schema(value_type = Option<HashMap<String, Value>>)]
    pub enc_meta: Option<Value>,
    /// E2E mode with passphrase: base64 verifier derived from the passphrase.
    pub passphrase_verifier: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateShareRequest {
    /// Empty string clears the title.
    pub title: Option<String>,
    /// Unix time; 0 removes the expiry.
    pub expires_at: Option<i64>,
    /// 0 removes the view limit.
    pub max_views: Option<i64>,
    pub require_owner_mfa: Option<bool>,
    pub policy: Option<Vec<PolicyRule>>,
    /// Revoke now: content is wiped immediately.
    #[serde(default)]
    pub revoke: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ShareStatus {
    Active,
    Expired,
    Burned,
    Revoked,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareSummary {
    pub id: String,
    pub slug: String,
    pub slug_generator: String,
    /// Link without any E2E key fragment.
    pub url: String,
    pub kind: ShareKind,
    pub title: Option<String>,
    pub enc_mode: EncMode,
    pub passphrase_required: bool,
    /// Wrong passphrase attempts so far.
    pub failed_attempts: i64,
    pub require_owner_mfa: bool,
    pub max_views: Option<i64>,
    pub views: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub status: ShareStatus,
    pub policy: Vec<PolicyRule>,
    pub entropy_bits: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessStatus {
    Ready,
    NeedPassphrase,
    NeedOwnerLogin,
    NeedOwnerMfa,
    NeedAuth,
    Denied,
}

/// What a visitor learns before opening a share. Details are hidden unless access is allowed.
#[derive(Debug, Serialize, ToSchema)]
pub struct ShareInfo {
    pub slug: String,
    pub status: AccessStatus,
    /// Acceptable sign-in methods when `status = need_auth` (empty = any).
    pub auth_methods: Vec<String>,
    pub kind: Option<ShareKind>,
    pub title: Option<String>,
    pub enc_mode: Option<EncMode>,
    pub passphrase_required: bool,
    /// E2E: KDF parameters the browser needs to derive the passphrase verifier.
    #[schema(value_type = Option<HashMap<String, Value>>)]
    pub kdf: Option<Value>,
    pub views_left: Option<i64>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct OpenRequest {
    /// Server mode passphrase.
    pub passphrase: Option<String>,
    /// E2E mode passphrase verifier (base64).
    pub passphrase_verifier: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OpenResponse {
    pub kind: ShareKind,
    pub enc_mode: EncMode,
    pub title: Option<String>,
    /// Server mode: decrypted content.
    pub payload: Option<SharePayload>,
    /// E2E mode: base64 ciphertext to decrypt in the browser.
    pub ciphertext: Option<String>,
    #[schema(value_type = Option<HashMap<String, Value>>)]
    pub enc_meta: Option<Value>,
    pub views_left: Option<i64>,
    /// True when this open used the last view and the content has been destroyed.
    pub burned: bool,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct AccessLogEntry {
    pub ts: i64,
    pub ip: String,
    pub country: Option<String>,
    pub identity: Option<String>,
    pub user_agent: Option<String>,
    pub outcome: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewRequest {
    #[serde(default)]
    #[schema(value_type = std::collections::HashMap<String, Value>)]
    pub options: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewResponse {
    pub slug: String,
    pub url: String,
    pub entropy_bits: f64,
}
