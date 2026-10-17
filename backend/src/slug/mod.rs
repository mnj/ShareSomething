//! Pluggable share-link generators.
//!
//! To add a new style: implement [`SlugGenerator`] in its own file and register it in
//! [`registry::builtins`]. The UI renders each generator's options from [`GeneratorInfo`].

pub mod custom;
pub mod pronounceable;
pub mod registry;
pub mod shortcode;
pub mod template;
pub mod uuid;
pub mod words;

use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

pub use registry::SlugRegistry;

/// Characters any generator may emit. Slugs live under `/s/`, so they can't collide with app routes.
pub const MAX_SLUG_LEN: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum SlugError {
    #[error("invalid option: {0}")]
    InvalidOption(String),
    #[error("invalid slug: {0}")]
    InvalidSlug(String),
}

pub trait SlugGenerator: Send + Sync {
    fn id(&self) -> &'static str;
    fn describe(&self) -> GeneratorInfo;
    fn generate(&self, opts: &Value) -> Result<String, SlugError>;
    fn validate(&self, slug: &str, opts: &Value) -> Result<(), SlugError>;
    /// Approximate guessing entropy of a slug produced with these options (0 = guessable).
    fn entropy_bits(&self, opts: &Value) -> f64;
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GeneratorInfo {
    pub id: String,
    pub label: String,
    pub description: String,
    /// The slug text itself comes from the user (e.g. vanity slugs) rather than randomness.
    pub user_supplied: bool,
    pub options: Vec<OptionField>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OptionField {
    pub name: String,
    pub label: String,
    #[serde(flatten)]
    pub kind: OptionKind,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OptionKind {
    Int {
        min: i64,
        max: i64,
        default: i64,
    },
    Select {
        choices: Vec<Choice>,
        default: String,
    },
    Text {
        placeholder: String,
        /// Client-side validation regex (empty = none).
        pattern: String,
        /// Pre-filled value (empty = the user must type one).
        default: String,
    },
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

impl Choice {
    pub fn new(value: &str, label: &str) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
        }
    }
}

/// Reads an integer option, applying the default and bounds from its field definition.
pub(crate) fn int_opt(opts: &Value, name: &str, min: i64, max: i64, default: i64) -> Result<i64, SlugError> {
    match opts.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_i64()
                .ok_or_else(|| SlugError::InvalidOption(format!("{name} must be an integer")))?;
            if !(min..=max).contains(&n) {
                return Err(SlugError::InvalidOption(format!("{name} must be between {min} and {max}")));
            }
            Ok(n)
        }
    }
}

pub(crate) fn select_opt<'a>(opts: &'a Value, name: &str, allowed: &[&'a str], default: &'a str) -> Result<&'a str, SlugError> {
    match opts.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| SlugError::InvalidOption(format!("{name} must be a string")))?;
            allowed
                .iter()
                .find(|a| **a == s)
                .copied()
                .ok_or_else(|| SlugError::InvalidOption(format!("{name} must be one of {}", allowed.join(", "))))
        }
    }
}

/// Uniform random index without modulo bias.
pub(crate) fn pick<T>(items: &[T]) -> &T {
    use rand::Rng;
    &items[rand::rngs::OsRng.gen_range(0..items.len())]
}
