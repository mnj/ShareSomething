use serde_json::Value;

use super::*;

/// A vanity slug chosen by the owner, e.g. `wifi-guest`.
pub struct Custom;

impl Custom {
    fn check(slug: &str) -> Result<(), SlugError> {
        let b = slug.as_bytes();
        let ok = (3..=64).contains(&b.len())
            && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
            && !slug.contains("--");
        if ok {
            Ok(())
        } else {
            Err(SlugError::InvalidSlug("use 3-64 characters: a-z, 0-9 and single hyphens".into()))
        }
    }
}

impl SlugGenerator for Custom {
    fn id(&self) -> &'static str {
        "custom"
    }

    fn describe(&self) -> GeneratorInfo {
        GeneratorInfo {
            id: self.id().into(),
            label: "Custom".into(),
            description: "Pick your own link text. Easy to guess, so pair it with an access policy or passphrase.".into(),
            user_supplied: true,
            options: vec![OptionField {
                name: "value".into(),
                label: "Link text".into(),
                kind: OptionKind::Text {
                    placeholder: "wifi-guest".into(),
                    pattern: "^[a-z0-9]+(-[a-z0-9]+)*$".into(),
                    default: String::new(),
                },
            }],
        }
    }

    fn generate(&self, opts: &Value) -> Result<String, SlugError> {
        let v = opts
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| SlugError::InvalidOption("value is required".into()))?
            .trim()
            .to_ascii_lowercase();
        Self::check(&v)?;
        Ok(v)
    }

    fn validate(&self, slug: &str, _opts: &Value) -> Result<(), SlugError> {
        Self::check(slug)
    }

    fn entropy_bits(&self, _opts: &Value) -> f64 {
        0.0
    }
}
