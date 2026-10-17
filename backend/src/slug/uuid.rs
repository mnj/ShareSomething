use serde_json::Value;

use super::*;

/// A UUID, e.g. `3f2b6c1e-8d4a-4f7e-9a21-5c0d7e8b9f10`. Long but universally recognised, and
/// the natural choice when links end up in tickets, logs or other systems.
pub struct UuidSlug;

impl UuidSlug {
    fn params(opts: &Value) -> Result<(&str, bool), SlugError> {
        let version = select_opt(opts, "version", &["v4", "v7"], "v4")?;
        let hyphens = select_opt(opts, "format", &["hyphenated", "compact"], "hyphenated")? == "hyphenated";
        Ok((version, hyphens))
    }
}

impl SlugGenerator for UuidSlug {
    fn id(&self) -> &'static str {
        "uuid"
    }

    fn describe(&self) -> GeneratorInfo {
        GeneratorInfo {
            id: self.id().into(),
            label: "GUID".into(),
            description: "A UUID, e.g. 3f2b6c1e-8d4a-4f7e-9a21-5c0d7e8b9f10".into(),
            user_supplied: false,
            options: vec![
                OptionField {
                    name: "version".into(),
                    label: "Kind".into(),
                    kind: OptionKind::Select {
                        choices: vec![
                            Choice::new("v4", "Random (v4)"),
                            Choice::new("v7", "Time-ordered (v7, reveals creation time)"),
                        ],
                        default: "v4".into(),
                    },
                },
                OptionField {
                    name: "format".into(),
                    label: "Format".into(),
                    kind: OptionKind::Select {
                        choices: vec![Choice::new("hyphenated", "With hyphens"), Choice::new("compact", "Without hyphens")],
                        default: "hyphenated".into(),
                    },
                },
            ],
        }
    }

    fn generate(&self, opts: &Value) -> Result<String, SlugError> {
        let (version, hyphens) = Self::params(opts)?;
        let id = if version == "v7" {
            ::uuid::Uuid::now_v7()
        } else {
            ::uuid::Uuid::new_v4()
        };
        Ok(if hyphens {
            id.hyphenated().to_string()
        } else {
            id.simple().to_string()
        })
    }

    fn validate(&self, slug: &str, opts: &Value) -> Result<(), SlugError> {
        let (version, hyphens) = Self::params(opts)?;
        let bad = || SlugError::InvalidSlug("does not match uuid format".into());
        let id = ::uuid::Uuid::parse_str(slug).map_err(|_| bad())?;
        let canonical = if hyphens {
            id.hyphenated().to_string()
        } else {
            id.simple().to_string()
        };
        let want = if version == "v7" { 7 } else { 4 };
        if canonical != slug || id.get_version_num() != want {
            return Err(bad());
        }
        Ok(())
    }

    fn entropy_bits(&self, opts: &Value) -> f64 {
        // v7 spends 48 bits on the timestamp; 74 random bits remain.
        match Self::params(opts) {
            Ok(("v7", _)) => 74.0,
            Ok(_) => 122.0,
            Err(_) => 0.0,
        }
    }
}
