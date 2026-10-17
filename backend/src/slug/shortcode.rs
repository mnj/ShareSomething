use serde_json::Value;

use super::*;

/// Random short code, e.g. `k7m2qx9d`.
pub struct Shortcode;

/// Lowercase, without the easily confused i, l, o, u.
const BASE32: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";
const BASE62: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";

impl Shortcode {
    fn params(opts: &Value) -> Result<(usize, &'static [u8]), SlugError> {
        let len = int_opt(opts, "length", 4, 32, 8)? as usize;
        let alphabet = match select_opt(opts, "alphabet", &["base32", "base62", "digits"], "base32")? {
            "base62" => BASE62,
            "digits" => DIGITS,
            _ => BASE32,
        };
        Ok((len, alphabet))
    }
}

impl SlugGenerator for Shortcode {
    fn id(&self) -> &'static str {
        "shortcode"
    }

    fn describe(&self) -> GeneratorInfo {
        GeneratorInfo {
            id: self.id().into(),
            label: "Short code".into(),
            description: "Random characters, e.g. k7m2qx9d".into(),
            user_supplied: false,
            options: vec![
                OptionField {
                    name: "length".into(),
                    label: "Length".into(),
                    kind: OptionKind::Int {
                        min: 4,
                        max: 32,
                        default: 8,
                    },
                },
                OptionField {
                    name: "alphabet".into(),
                    label: "Characters".into(),
                    kind: OptionKind::Select {
                        choices: vec![
                            Choice::new("base32", "Lowercase + digits (easy to type)"),
                            Choice::new("base62", "Mixed case + digits (shorter)"),
                            Choice::new("digits", "Digits only (PIN-like)"),
                        ],
                        default: "base32".into(),
                    },
                },
            ],
        }
    }

    fn generate(&self, opts: &Value) -> Result<String, SlugError> {
        let (len, alphabet) = Self::params(opts)?;
        Ok((0..len).map(|_| *pick(alphabet) as char).collect())
    }

    fn validate(&self, slug: &str, opts: &Value) -> Result<(), SlugError> {
        let (len, alphabet) = Self::params(opts)?;
        if slug.len() != len || !slug.bytes().all(|b| alphabet.contains(&b)) {
            return Err(SlugError::InvalidSlug("does not match shortcode format".into()));
        }
        Ok(())
    }

    fn entropy_bits(&self, opts: &Value) -> f64 {
        Self::params(opts)
            .map(|(len, a)| len as f64 * (a.len() as f64).log2())
            .unwrap_or(0.0)
    }
}
