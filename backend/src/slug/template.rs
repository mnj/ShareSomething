use std::sync::Arc;

use serde_json::Value;

use super::*;

/// Fixed text with random parts, e.g. `acme-{word}-{digits:4}` -> `acme-otter-4821`.
/// Useful for team/project prefixes while keeping the link unguessable.
pub struct Template {
    words: Arc<Vec<String>>,
}

const DEFAULT: &str = "{word}-{word}-{digits:4}";
const DIGITS: &[u8] = b"0123456789";
const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const CODE: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";
const HEX: &[u8] = b"0123456789abcdef";

#[derive(Debug, Clone, PartialEq)]
enum Part {
    Literal(String),
    Word,
    Chars(&'static [u8], usize),
}

impl Template {
    pub fn new(words: Arc<Vec<String>>) -> Self {
        Self { words }
    }

    fn parse(opts: &Value) -> Result<Vec<Part>, SlugError> {
        let t = match opts.get("template") {
            None | Some(Value::Null) => DEFAULT,
            Some(v) => v.as_str().ok_or_else(|| SlugError::InvalidOption("template must be text".into()))?,
        };
        let t = t.trim();
        let err = |m: &str| SlugError::InvalidOption(format!("template: {m}"));
        if t.is_empty() || t.len() > 80 {
            return Err(err("1-80 characters"));
        }
        let mut parts = Vec::new();
        let mut rest = t;
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix('{') {
                let end = after.find('}').ok_or_else(|| err("unclosed '{'"))?;
                let (name, n) = match after[..end].split_once(':') {
                    Some((name, n)) => (name, Some(n.parse::<usize>().map_err(|_| err("length must be a number"))?)),
                    None => (&after[..end], None),
                };
                let chars = |set: &'static [u8], default: usize| -> Result<Part, SlugError> {
                    let n = n.unwrap_or(default);
                    if !(1..=24).contains(&n) {
                        return Err(err("lengths must be 1-24"));
                    }
                    Ok(Part::Chars(set, n))
                };
                parts.push(match name {
                    "word" if n.is_none() => Part::Word,
                    "digits" => chars(DIGITS, 4)?,
                    "letters" => chars(LETTERS, 4)?,
                    "code" => chars(CODE, 6)?,
                    "hex" => chars(HEX, 8)?,
                    other => {
                        return Err(err(&format!(
                            "unknown token {{{other}}}; use {{word}}, {{digits:N}}, {{letters:N}}, {{code:N}}, {{hex:N}}"
                        )));
                    }
                });
                rest = &after[end + 1..];
            } else {
                let end = rest.find('{').unwrap_or(rest.len());
                let lit = &rest[..end];
                if !lit
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
                {
                    return Err(err("fixed text may only use a-z, 0-9, '-', '.', '_'"));
                }
                parts.push(Part::Literal(lit.to_string()));
                rest = &rest[end..];
            }
        }
        if !parts.iter().any(|p| !matches!(p, Part::Literal(_))) {
            return Err(err("needs at least one random part, e.g. {word} or {digits:4}"));
        }
        Ok(parts)
    }

    /// Backtracking match of `slug` against the parsed template.
    fn matches(&self, parts: &[Part], slug: &str) -> bool {
        let Some((first, rest)) = parts.split_first() else {
            return slug.is_empty();
        };
        match first {
            Part::Literal(l) => slug.strip_prefix(l.as_str()).is_some_and(|s| self.matches(rest, s)),
            Part::Chars(set, n) => {
                slug.len() >= *n && slug.as_bytes()[..*n].iter().all(|b| set.contains(b)) && self.matches(rest, &slug[*n..])
            }
            Part::Word => self
                .words
                .iter()
                .any(|w| slug.strip_prefix(w.as_str()).is_some_and(|s| self.matches(rest, s))),
        }
    }
}

impl SlugGenerator for Template {
    fn id(&self) -> &'static str {
        "template"
    }

    fn describe(&self) -> GeneratorInfo {
        GeneratorInfo {
            id: self.id().into(),
            label: "Template".into(),
            description: "Fixed text plus random parts: {word}, {digits:N}, {letters:N}, {code:N}, {hex:N}. E.g. acme-{word}-{digits:4}"
                .into(),
            user_supplied: false,
            options: vec![OptionField {
                name: "template".into(),
                label: "Template".into(),
                kind: OptionKind::Text {
                    placeholder: DEFAULT.into(),
                    pattern: String::new(),
                    default: DEFAULT.into(),
                },
            }],
        }
    }

    fn generate(&self, opts: &Value) -> Result<String, SlugError> {
        let mut out = String::new();
        for p in Self::parse(opts)? {
            match p {
                Part::Literal(l) => out.push_str(&l),
                Part::Word => out.push_str(pick(&self.words)),
                Part::Chars(set, n) => (0..n).for_each(|_| out.push(*pick(set) as char)),
            }
        }
        Ok(out)
    }

    fn validate(&self, slug: &str, opts: &Value) -> Result<(), SlugError> {
        if self.matches(&Self::parse(opts)?, slug) {
            Ok(())
        } else {
            Err(SlugError::InvalidSlug("does not match the template".into()))
        }
    }

    fn entropy_bits(&self, opts: &Value) -> f64 {
        Self::parse(opts)
            .map(|parts| {
                parts
                    .iter()
                    .map(|p| match p {
                        Part::Literal(_) => 0.0,
                        Part::Word => (self.words.len() as f64).log2(),
                        Part::Chars(set, n) => *n as f64 * (set.len() as f64).log2(),
                    })
                    .sum()
            })
            .unwrap_or(0.0)
    }
}
