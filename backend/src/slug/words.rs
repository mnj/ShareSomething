use serde_json::Value;

use super::*;

/// Dictionary words joined by a separator, e.g. `monkey-space-balls-sun`.
pub struct Words {
    list: std::sync::Arc<Vec<String>>,
}

const EFF_SHORT: &str = include_str!("../../assets/eff_short_wordlist_1.txt");
const SEPARATORS: [&str; 3] = ["-", ".", "_"];

impl Words {
    /// The word list, shared with other generators (e.g. templates).
    pub fn list(&self) -> std::sync::Arc<Vec<String>> {
        self.list.clone()
    }

    pub fn eff() -> Self {
        Self::from_text(EFF_SHORT).expect("embedded wordlist is valid")
    }

    pub fn from_text(text: &str) -> anyhow::Result<Self> {
        let mut list: Vec<String> = text
            .lines()
            .map(|l| l.trim().to_ascii_lowercase())
            .filter(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()))
            .collect();
        list.sort();
        list.dedup();
        anyhow::ensure!(
            list.len() >= 256,
            "wordlist needs at least 256 distinct a-z words, got {}",
            list.len()
        );
        Ok(Self {
            list: std::sync::Arc::new(list),
        })
    }

    fn params(opts: &Value) -> Result<(usize, &str), SlugError> {
        Ok((
            int_opt(opts, "count", 2, 8, 4)? as usize,
            select_opt(opts, "separator", &SEPARATORS, "-")?,
        ))
    }
}

impl SlugGenerator for Words {
    fn id(&self) -> &'static str {
        "words"
    }

    fn describe(&self) -> GeneratorInfo {
        GeneratorInfo {
            id: self.id().into(),
            label: "Words".into(),
            description: format!("Random words from a {}-word list, e.g. monkey-space-sun-earth", self.list.len()),
            user_supplied: false,
            options: vec![
                OptionField {
                    name: "count".into(),
                    label: "Number of words".into(),
                    kind: OptionKind::Int {
                        min: 2,
                        max: 8,
                        default: 4,
                    },
                },
                OptionField {
                    name: "separator".into(),
                    label: "Separator".into(),
                    kind: OptionKind::Select {
                        choices: SEPARATORS.iter().map(|s| Choice::new(s, s)).collect(),
                        default: "-".into(),
                    },
                },
            ],
        }
    }

    fn generate(&self, opts: &Value) -> Result<String, SlugError> {
        let (count, sep) = Self::params(opts)?;
        Ok((0..count).map(|_| pick(&self.list).as_str()).collect::<Vec<_>>().join(sep))
    }

    fn validate(&self, slug: &str, opts: &Value) -> Result<(), SlugError> {
        let (count, sep) = Self::params(opts)?;
        let parts: Vec<&str> = slug.split(sep).collect();
        if parts.len() != count || !parts.iter().all(|p| self.list.binary_search_by(|w| w.as_str().cmp(p)).is_ok()) {
            return Err(SlugError::InvalidSlug("does not match words format".into()));
        }
        Ok(())
    }

    fn entropy_bits(&self, opts: &Value) -> f64 {
        Self::params(opts)
            .map(|(c, _)| c as f64 * (self.list.len() as f64).log2())
            .unwrap_or(0.0)
    }
}
