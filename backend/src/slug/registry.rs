use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, bail};
use serde_json::Value;

use super::*;
use crate::config::SlugConfig;

#[derive(Clone)]
pub struct SlugRegistry {
    order: Vec<&'static str>,
    generators: HashMap<&'static str, Arc<dyn SlugGenerator>>,
    default: String,
}

/// All built-in generators, in display order.
pub fn builtins(cfg: &SlugConfig) -> anyhow::Result<Vec<Arc<dyn SlugGenerator>>> {
    let words = match &cfg.words_file {
        Some(path) => {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading wordlist {}", path.display()))?;
            words::Words::from_text(&text)?
        }
        None => words::Words::eff(),
    };
    let template = template::Template::new(words.list());
    Ok(vec![
        Arc::new(shortcode::Shortcode),
        Arc::new(words),
        Arc::new(pronounceable::Pronounceable),
        Arc::new(uuid::UuidSlug),
        Arc::new(template),
        Arc::new(custom::Custom),
    ])
}

impl SlugRegistry {
    pub fn from_config(cfg: &SlugConfig) -> anyhow::Result<Self> {
        Self::new(builtins(cfg)?, &cfg.enabled, &cfg.default)
    }

    pub fn new(all: Vec<Arc<dyn SlugGenerator>>, enabled: &[String], default: &str) -> anyhow::Result<Self> {
        for id in enabled {
            if !all.iter().any(|g| g.id() == id) {
                bail!("unknown slug generator '{id}'");
            }
        }
        let active: Vec<_> = all
            .into_iter()
            .filter(|g| enabled.is_empty() || enabled.iter().any(|e| e == g.id()))
            .collect();
        if !active.iter().any(|g| g.id() == default) {
            bail!("default slug generator '{default}' is not enabled");
        }
        Ok(Self {
            order: active.iter().map(|g| g.id()).collect(),
            generators: active.into_iter().map(|g| (g.id(), g)).collect(),
            default: default.to_string(),
        })
    }

    pub fn default_id(&self) -> &str {
        &self.default
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn SlugGenerator>> {
        self.generators.get(id)
    }

    pub fn list(&self) -> Vec<GeneratorInfo> {
        self.order.iter().map(|id| self.generators[id].describe()).collect()
    }

    /// Generates a slug and checks it against the generator's own format and the global limits.
    pub fn generate(&self, id: &str, opts: &Value) -> Result<String, SlugError> {
        let g = self
            .get(id)
            .ok_or_else(|| SlugError::InvalidOption(format!("unknown generator '{id}'")))?;
        let slug = g.generate(opts)?;
        g.validate(&slug, opts)?;
        if slug.is_empty() || slug.len() > MAX_SLUG_LEN || !slug.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)) {
            return Err(SlugError::InvalidSlug(format!("generator '{id}' produced an unsafe slug")));
        }
        Ok(slug)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn registry() -> SlugRegistry {
        SlugRegistry::from_config(&SlugConfig::default()).unwrap()
    }

    /// Every registered random generator must round-trip and produce varied output.
    #[test]
    fn conformance_all_random_generators() {
        let reg = registry();
        for info in reg.list().into_iter().filter(|i| !i.user_supplied) {
            let g = reg.get(&info.id).unwrap();
            let opts = json!({});
            let mut seen = std::collections::HashSet::new();
            for _ in 0..200 {
                let s = reg.generate(&info.id, &opts).unwrap();
                g.validate(&s, &opts)
                    .unwrap_or_else(|e| panic!("{}: {s} failed validation: {e}", info.id));
                seen.insert(s);
            }
            assert!(seen.len() > 190, "{} produced too many duplicates", info.id);
            assert!(g.entropy_bits(&opts) >= 30.0, "{} default entropy too low", info.id);
        }
    }

    #[test]
    fn options_are_bounds_checked() {
        let reg = registry();
        assert!(reg.generate("shortcode", &json!({"length": 2})).is_err());
        assert!(reg.generate("shortcode", &json!({"alphabet": "emoji"})).is_err());
        assert_eq!(
            reg.generate("shortcode", &json!({"length": 12, "alphabet": "digits"}))
                .unwrap()
                .len(),
            12
        );
        let w = reg.generate("words", &json!({"count": 5, "separator": "."})).unwrap();
        assert_eq!(w.split('.').count(), 5);
    }

    #[test]
    fn uuid_and_template() {
        let reg = registry();
        let v4 = reg.generate("uuid", &json!({})).unwrap();
        assert_eq!(v4.len(), 36);
        assert_eq!(::uuid::Uuid::parse_str(&v4).unwrap().get_version_num(), 4);
        let v7 = reg.generate("uuid", &json!({"version": "v7", "format": "compact"})).unwrap();
        assert_eq!(v7.len(), 32);
        assert!(
            reg.get("uuid")
                .unwrap()
                .validate(&v7, &json!({"version": "v4", "format": "compact"}))
                .is_err()
        );

        let t = reg.generate("template", &json!({"template": "acme-{word}-{digits:4}"})).unwrap();
        assert!(t.starts_with("acme-"), "{t}");
        let digits = t.rsplit('-').next().unwrap();
        assert!(digits.len() == 4 && digits.bytes().all(|b| b.is_ascii_digit()), "{t}");
        let g = reg.get("template").unwrap();
        let bits = g.entropy_bits(&json!({"template": "acme-{word}-{digits:4}"}));
        assert!((bits - (1295f64.log2() + 4.0 * 10f64.log2())).abs() < 0.01, "{bits}");
        assert!(reg.generate("template", &json!({"template": "{hex:32}"})).is_err(), "length cap");
        for bad in ["acme", "ACME-{word}", "{nope}", "x-{word", "a b{word}", "{word:3}"] {
            assert!(reg.generate("template", &json!({"template": bad})).is_err(), "{bad} accepted");
        }
        // Adjacent words still validate thanks to backtracking.
        let s = reg.generate("template", &json!({"template": "{word}{word}"})).unwrap();
        g.validate(&s, &json!({"template": "{word}{word}"})).unwrap();
    }

    #[test]
    fn custom_slugs() {
        let reg = registry();
        assert_eq!(reg.generate("custom", &json!({"value": "WiFi-Guest"})).unwrap(), "wifi-guest");
        for bad in ["ab", "-x-y", "a--b", "has space", "../etc", "x".repeat(65).as_str()] {
            assert!(reg.generate("custom", &json!({"value": bad})).is_err(), "{bad} accepted");
        }
        assert_eq!(reg.get("custom").unwrap().entropy_bits(&json!({})), 0.0);
    }

    #[test]
    fn enabled_and_default_validation() {
        let all = builtins(&SlugConfig::default()).unwrap();
        assert!(SlugRegistry::new(all, &["words".into()], "shortcode").is_err());
        let all = builtins(&SlugConfig::default()).unwrap();
        let reg = SlugRegistry::new(all, &["words".into()], "words").unwrap();
        assert!(reg.get("shortcode").is_none());
    }
}
