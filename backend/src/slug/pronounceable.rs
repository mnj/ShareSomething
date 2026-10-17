use serde_json::Value;

use super::*;

/// Consonant-vowel syllables that are easy to say aloud, e.g. `bafoki-turesa`.
pub struct Pronounceable;

const CONSONANTS: &[u8] = b"bdfghjklmnprstvz";
const VOWELS: &[u8] = b"aeiou";

impl Pronounceable {
    fn syllables(opts: &Value) -> Result<usize, SlugError> {
        Ok(int_opt(opts, "syllables", 3, 12, 6)? as usize)
    }
}

impl SlugGenerator for Pronounceable {
    fn id(&self) -> &'static str {
        "pronounceable"
    }

    fn describe(&self) -> GeneratorInfo {
        GeneratorInfo {
            id: self.id().into(),
            label: "Pronounceable".into(),
            description: "Made-up words that are easy to read aloud, e.g. bafoki-turesa".into(),
            user_supplied: false,
            options: vec![OptionField {
                name: "syllables".into(),
                label: "Syllables".into(),
                kind: OptionKind::Int {
                    min: 3,
                    max: 12,
                    default: 6,
                },
            }],
        }
    }

    fn generate(&self, opts: &Value) -> Result<String, SlugError> {
        let n = Self::syllables(opts)?;
        let mut out = String::new();
        for i in 0..n {
            if i > 0 && i % 3 == 0 {
                out.push('-');
            }
            out.push(*pick(CONSONANTS) as char);
            out.push(*pick(VOWELS) as char);
        }
        Ok(out)
    }

    fn validate(&self, slug: &str, opts: &Value) -> Result<(), SlugError> {
        let n = Self::syllables(opts)?;
        let letters: Vec<u8> = slug.bytes().filter(|b| *b != b'-').collect();
        let ok = letters.len() == n * 2
            && letters.chunks(2).all(|c| CONSONANTS.contains(&c[0]) && VOWELS.contains(&c[1]))
            && slug == {
                let mut s = String::new();
                for (i, c) in letters.chunks(2).enumerate() {
                    if i > 0 && i % 3 == 0 {
                        s.push('-');
                    }
                    s.push(c[0] as char);
                    s.push(c[1] as char);
                }
                s
            };
        if !ok {
            return Err(SlugError::InvalidSlug("does not match pronounceable format".into()));
        }
        Ok(())
    }

    fn entropy_bits(&self, opts: &Value) -> f64 {
        Self::syllables(opts)
            .map(|n| n as f64 * ((CONSONANTS.len() * VOWELS.len()) as f64).log2())
            .unwrap_or(0.0)
    }
}
