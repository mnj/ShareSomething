use totp_rs::{Algorithm, Secret, TOTP};

pub const ISSUER: &str = "ShareSomething";
const STEP: u64 = 30;

pub fn new_secret() -> String {
    match Secret::generate_secret().to_encoded() {
        Secret::Encoded(s) => s,
        Secret::Raw(_) => unreachable!(),
    }
}

pub fn build(secret_b32: &str) -> anyhow::Result<TOTP> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("bad TOTP secret: {e:?}"))?;
    Ok(TOTP::new(Algorithm::SHA1, 6, 1, STEP, bytes, Some(ISSUER.into()), "owner".into())?)
}

/// Checks `code` against the previous, current and next 30s step. Returns the matched step so
/// the caller can reject replays (step must be greater than the last accepted one).
pub fn verify(secret_b32: &str, code: &str, now: i64) -> anyhow::Result<Option<i64>> {
    let totp = build(secret_b32)?;
    let code = code.trim().replace(' ', "");
    let cur = now / STEP as i64;
    for step in [cur - 1, cur, cur + 1] {
        let expected = totp.generate(step as u64 * STEP);
        if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), code.as_bytes()).into() {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

pub fn otpauth_url(secret_b32: &str) -> anyhow::Result<String> {
    Ok(build(secret_b32)?.get_url())
}

#[cfg(test)]
pub fn code_at(secret_b32: &str, now: i64) -> String {
    build(secret_b32).unwrap().generate(now as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_window() {
        let s = new_secret();
        let now = 1_700_000_000;
        assert_eq!(verify(&s, &code_at(&s, now), now).unwrap(), Some(now / 30));
        assert!(verify(&s, &code_at(&s, now - 30), now).unwrap().is_some());
        assert!(verify(&s, &code_at(&s, now - 120), now).unwrap().is_none());
        assert!(verify(&s, "000000x", now).unwrap().is_none());
    }
}
