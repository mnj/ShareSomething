//! Small in-memory fixed-window rate limiter keyed by client IP (or any string).

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    hits: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Records a hit; returns false when the key is over its limit for the current window.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        if hits.len() > 50_000 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = hits.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }
}

pub struct RateLimiters {
    /// Coarse per-IP budget for every API call except file chunk transfers.
    pub api: RateLimiter,
    pub login: RateLimiter,
    pub lookup: RateLimiter,
    pub open: RateLimiter,
    pub email_ip: RateLimiter,
    pub email_addr: RateLimiter,
    pub email_verify: RateLimiter,
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self {
            api: RateLimiter::new(600, Duration::from_secs(60)),
            login: RateLimiter::new(10, Duration::from_secs(300)),
            lookup: RateLimiter::new(120, Duration::from_secs(60)),
            open: RateLimiter::new(30, Duration::from_secs(60)),
            email_ip: RateLimiter::new(10, Duration::from_secs(600)),
            email_addr: RateLimiter::new(3, Duration::from_secs(600)),
            email_verify: RateLimiter::new(20, Duration::from_secs(600)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_key() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        assert!(rl.check("a"));
        assert!(rl.check("a"));
        assert!(!rl.check("a"));
        assert!(rl.check("b"));
    }
}
