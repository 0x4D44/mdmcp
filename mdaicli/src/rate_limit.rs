use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::Config;

struct Bucket {
    capacity: f64, // tokens per minute (RPM capacity)
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(capacity: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let per_sec = self.capacity / 60.0;
        self.tokens = (self.tokens + per_sec * (elapsed.as_secs_f64())).min(self.capacity);
        self.last_refill = now;
    }

    fn take(&mut self, n: f64) -> Option<Duration> {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            return None;
        }
        let per_sec = self.capacity / 60.0;
        let need = n - self.tokens;
        let secs = need / per_sec;
        Some(Duration::from_secs_f64(secs.max(0.0)))
    }
}

static RL: OnceLock<Mutex<HashMap<String, Bucket>>> = OnceLock::new();

fn map() -> &'static Mutex<HashMap<String, Bucket>> {
    RL.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn before_request(cfg: &Config, provider: &str, account: &str) {
    // Use requests_per_minute; default to 60 if not set
    let rpm = cfg
        .limits
        .get(provider)
        .map(|l| l.requests_per_minute as f64)
        .unwrap_or(60.0);
    let key = format!("{}:{}", provider, account);
    let mut guard = map().lock().unwrap();
    let bucket = guard.entry(key).or_insert_with(|| Bucket::new(rpm));
    if let Some(delay) = bucket.take(1.0) {
        std::thread::sleep(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_take_and_refill_math() {
        let mut b = Bucket::new(1.0); // 1 token/min => ~60s per token
        assert!(b.take(1.0).is_none()); // first token available immediately
        let d = b.take(1.0).expect("second should be delayed");
        assert!(d.as_secs() >= 59); // about a minute wait
    }
}
