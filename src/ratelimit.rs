// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! Client-side send ceiling: at most `limit` sends in any one-second window
//! per session, matching `Welcome.max_sends_per_second`. Polymorfa enforces
//! the same ceiling and answers `CODE_RATE_LIMITED` past it; pacing here
//! keeps a burst from the application from turning into refused sends.

use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

const WINDOW: Duration = Duration::from_secs(1);

pub struct SendLimiter {
    sent: Mutex<VecDeque<Instant>>,
}

impl Default for SendLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl SendLimiter {
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(VecDeque::new()),
        }
    }

    /// Wait until one more send fits under `limit` per second, then record
    /// it. Callers queue in arrival order on the internal lock.
    pub async fn acquire(&self, limit: u32) {
        let limit = limit.max(1) as usize;
        let mut sent = self.sent.lock().await;
        loop {
            let now = Instant::now();
            while sent
                .front()
                .is_some_and(|t| now.duration_since(*t) >= WINDOW)
            {
                sent.pop_front();
            }
            if sent.len() < limit {
                sent.push_back(now);
                return;
            }
            let oldest = *sent.front().expect("the window is full");
            tokio::time::sleep_until(oldest + WINDOW).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn no_window_ever_holds_more_than_the_limit() {
        let limiter = SendLimiter::new();
        let start = Instant::now();
        let mut stamps = Vec::new();
        for _ in 0..12 {
            limiter.acquire(5).await;
            stamps.push(Instant::now().duration_since(start));
        }
        for (i, t) in stamps.iter().enumerate() {
            let in_window = stamps[i..].iter().filter(|u| **u < *t + WINDOW).count();
            assert!(in_window <= 5, "{in_window} sends within one second");
        }
        // 12 sends at 5 per second need two full windows.
        assert!(stamps[11] >= Duration::from_secs(2));
    }
}
