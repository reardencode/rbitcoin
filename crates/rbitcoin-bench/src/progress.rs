//! Sparse stderr progress for a long bench run.

use std::io::{self, Write};
use std::time::{Duration, Instant};

const MIN_INTERVAL: Duration = Duration::from_secs(15);
const PCT_STEPS: u64 = 20;

pub struct Progress {
    label: String,
    total: u64,
    done: u64,
    started: Instant,
    last_emit: Option<Instant>,
    last_done: u64,
}

impl Progress {
    pub fn start(label: impl Into<String>, total: u64) -> Self {
        let mut p = Self {
            label: label.into(),
            total,
            done: 0,
            started: Instant::now(),
            last_emit: None,
            last_done: 0,
        };
        p.emit(true);
        p
    }

    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = label.into();
        self.emit(true);
    }

    pub fn tick(&mut self) {
        self.done = self.done.saturating_add(1);
        self.emit(false);
    }

    pub fn add_work(&mut self, extra: u64) {
        self.total = self.total.saturating_add(extra);
    }

    pub fn finish(&mut self) {
        self.done = self.total;
        if self.last_done >= self.total && self.total > 0 {
            return;
        }
        self.emit(true);
    }
}

impl Progress {
    fn emit(&mut self, force: bool) {
        let now = Instant::now();
        let since = self
            .last_emit
            .map(|t| now.saturating_duration_since(t))
            .unwrap_or(Duration::MAX);
        if !force && !should_emit(self.done, self.total, self.last_done, since) {
            return;
        }
        let elapsed = now.saturating_duration_since(self.started);
        let line = format_progress(&self.label, self.done, self.total, elapsed);
        let _ = writeln!(io::stderr(), "{line}");
        self.last_emit = Some(now);
        self.last_done = self.done;
    }
}

pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

pub fn format_progress(label: &str, done: u64, total: u64, elapsed: Duration) -> String {
    // Zero total is 100% complete, not `checked_div` None.
    #[allow(clippy::manual_checked_ops)]
    let pct = if total == 0 {
        100
    } else {
        done.saturating_mul(100) / total
    };
    let left = if done == 0 || done >= total {
        "0s".to_string()
    } else {
        let ns = elapsed.as_nanos().saturating_mul((total - done) as u128) / done as u128;
        let secs = (ns / 1_000_000_000) as u64;
        format_duration(Duration::from_secs(secs))
    };
    format!(
        "rbitcoin-bench: {label} {done}/{total} ({pct}%)  elapsed {}  left {left}",
        format_duration(elapsed)
    )
}

pub fn should_emit(done: u64, total: u64, last_done: u64, since_last: Duration) -> bool {
    if done == last_done && last_done != 0 {
        return false;
    }
    if done == 0 || (total > 0 && done >= total) {
        return true;
    }
    let bucket = |n: u64| {
        // Zero total is the last bucket, not `checked_div` None.
        #[allow(clippy::manual_checked_ops)]
        if total == 0 {
            PCT_STEPS
        } else {
            n.saturating_mul(PCT_STEPS) / total
        }
    };
    if bucket(done) > bucket(last_done) {
        return true;
    }
    since_last >= MIN_INTERVAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_human() {
        assert_eq!(format_duration(Duration::from_secs(9)), "9s");
        assert_eq!(format_duration(Duration::from_secs(75)), "1m15s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h01m");
    }

    #[test]
    fn progress_line_has_counts_and_eta() {
        let s = format_progress("casa", 50, 100, Duration::from_secs(10));
        assert!(s.contains("50/100 (50%)"), "{s}");
        assert!(s.contains("elapsed 10s"), "{s}");
        assert!(s.contains("left 10s"), "{s}");
        let done = format_progress("casa", 100, 100, Duration::from_secs(20));
        assert!(done.contains("(100%)"), "{done}");
        assert!(done.contains("left 0s"), "{done}");
    }

    #[test]
    fn emit_on_five_percent_and_interval() {
        assert!(should_emit(0, 100, 0, Duration::from_secs(0)));
        assert!(should_emit(100, 100, 95, Duration::from_secs(1)));
        assert!(!should_emit(1, 100, 0, Duration::from_secs(1)));
        assert!(should_emit(5, 100, 0, Duration::from_secs(1)));
        assert!(should_emit(3, 100, 2, Duration::from_secs(15)));
        assert!(!should_emit(3, 100, 3, Duration::from_secs(15)));
    }
}
