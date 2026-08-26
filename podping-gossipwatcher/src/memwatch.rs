// Adaptive memory watchdog.
//
// Mitigates unbounded RSS growth from iroh's path-open retry leak
// (https://github.com/n0-computer/iroh/issues/4390): a fast poller checks
// process RSS against thresholds derived from the machine's effective memory
// (host RAM capped by any cgroup limit). Crossing the soft ceiling triggers
// the existing endpoint recycle; the hard ceiling — or a soft breach that a
// recycle fails to clear — re-execs the process in place, which frees all
// memory (including a wedged iroh actor task) without depending on any
// container restart policy.

const MB: u64 = 1024 * 1024;

const SOFT_FLOOR: u64 = 128 * MB;
const SOFT_CAP: u64 = 1024 * MB;
const DEFAULT_SOFT: u64 = 512 * MB;
const DEFAULT_HARD: u64 = 1024 * MB;
// cgroup v1 reports "unlimited" as a huge page-aligned i64::MAX-ish value
const CGROUP_UNLIMITED_MIN: u64 = 1 << 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    pub soft: u64,
    pub hard: u64,
}

/// Parse the MemTotal line of /proc/meminfo ("MemTotal: 16384256 kB") into bytes.
pub fn parse_meminfo_total(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

/// Parse a cgroup memory limit file (v2 memory.max or v1 memory.limit_in_bytes).
/// Returns None when unlimited ("max", or the v1 no-limit sentinel) or unparseable.
pub fn parse_cgroup_limit(contents: &str) -> Option<u64> {
    let v = contents.trim();
    if v == "max" {
        return None;
    }
    v.parse::<u64>().ok().filter(|&n| n < CGROUP_UNLIMITED_MIN)
}

/// Compute watchdog thresholds from the machine's effective total memory.
///
/// soft = clamp(total/4, 128MB, 1GB); hard = min(2*soft, total/2), never below
/// soft. Without a known total, conservative fixed defaults (512MB/1GB).
/// Overrides (from env) win verbatim, with hard floored to soft.
pub fn compute_thresholds(
    effective_total: Option<u64>,
    soft_override: Option<u64>,
    hard_override: Option<u64>,
) -> Thresholds {
    let (formula_soft, formula_hard) = match effective_total {
        Some(total) => {
            let soft = (total / 4).clamp(SOFT_FLOOR, SOFT_CAP);
            let hard = (soft * 2).min(total / 2).max(soft);
            (soft, hard)
        }
        None => (DEFAULT_SOFT, DEFAULT_HARD),
    };
    let mut soft = soft_override.unwrap_or(formula_soft);
    let hard = hard_override.unwrap_or(formula_hard);
    // Keep hard >= soft: an explicit hard below a formula-derived soft pulls
    // soft down (the operator's value wins); an explicit soft floors hard.
    if hard < soft && soft_override.is_none() {
        soft = hard;
    }
    Thresholds { soft, hard: hard.max(soft) }
}

/// How often the watchdog samples RSS. Must be fast relative to the leak's
/// 333ms doubling period so a blowup is caught while still small.
const POLL_INTERVAL_MS: u64 = 500;
/// How long after a soft-triggered recycle RSS may stay above the soft
/// ceiling before we conclude the recycle cannot reclaim (wedged actor).
const RECYCLE_GRACE_SECS: u64 = 60;
const RESTART_COUNT_ENV: &str = "PODPING_WATCHDOG_RESTARTS";

/// Read process resident set size in bytes. Returns 0 on non-Linux or read failure.
pub fn read_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(pages) = s.split_whitespace().nth(1).and_then(|p| p.parse::<u64>().ok()) {
                return pages * 4096;
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Effective memory budget: host RAM capped by any cgroup limit.
fn effective_total_bytes() -> Option<u64> {
    let host = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| parse_meminfo_total(&s));
    let cgroup = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .or_else(|_| std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
        .ok()
        .and_then(|s| parse_cgroup_limit(&s));
    match (host, cgroup) {
        (Some(h), Some(c)) => Some(h.min(c)),
        (h, c) => h.or(c),
    }
}

fn env_mb(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.trim().parse::<u64>().ok().map(|mb| mb * MB)
}

/// Thresholds from effective memory + env overrides, with a description of
/// where they came from (for the startup log).
pub fn thresholds_from_env() -> (Thresholds, String) {
    let total = effective_total_bytes();
    let soft_override = env_mb("PODPING_MEM_SOFT_MB");
    let hard_override = env_mb("PODPING_MEM_HARD_MB");
    let t = compute_thresholds(total, soft_override, hard_override);
    let source = if soft_override.is_some() || hard_override.is_some() {
        "env override".to_string()
    } else {
        match total {
            Some(b) => format!("scaled from {}MB effective memory", b / MB),
            None => "defaults (effective memory unknown)".to_string(),
        }
    };
    (t, source)
}

pub fn enabled() -> bool {
    !std::env::var("PODPING_MEMWATCH").is_ok_and(|v| v.eq_ignore_ascii_case("off"))
}

/// Number of times the watchdog has re-exec'd this process (0 on a fresh start).
pub fn restart_count() -> u64 {
    std::env::var(RESTART_COUNT_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// Replace the process image in place, freeing all memory while keeping the
/// PID (and therefore the container) alive. Falls back to exit(1) so a
/// supervisor/restart policy can take over if exec itself fails.
fn restart_process(reason: &str) -> ! {
    let restarts = restart_count() + 1;
    eprintln!(
        "\x1b[1;31m[MEMWATCH] {} — re-exec'ing process to reclaim memory (restart #{})\x1b[0m",
        reason, restarts
    );
    // Pause so a misconfigured threshold produces a visible slow loop, not a hot one
    std::thread::sleep(std::time::Duration::from_secs(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new("/proc/self/exe")
            .args(std::env::args_os().skip(1))
            .env(RESTART_COUNT_ENV, restarts.to_string())
            .exec();
        eprintln!("\x1b[1;31m[MEMWATCH] exec failed: {} — exiting instead\x1b[0m", err);
    }
    std::process::exit(1);
}

/// Spawn the watchdog task. Soft-ceiling breaches trigger the caller's
/// endpoint-recycle machinery; hard-ceiling breaches (or soft breaches a
/// recycle fails to clear within the grace period) re-exec the process.
pub fn spawn(
    thresholds: Thresholds,
    force_endpoint_reset: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reconnect_requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reconnect_notify: std::sync::Arc<tokio::sync::Notify>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    tokio::spawn(async move {
        let mut soft_tripped_at: Option<std::time::Instant> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            let rss = read_rss_bytes();
            if rss == 0 {
                continue;
            }
            if rss > thresholds.hard {
                restart_process(&format!(
                    "RSS {}MB exceeds hard ceiling {}MB",
                    rss / MB,
                    thresholds.hard / MB
                ));
            }
            if rss > thresholds.soft {
                match soft_tripped_at {
                    None => {
                        eprintln!(
                            "\x1b[1;35m[MEMWATCH] RSS {}MB exceeds soft ceiling {}MB — triggering endpoint recycle\x1b[0m",
                            rss / MB,
                            thresholds.soft / MB
                        );
                        force_endpoint_reset.store(true, Ordering::Relaxed);
                        reconnect_requested.store(true, Ordering::Relaxed);
                        reconnect_notify.notify_one();
                        soft_tripped_at = Some(std::time::Instant::now());
                    }
                    Some(t) if t.elapsed().as_secs() >= RECYCLE_GRACE_SECS => {
                        restart_process(&format!(
                            "RSS {}MB still above soft ceiling {}MB {}s after endpoint recycle",
                            rss / MB,
                            thresholds.soft / MB,
                            t.elapsed().as_secs()
                        ));
                    }
                    Some(_) => {}
                }
            } else {
                soft_tripped_at = None;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1024 * MB;

    #[test]
    fn parses_meminfo_total_to_bytes() {
        let meminfo = "MemTotal:       16384256 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_meminfo_total(meminfo), Some(16384256 * 1024));
    }

    #[test]
    fn meminfo_without_memtotal_is_none() {
        assert_eq!(parse_meminfo_total("MemFree: 1234 kB\n"), None);
        assert_eq!(parse_meminfo_total("MemTotal: garbage kB\n"), None);
    }

    #[test]
    fn cgroup_v2_numeric_limit_parses() {
        assert_eq!(parse_cgroup_limit("1073741824\n"), Some(1073741824));
    }

    #[test]
    fn cgroup_v2_max_means_unlimited() {
        assert_eq!(parse_cgroup_limit("max\n"), None);
    }

    #[test]
    fn cgroup_v1_no_limit_sentinel_means_unlimited() {
        assert_eq!(parse_cgroup_limit("9223372036854771712\n"), None);
    }

    #[test]
    fn cgroup_garbage_is_none() {
        assert_eq!(parse_cgroup_limit("not-a-number\n"), None);
    }

    #[test]
    fn thresholds_scale_on_pi_512mb() {
        // 25% of 512MB is 128MB (at the floor); hard = min(256MB, 256MB)
        let t = compute_thresholds(Some(512 * MB), None, None);
        assert_eq!(t, Thresholds { soft: 128 * MB, hard: 256 * MB });
    }

    #[test]
    fn thresholds_scale_on_4gb() {
        let t = compute_thresholds(Some(4 * GB), None, None);
        assert_eq!(t, Thresholds { soft: 1 * GB, hard: 2 * GB });
    }

    #[test]
    fn thresholds_cap_on_64gb() {
        // soft caps at 1GB regardless of RAM; hard = 2GB
        let t = compute_thresholds(Some(64 * GB), None, None);
        assert_eq!(t, Thresholds { soft: 1 * GB, hard: 2 * GB });
    }

    #[test]
    fn thresholds_on_tiny_256mb_host_keep_hard_at_least_soft() {
        // soft floors at 128MB; total/2 = 128MB, so hard clamps up to soft
        let t = compute_thresholds(Some(256 * MB), None, None);
        assert_eq!(t, Thresholds { soft: 128 * MB, hard: 128 * MB });
    }

    #[test]
    fn thresholds_default_without_total() {
        let t = compute_thresholds(None, None, None);
        assert_eq!(t, Thresholds { soft: 512 * MB, hard: 1 * GB });
    }

    #[test]
    fn soft_override_wins_and_hard_follows_formula() {
        let t = compute_thresholds(Some(4 * GB), Some(200 * MB), None);
        assert_eq!(t.soft, 200 * MB);
        assert_eq!(t.hard, 2 * GB); // hard still from formula
    }

    #[test]
    fn hard_override_below_soft_is_floored_to_soft() {
        let t = compute_thresholds(Some(4 * GB), Some(800 * MB), Some(400 * MB));
        assert_eq!(t, Thresholds { soft: 800 * MB, hard: 800 * MB });
    }

    #[test]
    fn hard_override_below_formula_soft_lowers_soft() {
        // Operator set only a hard ceiling, below the computed soft ceiling:
        // their value must win — soft drops to match, not hard raised.
        let t = compute_thresholds(Some(4 * GB), None, Some(10 * MB));
        assert_eq!(t, Thresholds { soft: 10 * MB, hard: 10 * MB });
    }
}
