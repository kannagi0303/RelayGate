use std::{
    collections::HashMap,
    env, fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    dns::{DnsCacheEntry, DnsCacheKey},
    dns_observation::{DnsObservationSnapshot, DnsProfileHealthSnapshot},
    path_mode::{app_path_mode, AppPathMode},
};

const DNS_STATE_FILE_NAME: &str = "dns.bin";
const DNS_STATE_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedDnsState {
    #[serde(default)]
    cache: PersistedDnsCache,
    #[serde(default)]
    learned: PersistedDnsLearnedState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedDnsCache {
    #[serde(default)]
    entries: Vec<PersistedDnsCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDnsCacheEntry {
    profile_id: String,
    host: String,
    addrs: Vec<IpAddr>,
    expires_at_unix: u64,
    stale_until_unix: u64,
    #[serde(default)]
    negative: bool,
    #[serde(default)]
    source_profile_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedDnsLearnedState {
    #[serde(default)]
    observed_hosts: usize,
    #[serde(default)]
    profiles: Vec<PersistedDnsProfileHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDnsProfileHealth {
    profile_id: String,
    #[serde(default)]
    observed_hosts: usize,
    #[serde(default)]
    samples: u64,
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    success_rate: f64,
    #[serde(default)]
    timeout_rate: f64,
    #[serde(default)]
    nxdomain_rate: f64,
    #[serde(default)]
    no_records_rate: f64,
    #[serde(default)]
    divergent_success_rate: f64,
    #[serde(default)]
    average_latency_ms: Option<u64>,
    #[serde(default)]
    last_latency_ms: Option<u64>,
    #[serde(default)]
    last_ttl_secs: Option<u64>,
    #[serde(default)]
    last_error_kind: Option<String>,
    #[serde(default)]
    last_observed_unix: Option<u64>,
    #[serde(default)]
    health_score: u8,
}

pub(crate) fn load_snapshots(
    max_cache_entries: usize,
) -> (HashMap<DnsCacheKey, DnsCacheEntry>, DnsObservationSnapshot) {
    match load_state_inner() {
        Ok(state) => (
            state.cache.into_cache(max_cache_entries),
            state.learned.into_snapshot(),
        ),
        Err(error) => {
            tracing::warn!(error = %error, "failed to load persisted DNS state");
            (HashMap::new(), DnsObservationSnapshot::default())
        }
    }
}

pub(crate) fn save_snapshots(
    cache: Option<&HashMap<DnsCacheKey, DnsCacheEntry>>,
    learned: Option<&DnsObservationSnapshot>,
) -> bool {
    if cache.is_none() && learned.is_none() {
        return true;
    }

    match save_snapshots_inner(cache, learned) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(error = %error, "failed to save DNS state");
            false
        }
    }
}

fn load_state_inner() -> Result<PersistedDnsState> {
    let path = dns_state_file()?;
    if !path.exists() {
        return Ok(PersistedDnsState::default());
    }

    let content = read_limited_state_file(&path, DNS_STATE_MAX_FILE_BYTES)
        .with_context(|| format!("failed to read DNS state file: {}", path.display()))?;
    postcard::from_bytes(&content)
        .with_context(|| format!("failed to decode DNS state file: {}", path.display()))
}

fn read_limited_state_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read state file metadata: {}", path.display()))?;
    if metadata.len() > max_bytes {
        anyhow::bail!(
            "state file is too large: {} bytes > {} bytes",
            metadata.len(),
            max_bytes
        );
    }
    fs::read(path).with_context(|| format!("failed to read state file content: {}", path.display()))
}

fn save_snapshots_inner(
    cache: Option<&HashMap<DnsCacheKey, DnsCacheEntry>>,
    learned: Option<&DnsObservationSnapshot>,
) -> Result<()> {
    let path = dns_state_file()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create DNS state dir: {}", parent.display()))?;
    }

    let mut state = match load_state_inner() {
        Ok(state) => state,
        Err(error) => {
            tracing::debug!(error = %error, "discarding invalid persisted DNS state before rewrite");
            PersistedDnsState::default()
        }
    };

    if let Some(cache) = cache {
        state.cache = PersistedDnsCache::from_cache(cache);
    }

    if let Some(learned) = learned {
        state.learned = PersistedDnsLearnedState::from_snapshot(learned);
    }

    let content = postcard::to_stdvec(&state).context("failed to serialize DNS state")?;
    write_atomic(&path, &content)
        .with_context(|| format!("failed to replace DNS state file: {}", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create DNS state dir: {}", parent.display()))?;
    }

    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("tmp")
    ));

    {
        let mut file = fs::File::create(&tmp_path).with_context(|| {
            format!(
                "failed to create DNS state temporary file: {}",
                tmp_path.display()
            )
        })?;
        file.write_all(bytes).with_context(|| {
            format!(
                "failed to write DNS state temporary file: {}",
                tmp_path.display()
            )
        })?;
    }

    replace_file(&tmp_path, path)
        .with_context(|| format!("failed to replace DNS state file: {}", path.display()))
}

#[cfg(unix)]
fn replace_file(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to)
        .with_context(|| format!("failed to rename {} to {}", from.display(), to.display()))
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        fs::remove_file(to)
            .with_context(|| format!("failed to remove old file: {}", to.display()))?;
    }
    fs::rename(from, to)
        .with_context(|| format!("failed to rename {} to {}", from.display(), to.display()))
}

#[cfg(not(any(unix, windows)))]
fn replace_file(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        fs::remove_file(to)
            .with_context(|| format!("failed to remove old file: {}", to.display()))?;
    }
    fs::rename(from, to)
        .with_context(|| format!("failed to rename {} to {}", from.display(), to.display()))
}

impl PersistedDnsCache {
    fn from_cache(cache: &HashMap<DnsCacheKey, DnsCacheEntry>) -> Self {
        let now = Instant::now();
        let now_unix = unix_seconds_now();
        let entries = cache
            .iter()
            .filter_map(|(key, entry)| {
                if entry.negative {
                    // Negative DNS results are intentionally memory-only. Persisting them can
                    // turn a short DNS/provider glitch into a broken browser session after restart.
                    return None;
                } else if now > entry.stale_until || entry.addrs.is_empty() {
                    return None;
                }

                Some(PersistedDnsCacheEntry {
                    profile_id: key.profile_id.clone(),
                    host: key.host.clone(),
                    addrs: entry.addrs.clone(),
                    expires_at_unix: now_unix.saturating_add(remaining_secs(now, entry.expires_at)),
                    stale_until_unix: now_unix
                        .saturating_add(remaining_secs(now, entry.stale_until)),
                    negative: entry.negative,
                    source_profile_id: entry.source_profile_id.clone(),
                })
            })
            .collect();

        Self { entries }
    }

    fn into_cache(self, max_cache_entries: usize) -> HashMap<DnsCacheKey, DnsCacheEntry> {
        let now_unix = unix_seconds_now();
        let now = Instant::now();
        let mut cache = HashMap::new();

        for item in self.entries {
            if item.profile_id.trim().is_empty() || item.host.trim().is_empty() {
                continue;
            }
            if item.negative {
                // Negative DNS results are intentionally memory-only.
                continue;
            } else if item.stale_until_unix <= now_unix || item.addrs.is_empty() {
                continue;
            }

            let expires_remaining = item.expires_at_unix.saturating_sub(now_unix);
            let stale_remaining = item.stale_until_unix.saturating_sub(now_unix);
            let source_profile_id = if item.source_profile_id.trim().is_empty() {
                item.profile_id.clone()
            } else {
                item.source_profile_id
            };
            cache.insert(
                DnsCacheKey {
                    profile_id: item.profile_id,
                    host: item.host,
                },
                DnsCacheEntry {
                    addrs: item.addrs,
                    expires_at: now + Duration::from_secs(expires_remaining),
                    stale_until: now + Duration::from_secs(stale_remaining),
                    negative: item.negative,
                    source_profile_id,
                },
            );

            if cache.len() >= max_cache_entries.max(1) {
                break;
            }
        }

        cache
    }
}

impl PersistedDnsLearnedState {
    fn from_snapshot(snapshot: &DnsObservationSnapshot) -> Self {
        let now_unix = unix_seconds_now();
        Self {
            observed_hosts: snapshot.observed_hosts,
            profiles: snapshot
                .profiles
                .iter()
                .map(|profile| PersistedDnsProfileHealth::from_snapshot(profile, now_unix))
                .collect(),
        }
    }

    fn into_snapshot(self) -> DnsObservationSnapshot {
        let now_unix = unix_seconds_now();
        let mut profiles = self
            .profiles
            .into_iter()
            .filter_map(|profile| profile.into_snapshot(now_unix))
            .collect::<Vec<_>>();
        sort_profiles(&mut profiles);

        DnsObservationSnapshot {
            observed_hosts: self.observed_hosts,
            profiles,
        }
    }
}

impl PersistedDnsProfileHealth {
    fn from_snapshot(profile: &DnsProfileHealthSnapshot, now_unix: u64) -> Self {
        Self {
            profile_id: profile.profile_id.clone(),
            observed_hosts: profile.observed_hosts,
            samples: profile.samples,
            successes: profile.successes,
            failures: profile.failures,
            success_rate: finite_f64_or_zero(profile.success_rate),
            timeout_rate: finite_f64_or_zero(profile.timeout_rate),
            nxdomain_rate: finite_f64_or_zero(profile.nxdomain_rate),
            no_records_rate: finite_f64_or_zero(profile.no_records_rate),
            divergent_success_rate: finite_f64_or_zero(profile.divergent_success_rate),
            average_latency_ms: profile.average_latency_ms,
            last_latency_ms: profile.last_latency_ms,
            last_ttl_secs: profile.last_ttl_secs,
            last_error_kind: profile.last_error_kind.map(|kind| kind.to_string()),
            last_observed_unix: profile
                .last_observed_age_secs
                .map(|age| now_unix.saturating_sub(age)),
            health_score: profile.health_score,
        }
    }

    fn into_snapshot(self, now_unix: u64) -> Option<DnsProfileHealthSnapshot> {
        let profile_id = self.profile_id.trim();
        if profile_id.is_empty() || self.samples == 0 {
            return None;
        }

        Some(DnsProfileHealthSnapshot {
            profile_id: profile_id.to_string(),
            observed_hosts: self.observed_hosts,
            samples: self.samples,
            successes: self.successes,
            failures: self.failures,
            success_rate: finite_f64_or_zero(self.success_rate),
            timeout_rate: finite_f64_or_zero(self.timeout_rate),
            nxdomain_rate: finite_f64_or_zero(self.nxdomain_rate),
            no_records_rate: finite_f64_or_zero(self.no_records_rate),
            divergent_success_rate: finite_f64_or_zero(self.divergent_success_rate),
            average_latency_ms: self.average_latency_ms,
            last_latency_ms: self.last_latency_ms,
            last_ttl_secs: self.last_ttl_secs,
            last_error_kind: self
                .last_error_kind
                .as_deref()
                .and_then(normalize_error_kind),
            last_observed_age_secs: self
                .last_observed_unix
                .map(|last| now_unix.saturating_sub(last)),
            health_score: self.health_score.min(100),
        })
    }
}

fn remaining_secs(now: Instant, expires_at: Instant) -> u64 {
    expires_at
        .checked_duration_since(now)
        .unwrap_or_default()
        .as_secs()
}

fn normalize_error_kind(value: &str) -> Option<&'static str> {
    match value {
        "timeout" => Some("timeout"),
        "nxdomain" => Some("nxdomain"),
        "no_records" => Some("no_records"),
        "temporary_failure" => Some("temporary_failure"),
        _ => None,
    }
}

fn finite_f64_or_zero(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn sort_profiles(profiles: &mut [DnsProfileHealthSnapshot]) {
    profiles.sort_by(|left, right| {
        right
            .health_score
            .cmp(&left.health_score)
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn dns_state_file() -> Result<PathBuf> {
    Ok(preferred_base_dir()?
        .join("data")
        .join("state")
        .join(DNS_STATE_FILE_NAME))
}

fn preferred_base_dir() -> Result<PathBuf> {
    match app_path_mode() {
        AppPathMode::Workspace => Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
        AppPathMode::Portable => {
            let exe = env::current_exe().context("failed to resolve current executable path")?;
            let exe_dir = exe.parent().ok_or_else(|| {
                anyhow::anyhow!("current executable path does not have a parent directory")
            })?;
            Ok(exe_dir.to_path_buf())
        }
    }
}
