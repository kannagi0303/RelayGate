use std::{
    collections::HashMap,
    env, fs,
    net::IpAddr,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    dns::{DnsCacheEntry, DnsCacheKey},
    path_mode::{app_path_mode, AppPathMode},
};

const DNS_CACHE_FILE_NAME: &str = "cache.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDnsCache {
    #[serde(default)]
    version: u8,
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
}

pub(crate) fn load_cache(max_cache_entries: usize) -> HashMap<DnsCacheKey, DnsCacheEntry> {
    match load_cache_inner(max_cache_entries) {
        Ok(cache) => cache,
        Err(error) => {
            tracing::warn!(error = %error, "failed to load persisted DNS cache");
            HashMap::new()
        }
    }
}

pub(crate) fn save_cache(cache: &HashMap<DnsCacheKey, DnsCacheEntry>) {
    if let Err(error) = save_cache_inner(cache) {
        tracing::debug!(error = %error, "failed to save persisted DNS cache");
    }
}

fn load_cache_inner(max_cache_entries: usize) -> Result<HashMap<DnsCacheKey, DnsCacheEntry>> {
    let path = dns_cache_file()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read DNS cache file: {}", path.display()))?;
    let persisted: PersistedDnsCache = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse DNS cache file: {}", path.display()))?;

    let now_unix = unix_seconds_now();
    let now = Instant::now();
    let mut cache = HashMap::new();
    for item in persisted.entries {
        if item.profile_id.trim().is_empty() || item.host.trim().is_empty() {
            continue;
        }
        if item.negative {
            // Negative DNS results are intentionally memory-only. Persisting them can
            // turn a short DNS/provider glitch into a broken browser session after restart.
            continue;
        } else if item.stale_until_unix <= now_unix || item.addrs.is_empty() {
            continue;
        }

        let expires_remaining = item.expires_at_unix.saturating_sub(now_unix);
        let stale_remaining = item.stale_until_unix.saturating_sub(now_unix);
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
            },
        );

        if cache.len() >= max_cache_entries.max(1) {
            break;
        }
    }

    Ok(cache)
}

fn save_cache_inner(cache: &HashMap<DnsCacheKey, DnsCacheEntry>) -> Result<()> {
    let path = dns_cache_file()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create DNS cache dir: {}", parent.display()))?;
    }

    let now = Instant::now();
    let now_unix = unix_seconds_now();
    let entries = cache
        .iter()
        .filter_map(|(key, entry)| {
            if entry.negative {
                // Keep negative DNS cache entries in memory only. Positive cache can
                // improve startup latency, but negative cache should not survive restarts.
                return None;
            } else if now > entry.stale_until || entry.addrs.is_empty() {
                return None;
            }

            Some(PersistedDnsCacheEntry {
                profile_id: key.profile_id.clone(),
                host: key.host.clone(),
                addrs: entry.addrs.clone(),
                expires_at_unix: now_unix.saturating_add(remaining_secs(now, entry.expires_at)),
                stale_until_unix: now_unix.saturating_add(remaining_secs(now, entry.stale_until)),
                negative: entry.negative,
            })
        })
        .collect::<Vec<_>>();

    let payload = PersistedDnsCache {
        version: 1,
        entries,
    };
    let content =
        serde_json::to_string_pretty(&payload).context("failed to serialize DNS cache")?;
    fs::write(&path, content)
        .with_context(|| format!("failed to write DNS cache file: {}", path.display()))
}

fn remaining_secs(now: Instant, expires_at: Instant) -> u64 {
    expires_at
        .checked_duration_since(now)
        .unwrap_or_default()
        .as_secs()
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn dns_cache_file() -> Result<PathBuf> {
    Ok(preferred_base_dir()?
        .join("data")
        .join("dns")
        .join(DNS_CACHE_FILE_NAME))
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
