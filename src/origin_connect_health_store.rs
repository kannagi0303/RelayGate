use std::{
    env, fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::path_mode::{app_path_mode, AppPathMode};

const ORIGIN_CONNECT_HEALTH_FILE_NAME: &str = "origin_connect_health.bin";
const ORIGIN_CONNECT_HEALTH_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub(crate) struct OriginConnectHealthSnapshot {
    pub(crate) entries: Vec<OriginConnectHealthSnapshotEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct OriginConnectHealthSnapshotEntry {
    pub(crate) host: String,
    pub(crate) v4: OriginConnectFamilySnapshot,
    pub(crate) v6: OriginConnectFamilySnapshot,
    pub(crate) last_seen_age_secs: u64,
    pub(crate) last_ip: Option<IpAddr>,
    pub(crate) last_result: String,
    pub(crate) last_connect_ms: Option<u64>,
    pub(crate) last_dns_a_count: usize,
    pub(crate) last_dns_aaaa_count: usize,
    pub(crate) last_dns_seen_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct OriginConnectFamilySnapshot {
    pub(crate) success_count: u32,
    pub(crate) fail_count: u32,
    pub(crate) avg_connect_ms: Option<f64>,
    pub(crate) last_success_age_secs: Option<u64>,
    pub(crate) last_failure_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedOriginConnectHealth {
    #[serde(default)]
    entries: Vec<PersistedOriginConnectHealthEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedOriginConnectHealthEntry {
    host: String,
    #[serde(default)]
    v4: PersistedOriginConnectFamilyHealth,
    #[serde(default)]
    v6: PersistedOriginConnectFamilyHealth,
    last_seen_unix: u64,
    #[serde(default)]
    last_ip: Option<IpAddr>,
    #[serde(default)]
    last_result: String,
    #[serde(default)]
    last_connect_ms: Option<u64>,
    #[serde(default)]
    last_dns_a_count: usize,
    #[serde(default)]
    last_dns_aaaa_count: usize,
    #[serde(default)]
    last_dns_seen_unix: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedOriginConnectFamilyHealth {
    #[serde(default)]
    success_count: u32,
    #[serde(default)]
    fail_count: u32,
    #[serde(default)]
    avg_connect_ms: Option<f64>,
    #[serde(default)]
    last_success_unix: Option<u64>,
    #[serde(default)]
    last_failure_unix: Option<u64>,
}

pub(crate) fn load_snapshot(max_entries: usize) -> OriginConnectHealthSnapshot {
    match load_snapshot_inner(max_entries) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::debug!(error = %error, "failed to load persisted origin connect health; starting empty");
            OriginConnectHealthSnapshot::default()
        }
    }
}

pub(crate) fn save_snapshot(snapshot: Option<&OriginConnectHealthSnapshot>) -> bool {
    let Some(snapshot) = snapshot else {
        return true;
    };

    match save_snapshot_inner(snapshot) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(error = %error, "failed to save origin connect health state");
            false
        }
    }
}

fn load_snapshot_inner(max_entries: usize) -> Result<OriginConnectHealthSnapshot> {
    let path = origin_connect_health_file()?;
    if !path.exists() {
        return Ok(OriginConnectHealthSnapshot::default());
    }

    let content = read_limited_state_file(&path, ORIGIN_CONNECT_HEALTH_MAX_FILE_BYTES)
        .with_context(|| {
            format!(
                "failed to read origin connect health state file: {}",
                path.display()
            )
        })?;
    let persisted: PersistedOriginConnectHealth =
        postcard::from_bytes(&content).with_context(|| {
            format!(
                "failed to decode origin connect health state file: {}",
                path.display()
            )
        })?;
    Ok(persisted.into_snapshot(max_entries))
}

fn read_limited_state_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path).with_context(|| {
        format!(
            "failed to read origin connect health state file metadata: {}",
            path.display()
        )
    })?;
    if metadata.len() > max_bytes {
        anyhow::bail!(
            "state file is too large: {} bytes > {} bytes",
            metadata.len(),
            max_bytes
        );
    }
    fs::read(path).with_context(|| {
        format!(
            "failed to read origin connect health state file content: {}",
            path.display()
        )
    })
}

fn save_snapshot_inner(snapshot: &OriginConnectHealthSnapshot) -> Result<()> {
    let path = origin_connect_health_file()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create origin connect health state dir: {}",
                parent.display()
            )
        })?;
    }

    let persisted = PersistedOriginConnectHealth::from_snapshot(snapshot);
    let content = postcard::to_stdvec(&persisted)
        .context("failed to serialize origin connect health state")?;
    write_atomic(&path, &content).with_context(|| {
        format!(
            "failed to replace origin connect health state file: {}",
            path.display()
        )
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create origin connect health state dir: {}",
                parent.display()
            )
        })?;
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
                "failed to create origin connect health temporary file: {}",
                tmp_path.display()
            )
        })?;
        file.write_all(bytes).with_context(|| {
            format!(
                "failed to write origin connect health temporary file: {}",
                tmp_path.display()
            )
        })?;
    }

    replace_file(&tmp_path, path).with_context(|| {
        format!(
            "failed to replace origin connect health state file: {}",
            path.display()
        )
    })
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

impl PersistedOriginConnectHealth {
    fn from_snapshot(snapshot: &OriginConnectHealthSnapshot) -> Self {
        let now_unix = unix_seconds_now();
        let mut entries = snapshot
            .entries
            .iter()
            .filter_map(|entry| PersistedOriginConnectHealthEntry::from_snapshot(entry, now_unix))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| right.last_seen_unix.cmp(&left.last_seen_unix));
        Self { entries }
    }

    fn into_snapshot(self, max_entries: usize) -> OriginConnectHealthSnapshot {
        let now_unix = unix_seconds_now();
        let mut entries = self
            .entries
            .into_iter()
            .filter_map(|entry| entry.into_snapshot(now_unix))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.last_seen_age_secs);
        entries.truncate(max_entries.max(1));
        OriginConnectHealthSnapshot { entries }
    }
}

impl PersistedOriginConnectHealthEntry {
    fn from_snapshot(entry: &OriginConnectHealthSnapshotEntry, now_unix: u64) -> Option<Self> {
        let host = entry.host.trim();
        if host.is_empty()
            || (entry.v4.success_count == 0
                && entry.v4.fail_count == 0
                && entry.v6.success_count == 0
                && entry.v6.fail_count == 0)
        {
            return None;
        }

        Some(Self {
            host: host.to_string(),
            v4: PersistedOriginConnectFamilyHealth::from_snapshot(&entry.v4, now_unix),
            v6: PersistedOriginConnectFamilyHealth::from_snapshot(&entry.v6, now_unix),
            last_seen_unix: now_unix.saturating_sub(entry.last_seen_age_secs),
            last_ip: entry.last_ip,
            last_result: entry.last_result.clone(),
            last_connect_ms: entry.last_connect_ms,
            last_dns_a_count: entry.last_dns_a_count,
            last_dns_aaaa_count: entry.last_dns_aaaa_count,
            last_dns_seen_unix: entry
                .last_dns_seen_age_secs
                .map(|age| now_unix.saturating_sub(age)),
        })
    }

    fn into_snapshot(self, now_unix: u64) -> Option<OriginConnectHealthSnapshotEntry> {
        let host = self.host.trim();
        if host.is_empty() {
            return None;
        }

        Some(OriginConnectHealthSnapshotEntry {
            host: host.to_string(),
            v4: self.v4.into_snapshot(now_unix),
            v6: self.v6.into_snapshot(now_unix),
            last_seen_age_secs: now_unix.saturating_sub(self.last_seen_unix),
            last_ip: self.last_ip,
            last_result: normalize_result(&self.last_result).to_string(),
            last_connect_ms: self.last_connect_ms,
            last_dns_a_count: self.last_dns_a_count,
            last_dns_aaaa_count: self.last_dns_aaaa_count,
            last_dns_seen_age_secs: self
                .last_dns_seen_unix
                .map(|last| now_unix.saturating_sub(last)),
        })
    }
}

impl PersistedOriginConnectFamilyHealth {
    fn from_snapshot(snapshot: &OriginConnectFamilySnapshot, now_unix: u64) -> Self {
        Self {
            success_count: snapshot.success_count,
            fail_count: snapshot.fail_count,
            avg_connect_ms: snapshot.avg_connect_ms.filter(|value| value.is_finite()),
            last_success_unix: snapshot
                .last_success_age_secs
                .map(|age| now_unix.saturating_sub(age)),
            last_failure_unix: snapshot
                .last_failure_age_secs
                .map(|age| now_unix.saturating_sub(age)),
        }
    }

    fn into_snapshot(self, now_unix: u64) -> OriginConnectFamilySnapshot {
        OriginConnectFamilySnapshot {
            success_count: self.success_count,
            fail_count: self.fail_count,
            avg_connect_ms: self.avg_connect_ms.filter(|value| value.is_finite()),
            last_success_age_secs: self
                .last_success_unix
                .map(|last| now_unix.saturating_sub(last)),
            last_failure_age_secs: self
                .last_failure_unix
                .map(|last| now_unix.saturating_sub(last)),
        }
    }
}

fn normalize_result(value: &str) -> &'static str {
    match value {
        "success" => "success",
        "failure" => "failure",
        _ => "none",
    }
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn origin_connect_health_file() -> Result<PathBuf> {
    Ok(preferred_base_dir()?
        .join("data")
        .join("state")
        .join(ORIGIN_CONNECT_HEALTH_FILE_NAME))
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
