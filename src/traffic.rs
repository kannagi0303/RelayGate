use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{watch, Notify},
    time::{self, Duration, Instant},
};
use tracing::warn;

use crate::{
    config::TrafficConfig,
    lang,
    path_mode::{app_path_mode, AppPathMode},
    runtime::AppRuntime,
};

pub type SharedTrafficState = Arc<TrafficState>;

pub struct TrafficState {
    runtime: AppRuntime,
    storage: TrafficStorage,
    hosts: Mutex<HashMap<String, Arc<HostTrafficEntry>>>,
    persisted_state: Mutex<TrafficStateFile>,
    persist_signal: watch::Sender<u64>,
}

struct TrafficStorage {
    sites_path: PathBuf,
    state_path: PathBuf,
}

struct HostTrafficEntry {
    host: String,
    enabled: bool,
    notify: Notify,
    state: Mutex<HostTrafficRuntime>,
}

#[derive(Debug, Clone)]
struct HostTrafficRuntime {
    throttled: bool,
    observed_active_requests: usize,
    managed_active_requests: usize,
    queued_requests: usize,
    retrying_requests: usize,
    cooldown_until: Option<Instant>,
    next_release_at: Option<Instant>,
    learned: LearnedTrafficState,
    last_status_code: Option<u16>,
    last_429_at: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrafficSitesFile {
    #[serde(default)]
    hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TrafficStateFile {
    #[serde(default)]
    hosts: HashMap<String, LearnedTrafficState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedTrafficState {
    pub cooldown_secs: u64,
    pub release_interval_secs: u64,
    #[serde(default)]
    pub stable_successes: u64,
}

#[derive(Debug, Clone)]
pub struct TrafficRuntimeSnapshot {
    pub controlled_hosts: usize,
    pub active_requests: usize,
    pub queued_requests: usize,
    pub cooling_hosts: usize,
    pub hosts: Vec<HostTrafficHostSnapshot>,
}

#[derive(Debug, Clone)]
pub struct HostTrafficHostSnapshot {
    pub host: String,
    pub enabled: bool,
    pub throttled: bool,
    pub active_requests: usize,
    pub queued_requests: usize,
    pub retrying_requests: usize,
    pub cooldown_remaining_secs: Option<u64>,
    pub cooldown_secs: u64,
    pub release_interval_secs: u64,
    pub last_status_code: Option<u16>,
    pub last_429_at: Option<SystemTime>,
    pub stable_successes: u64,
}

pub struct TrafficPermit {
    runtime: AppRuntime,
    entry: Arc<HostTrafficEntry>,
    granted: bool,
    observed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficAction {
    Bypass,
    Managed,
}

#[derive(Debug, Clone, Copy)]
pub enum TrafficResponseDecision {
    Forward,
    RetryAfterDelay(Duration),
    ReloadPage(Duration),
}

enum AcquireDecision {
    Bypass,
    Granted,
    Wait(Option<Instant>),
}

impl TrafficState {
    pub fn shared(config: &TrafficConfig, runtime: AppRuntime) -> Result<SharedTrafficState> {
        let storage = TrafficStorage {
            sites_path: traffic_sites_path()?,
            state_path: traffic_state_path()?,
        };
        ensure_default_files(&storage)?;

        let sites = load_sites_file(&storage.sites_path)?;
        let learned = load_state_file(&storage.state_path)?;
        let defaults = LearnedTrafficState {
            cooldown_secs: config.initial_cooldown_secs,
            release_interval_secs: config.initial_release_interval_secs,
            stable_successes: 0,
        };

        let mut hosts = HashMap::new();
        for host in sites.hosts {
            let normalized = normalize_host(&host);
            let state = learned
                .hosts
                .get(&normalized)
                .cloned()
                .unwrap_or_else(|| defaults.clone());
            hosts.insert(
                normalized.clone(),
                Arc::new(HostTrafficEntry {
                    host: normalized,
                    enabled: true,
                    notify: Notify::new(),
                    state: Mutex::new(HostTrafficRuntime {
                        throttled: false,
                        observed_active_requests: 0,
                        managed_active_requests: 0,
                        queued_requests: 0,
                        retrying_requests: 0,
                        cooldown_until: None,
                        next_release_at: None,
                        learned: clamp_learned_state(state, config),
                        last_status_code: None,
                        last_429_at: None,
                    }),
                }),
            );
        }

        let (persist_signal, persist_rx) = watch::channel(0u64);

        let shared = Arc::new(Self {
            runtime,
            storage,
            hosts: Mutex::new(hosts),
            persisted_state: Mutex::new(learned),
            persist_signal,
        });

        tokio::spawn(shared.clone().persist_loop(persist_rx));

        Ok(shared)
    }

    pub fn action_for_request(
        &self,
        host: &str,
        method: &str,
        request_type: &str,
        config: &TrafficConfig,
    ) -> TrafficAction {
        if !config.enabled {
            return TrafficAction::Bypass;
        }
        if !method.eq_ignore_ascii_case("GET") || request_type != "document" {
            return TrafficAction::Bypass;
        }
        if self.host_is_throttled(host) {
            TrafficAction::Managed
        } else {
            TrafficAction::Bypass
        }
    }

    pub fn is_controlled_host(&self, host: &str) -> bool {
        self.managed_host_entry(host).is_some()
    }

    pub async fn acquire(&self, host: &str, config: &TrafficConfig) -> Result<TrafficPermit> {
        let Some(entry) = self.managed_host_entry(host) else {
            return Ok(TrafficPermit {
                runtime: self.runtime.clone(),
                entry: Arc::new(HostTrafficEntry {
                    host: normalize_host(host),
                    enabled: false,
                    notify: Notify::new(),
                    state: Mutex::new(HostTrafficRuntime {
                        throttled: false,
                        observed_active_requests: 0,
                        managed_active_requests: 0,
                        queued_requests: 0,
                        retrying_requests: 0,
                        cooldown_until: None,
                        next_release_at: None,
                        learned: LearnedTrafficState {
                            cooldown_secs: config.initial_cooldown_secs,
                            release_interval_secs: config.initial_release_interval_secs,
                            stable_successes: 0,
                        },
                        last_status_code: None,
                        last_429_at: None,
                    }),
                }),
                granted: false,
                observed: false,
            });
        };
        let mut queued = false;

        loop {
            let mut changed = false;
            let decision = {
                let mut state = entry
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("traffic host state lock poisoned"))?;
                let now = Instant::now();

                if state.cooldown_until.is_some_and(|deadline| deadline <= now) {
                    state.cooldown_until = None;
                    changed = true;
                }
                if !state.throttled {
                    if queued {
                        state.queued_requests = state.queued_requests.saturating_sub(1);
                    }
                    changed = true;
                    AcquireDecision::Bypass
                } else {
                    let next_gate = match (state.cooldown_until, state.next_release_at) {
                        (Some(cooldown_until), Some(next_release_at)) => {
                            Some(cooldown_until.max(next_release_at))
                        }
                        (Some(cooldown_until), None) => Some(cooldown_until),
                        (None, Some(next_release_at)) => Some(next_release_at),
                        (None, None) => None,
                    };

                    if state.managed_active_requests == 0
                        && next_gate.is_none_or(|deadline| deadline <= now)
                    {
                        state.managed_active_requests = 1;
                        if queued {
                            state.queued_requests = state.queued_requests.saturating_sub(1);
                        }
                        state.next_release_at = Some(
                            now + Duration::from_secs(state.learned.release_interval_secs.max(1)),
                        );
                        changed = true;
                        AcquireDecision::Granted
                    } else {
                        if !queued {
                            if state.queued_requests >= config.max_queue_per_host {
                                anyhow::bail!(
                                    "traffic queue is full for host `{host}` (limit: {})",
                                    config.max_queue_per_host
                                );
                            }
                            state.queued_requests += 1;
                            queued = true;
                            changed = true;
                        }
                        AcquireDecision::Wait(next_gate)
                    }
                }
            };

            if changed {
                self.runtime.notify_traffic_changed();
            }

            match decision {
                AcquireDecision::Bypass => {
                    return Ok(TrafficPermit {
                        runtime: self.runtime.clone(),
                        entry,
                        granted: false,
                        observed: false,
                    });
                }
                AcquireDecision::Granted => {
                    return Ok(TrafficPermit {
                        runtime: self.runtime.clone(),
                        entry,
                        granted: true,
                        observed: false,
                    });
                }
                AcquireDecision::Wait(wait_until) => {
                    let notified = entry.notify.notified();
                    if let Some(deadline) = wait_until {
                        tokio::select! {
                            _ = time::sleep_until(deadline) => {}
                            _ = notified => {}
                        }
                    } else {
                        notified.await;
                    }
                }
            }
        }
    }

    pub fn begin_observed_request(&self, host: &str) -> Option<TrafficPermit> {
        let entry = self.managed_host_entry(host)?;
        if let Ok(mut state) = entry.state.lock() {
            state.observed_active_requests = state.observed_active_requests.saturating_add(1);
        }
        self.runtime.notify_traffic_changed();
        Some(TrafficPermit {
            runtime: self.runtime.clone(),
            entry,
            granted: false,
            observed: true,
        })
    }

    pub fn on_success(&self, host: &str, config: &TrafficConfig) {
        let Some(entry) = self.managed_host_entry(host) else {
            return;
        };

        let mut persist = None;
        let mut changed = false;
        if let Ok(mut state) = entry.state.lock() {
            if !state.throttled {
                return;
            }
            state.last_status_code = Some(200);
            state.learned.stable_successes = state.learned.stable_successes.saturating_add(1);

            if state.learned.stable_successes >= config.auto_relax_after_successes {
                let next_cooldown = state
                    .learned
                    .cooldown_secs
                    .saturating_sub(config.auto_adjust_step_secs)
                    .max(config.min_cooldown_secs);
                let next_interval = state
                    .learned
                    .release_interval_secs
                    .saturating_sub(config.auto_adjust_step_secs)
                    .max(config.min_release_interval_secs);

                if next_cooldown != state.learned.cooldown_secs
                    || next_interval != state.learned.release_interval_secs
                {
                    state.learned.cooldown_secs = next_cooldown;
                    state.learned.release_interval_secs = next_interval;
                    changed = true;
                }
                state.learned.stable_successes = 0;
            }

            if changed {
                persist = Some(state.learned.clone());
            }
        }

        if let Some(learned) = persist {
            let _ = self.persist_host_state(host, learned);
            self.runtime.notify_traffic_changed();
        } else {
            self.runtime.notify_traffic_changed();
        }
    }

    pub fn on_429(
        &self,
        host: &str,
        retry_after_secs: Option<u64>,
        config: &TrafficConfig,
    ) -> Duration {
        let Some(entry) = self.managed_host_entry(host) else {
            return Duration::from_secs(config.initial_cooldown_secs.max(1));
        };

        let mut persist = None;
        let mut cooldown = Duration::from_secs(config.initial_cooldown_secs.max(1));
        if let Ok(mut state) = entry.state.lock() {
            state.throttled = true;
            state.last_status_code = Some(429);
            state.last_429_at = Some(SystemTime::now());
            state.learned.stable_successes = 0;

            state.learned.cooldown_secs = (state.learned.cooldown_secs
                + config.auto_adjust_step_secs)
                .min(config.max_cooldown_secs);
            state.learned.release_interval_secs = (state.learned.release_interval_secs
                + config.auto_adjust_step_secs)
                .min(config.max_release_interval_secs);

            let retry_after = retry_after_secs.unwrap_or(0);
            let cooldown_secs = state.learned.cooldown_secs.max(retry_after).max(1);
            state.cooldown_until = Some(Instant::now() + Duration::from_secs(cooldown_secs));
            cooldown = Duration::from_secs(cooldown_secs);
            persist = Some(state.learned.clone());
        }

        entry.notify.notify_waiters();
        if let Some(learned) = persist {
            let _ = self.persist_host_state(host, learned);
        }
        self.runtime.notify_traffic_changed();
        cooldown
    }

    pub fn begin_retry_wait(&self, host: &str) {
        let Some(entry) = self.managed_host_entry(host) else {
            return;
        };
        if let Ok(mut state) = entry.state.lock() {
            state.retrying_requests = state.retrying_requests.saturating_add(1);
        }
        self.runtime.notify_traffic_changed();
    }

    pub fn end_retry_wait(&self, host: &str) {
        let Some(entry) = self.managed_host_entry(host) else {
            return;
        };
        if let Ok(mut state) = entry.state.lock() {
            state.retrying_requests = state.retrying_requests.saturating_sub(1);
            refresh_throttle_state(&mut state);
        }
        entry.notify.notify_waiters();
        self.runtime.notify_traffic_changed();
    }

    pub fn on_fatal_error(&self, host: &str) {
        let Some(entry) = self.managed_host_entry(host) else {
            return;
        };
        if let Ok(mut state) = entry.state.lock() {
            state.throttled = false;
            state.queued_requests = 0;
            state.retrying_requests = 0;
            state.cooldown_until = None;
            state.next_release_at = None;
            state.learned.stable_successes = 0;
        }
        entry.notify.notify_waiters();
        self.runtime.notify_traffic_changed();
    }

    pub fn decide_429_response(
        &self,
        host: &str,
        attempt: usize,
        retry_after_secs: Option<u64>,
        config: &TrafficConfig,
    ) -> TrafficResponseDecision {
        let delay = self.on_429(host, retry_after_secs, config);
        if attempt < config.internal_retry_limit {
            TrafficResponseDecision::RetryAfterDelay(delay)
        } else {
            TrafficResponseDecision::ReloadPage(delay)
        }
    }

    pub fn snapshot(&self) -> TrafficRuntimeSnapshot {
        let entries = self
            .hosts
            .lock()
            .map(|hosts| hosts.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let now = Instant::now();
        let mut hosts = Vec::with_capacity(entries.len());
        let mut active_requests = 0usize;
        let mut queued_requests = 0usize;
        let mut cooling_hosts = 0usize;

        for entry in entries {
            let Ok(mut state) = entry.state.lock() else {
                continue;
            };
            refresh_throttle_state(&mut state);
            let host_active_requests =
                state.observed_active_requests + state.managed_active_requests;
            let host_queued_requests = state.queued_requests + state.retrying_requests;
            active_requests += host_active_requests;
            queued_requests += host_queued_requests;
            let cooldown_remaining_secs = state.cooldown_until.and_then(|deadline| {
                if deadline <= now {
                    None
                } else {
                    Some(deadline.duration_since(now).as_secs().max(1))
                }
            });
            if cooldown_remaining_secs.is_some() {
                cooling_hosts += 1;
            }
            hosts.push(HostTrafficHostSnapshot {
                host: entry.host.clone(),
                enabled: entry.enabled,
                throttled: state.throttled,
                active_requests: host_active_requests,
                queued_requests: host_queued_requests,
                retrying_requests: state.retrying_requests,
                cooldown_remaining_secs,
                cooldown_secs: state.learned.cooldown_secs,
                release_interval_secs: state.learned.release_interval_secs,
                last_status_code: state.last_status_code,
                last_429_at: state.last_429_at,
                stable_successes: state.learned.stable_successes,
            });
        }

        hosts.sort_by(|left, right| left.host.cmp(&right.host));
        TrafficRuntimeSnapshot {
            controlled_hosts: hosts.len(),
            active_requests,
            queued_requests,
            cooling_hosts,
            hosts,
        }
    }

    fn managed_host_entry(&self, host: &str) -> Option<Arc<HostTrafficEntry>> {
        let normalized = normalize_host(host);
        self.hosts
            .lock()
            .ok()
            .and_then(|hosts| hosts.get(&normalized).cloned())
    }

    fn host_is_throttled(&self, host: &str) -> bool {
        let Some(entry) = self.managed_host_entry(host) else {
            return false;
        };
        let Ok(mut state) = entry.state.lock() else {
            return false;
        };
        refresh_throttle_state(&mut state);
        state.throttled
    }

    fn persist_host_state(&self, host: &str, learned: LearnedTrafficState) -> Result<()> {
        let normalized = normalize_host(host);
        let mut state = self
            .persisted_state
            .lock()
            .map_err(|_| anyhow::anyhow!("traffic persisted state lock poisoned"))?;
        state.hosts.insert(normalized, learned);
        let _ = self.persist_signal.send_modify(|generation| {
            *generation = generation.saturating_add(1);
        });
        Ok(())
    }

    async fn persist_loop(self: Arc<Self>, mut persist_rx: watch::Receiver<u64>) {
        const PERSIST_DEBOUNCE_SECS: u64 = 60;

        loop {
            if persist_rx.changed().await.is_err() {
                return;
            }

            loop {
                tokio::select! {
                    changed = persist_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    _ = time::sleep(Duration::from_secs(PERSIST_DEBOUNCE_SECS)) => {
                        break;
                    }
                }
            }

            if let Err(error) = self.flush_persisted_state() {
                warn!(error = %error, "failed to flush debounced traffic state");
            }
        }
    }

    fn flush_persisted_state(&self) -> Result<()> {
        let state = self
            .persisted_state
            .lock()
            .map_err(|_| anyhow::anyhow!("traffic persisted state lock poisoned"))?
            .clone();
        let yaml = serde_yaml::to_string(&state)?;
        fs::write(&self.storage.state_path, yaml).with_context(|| {
            format!(
                "failed to write traffic state file: {}",
                self.storage.state_path.display()
            )
        })?;
        Ok(())
    }
}

impl TrafficPermit {
    pub fn release(&mut self) {
        if !self.granted {
            if !self.observed {
                return;
            }
        }
        if let Ok(mut state) = self.entry.state.lock() {
            if self.granted {
                state.managed_active_requests = state.managed_active_requests.saturating_sub(1);
            }
            if self.observed {
                state.observed_active_requests = state.observed_active_requests.saturating_sub(1);
            }
            refresh_throttle_state(&mut state);
        }
        self.granted = false;
        self.observed = false;
        self.entry.notify.notify_waiters();
        self.runtime.notify_traffic_changed();
    }
}

impl Drop for TrafficPermit {
    fn drop(&mut self) {
        self.release();
    }
}

pub fn parse_retry_after_secs(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
}

pub fn reload_page_response(delay: Duration, target_url: &str) -> Vec<u8> {
    let delay_ms = delay.as_millis().max(500);
    let title = html_escape(&lang::text("traffic.wait.title"));
    let message = html_escape(&lang::format(
        "traffic.wait.message",
        &[("url", target_url.to_string())],
    ));
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"{refresh}\"><title>{title}</title></head><body><script>setTimeout(function(){{location.reload();}}, {delay_ms});</script><p>{message}</p></body></html>",
        refresh = (delay_ms / 1000).max(1),
    );
    format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn ensure_default_files(storage: &TrafficStorage) -> Result<()> {
    if let Some(parent) = storage.sites_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if !storage.sites_path.exists() {
        let sites = TrafficSitesFile {
            hosts: vec!["sukebei.nyaa.si".to_string()],
        };
        fs::write(&storage.sites_path, serde_yaml::to_string(&sites)?)?;
    }

    if !storage.state_path.exists() {
        fs::write(
            &storage.state_path,
            serde_yaml::to_string(&TrafficStateFile::default())?,
        )?;
    }

    Ok(())
}

fn load_sites_file(path: &Path) -> Result<TrafficSitesFile> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read traffic sites file: {}", path.display()))?;
    let mut sites = serde_yaml::from_str::<TrafficSitesFile>(&content)
        .with_context(|| format!("failed to parse traffic sites file: {}", path.display()))?;
    let mut dedup = HashSet::new();
    sites
        .hosts
        .retain(|host| dedup.insert(normalize_host(host)));
    Ok(sites)
}

fn load_state_file(path: &Path) -> Result<TrafficStateFile> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read traffic state file: {}", path.display()))?;
    Ok(serde_yaml::from_str::<TrafficStateFile>(&content)
        .with_context(|| format!("failed to parse traffic state file: {}", path.display()))?)
}

fn traffic_sites_path() -> Result<PathBuf> {
    Ok(traffic_base_dir()?.join("sites.yaml"))
}

fn traffic_state_path() -> Result<PathBuf> {
    Ok(traffic_base_dir()?.join("state.yaml"))
}

fn traffic_base_dir() -> Result<PathBuf> {
    let base = match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => {
            let exe =
                std::env::current_exe().context("failed to resolve current executable path")?;
            exe.parent()
                .context("current executable path does not have a parent directory")?
                .to_path_buf()
        }
    };
    Ok(base.join("data").join("traffic"))
}

fn clamp_learned_state(
    mut state: LearnedTrafficState,
    config: &TrafficConfig,
) -> LearnedTrafficState {
    state.cooldown_secs = state
        .cooldown_secs
        .max(config.min_cooldown_secs)
        .min(config.max_cooldown_secs);
    state.release_interval_secs = state
        .release_interval_secs
        .max(config.min_release_interval_secs)
        .min(config.max_release_interval_secs);
    state
}

fn refresh_throttle_state(state: &mut HostTrafficRuntime) {
    let now = Instant::now();
    if state.cooldown_until.is_some_and(|deadline| deadline <= now) {
        state.cooldown_until = None;
    }
    if state.throttled
        && state.observed_active_requests == 0
        && state.managed_active_requests == 0
        && state.queued_requests == 0
        && state.retrying_requests == 0
        && state.cooldown_until.is_none()
    {
        state.throttled = false;
        state.next_release_at = None;
        state.learned.stable_successes = 0;
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase()
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
