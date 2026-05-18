use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::{
    net::UdpSocket,
    runtime::Handle,
    sync::{mpsc, oneshot, watch},
    time::{self, MissedTickBehavior},
};

use crate::{
    config::{DnsConfig, DnsProfileConfig, DnsProfileMode, DnsRouteConfig},
    dns_auto_select::DnsAutoSelectState,
    dns_observation::{
        DnsObservationErrorKind, DnsObservationSnapshot, DnsObservationStore,
        DnsProfileHealthSnapshot, DnsProfileObservationResult,
    },
    dns_state_store,
    dns_warm_cache::{self, DnsWarmCacheAccess, DnsWarmCacheCandidate},
    origin_connect_health_store::{
        self, OriginConnectFamilySnapshot, OriginConnectHealthSnapshot,
        OriginConnectHealthSnapshotEntry,
    },
    proxy::upstream,
};

pub type SharedDnsResolver = Arc<RelayGateDnsResolver>;

pub fn shared_from_config(config: DnsConfig) -> SharedDnsResolver {
    let resolver = Arc::new(RelayGateDnsResolver::new(config));
    RelayGateDnsResolver::start_warm_cache_worker(&resolver);
    RelayGateDnsResolver::start_cache_persistence_worker(&resolver);
    resolver
}

pub fn replace_shared_config(resolver: &SharedDnsResolver, config: DnsConfig) -> Result<()> {
    resolver.replace_config(config)
}

const NEGATIVE_DNS_FAILURE_THRESHOLD: usize = 3;
const NEGATIVE_DNS_FAILURE_WINDOW_SECS: u64 = 5;
const NEGATIVE_DNS_TTL_NXDOMAIN_SECS: u64 = 8;
const NEGATIVE_DNS_TTL_NO_RECORDS_SECS: u64 = 3;
const NEGATIVE_DNS_TTL_TEMPORARY_SECS: u64 = 2;
const NEGATIVE_DNS_TTL_EPHEMERAL_HOST_SECS: u64 = 1;
const POSITIVE_DNS_TTL_EPHEMERAL_HOST_MAX_SECS: u64 = 30;
const SYSTEM_DNS_PROFILE_ID: &str = "system";
const SHARED_DNS_CACHE_SCOPE_ID: &str = "__relaygate_shared";
const STRICT_DNS_CACHE_SCOPE_PREFIX: &str = "strict:";
const DNS_RACING_MAX_PROFILES: usize = 3;
const DNS_MAX_BACKGROUND_REFRESHES: usize = 8;
const DNS_CACHE_SNAPSHOT_INTERVAL_SECS: u64 = 15 * 60;
const ORIGIN_CONNECT_HEALTH_MAX_HOSTS: usize = 4096;
const ORIGIN_CONNECT_HEALTH_IDLE_TTL_SECS: u64 = 24 * 60 * 60;
const ORIGIN_CONNECT_HEALTH_PERSISTED_LOAD_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const ORIGIN_CONNECT_HEALTH_PERSISTED_RESTORE_AGE_SECS: u64 = 12 * 60 * 60;
const ORIGIN_CONNECT_HEALTH_PERSISTED_SAMPLE_HALF_LIFE_SECS: u64 = 24 * 60 * 60;
const ORIGIN_CONNECT_HEALTH_PERSISTED_DNS_CONTEXT_TTL_SECS: u64 = 24 * 60 * 60;
const ORIGIN_CONNECT_HEALTH_PRUNE_INTERVAL_SECS: u64 = 60;
const ORIGIN_CONNECT_HEALTH_DNS_CONTEXT_REFRESH_SECS: u64 = 15 * 60;
const ORIGIN_CONNECT_HEALTH_MIN_SAMPLES_PER_FAMILY: u32 = 3;
const ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN: u32 = 8;
const ORIGIN_CONNECT_HEALTH_MAX_SAMPLES_PER_FAMILY: u32 = 128;
const ORIGIN_CONNECT_HEALTH_FAILURE_RATE_GAP: f64 = 0.35;
const ORIGIN_CONNECT_HEALTH_FAILURE_COUNT_GAP: u32 = 2;
const ORIGIN_CONNECT_HEALTH_LATENCY_MIN_SUCCESSES_PER_FAMILY: u32 = 3;
const ORIGIN_CONNECT_HEALTH_LATENCY_GAP_MS: f64 = 50.0;
const ORIGIN_CONNECT_HEALTH_LATENCY_RATIO: f64 = 0.75;
const CONNECTION_INFO_SNAPSHOT_MAX_ITEMS: usize = 50;

#[derive(Clone)]
pub struct ReqwestDnsResolver {
    inner: SharedDnsResolver,
}

impl ReqwestDnsResolver {
    pub fn new(inner: SharedDnsResolver) -> Self {
        Self { inner }
    }
}

pub struct RelayGateDnsResolver {
    state: Arc<RwLock<DnsState>>,
    cache: Arc<RwLock<HashMap<DnsCacheKey, DnsCacheEntry>>>,
    warm_cache: Arc<RwLock<HashMap<DnsCacheKey, DnsWarmCacheAccess>>>,
    observations: Arc<RwLock<DnsObservationStore>>,
    learned_observation: Arc<RwLock<DnsObservationSnapshot>>,
    auto_select: Arc<RwLock<DnsAutoSelectState>>,
    refreshing: Arc<RwLock<HashSet<DnsCacheKey>>>,
    inflight: Arc<RwLock<HashMap<DnsInflightKey, watch::Sender<Option<DnsInflightResult>>>>>,
    negative_failures: Arc<RwLock<HashMap<DnsCacheKey, NegativeDnsFailureState>>>,
    origin_connect_health: Arc<RwLock<HashMap<String, OriginConnectHealthEntry>>>,
    origin_connect_health_last_prune: Arc<Mutex<Instant>>,
    origin_connect_health_dirty: Arc<AtomicBool>,
    cache_dirty: Arc<AtomicBool>,
    learned_dirty: Arc<AtomicBool>,
}

#[derive(Clone)]
struct DnsState {
    config: DnsConfig,
    profiles: HashMap<String, DnsProfileConfig>,
    routes: DnsRouteMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DnsCacheKey {
    /// Cache scope, not the DNS server owner. Normal DNS lookups use a shared
    /// RelayGate-wide scope; strict routes use an isolated scope.
    pub(crate) profile_id: String,
    pub(crate) host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsResolveIngress {
    /// RelayGate-internal lookups used by the proxy/upstream path.
    /// This preserves the existing behavior and may use the System DNS profile.
    ProxyInternal,
    /// Lookups accepted from RelayGate's future DNS Server listener.
    /// This path must never query the System DNS profile, because the OS may
    /// point System DNS back to RelayGate and create a resolver loop.
    DnsServer,
}

impl DnsResolveIngress {
    fn allows_system_profile(self) -> bool {
        matches!(self, Self::ProxyInternal)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ProxyInternal => "proxy_internal",
            Self::DnsServer => "dns_server",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsInflightKey {
    cache: DnsCacheKey,
    allow_system_profile: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DnsCacheEntry {
    pub(crate) addrs: Vec<IpAddr>,
    pub(crate) expires_at: Instant,
    pub(crate) stale_until: Instant,
    pub(crate) negative: bool,
    pub(crate) source_profile_id: String,
}

#[derive(Debug, Clone)]
enum DnsCacheLookup {
    Hit(Vec<IpAddr>),
    Negative,
    Miss,
}

#[derive(Debug, Clone)]
struct DnsCacheLookupOutcome {
    lookup: DnsCacheLookup,
    refresh: Option<DnsRefreshReason>,
    stale_remaining_secs: u64,
}

#[derive(Debug, Clone)]
struct NegativeDnsFailureState {
    kind: DnsNegativeKind,
    count: usize,
    first_seen: Instant,
}

#[derive(Debug, Clone)]
struct OriginConnectHealthEntry {
    v4: OriginConnectFamilyHealth,
    v6: OriginConnectFamilyHealth,
    last_seen: Instant,
    last_ip: Option<IpAddr>,
    last_result: OriginConnectResult,
    last_connect_ms: Option<u64>,
    last_dns_a_count: usize,
    last_dns_aaaa_count: usize,
    last_dns_seen: Option<Instant>,
    last_family_preference: AddressFamilyPreference,
}

#[derive(Debug, Clone, Default)]
struct OriginConnectFamilyHealth {
    success_count: u32,
    fail_count: u32,
    avg_connect_ms: Option<f64>,
    last_success_at: Option<Instant>,
    last_failure_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OriginConnectResult {
    None,
    Success,
    Failure,
}

impl OriginConnectResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamilyPreference {
    Neutral,
    PreferIpv4,
    PreferIpv6,
}

impl AddressFamilyPreference {
    fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::PreferIpv4 => "prefer_ipv4",
            Self::PreferIpv6 => "prefer_ipv6",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectionInfoSnapshot {
    pub(crate) max_items: usize,
    pub(crate) items: Vec<ConnectionInfoHostSnapshot>,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectionInfoHostSnapshot {
    pub(crate) host: String,
    pub(crate) route: String,
    pub(crate) dns_profile: Option<String>,
    pub(crate) dns_a_count: usize,
    pub(crate) dns_aaaa_count: usize,
    pub(crate) last_ip: Option<IpAddr>,
    pub(crate) last_family: Option<String>,
    pub(crate) last_result: String,
    pub(crate) last_connect_ms: Option<u64>,
    pub(crate) last_seen_age_secs: u64,
    pub(crate) family_preference: String,
}

impl OriginConnectHealthEntry {
    fn new(now: Instant) -> Self {
        Self {
            v4: OriginConnectFamilyHealth::default(),
            v6: OriginConnectFamilyHealth::default(),
            last_seen: now,
            last_ip: None,
            last_result: OriginConnectResult::None,
            last_connect_ms: None,
            last_dns_a_count: 0,
            last_dns_aaaa_count: 0,
            last_dns_seen: None,
            last_family_preference: AddressFamilyPreference::Neutral,
        }
    }

    fn family_mut(&mut self, ip: IpAddr) -> &mut OriginConnectFamilyHealth {
        if ip.is_ipv4() {
            &mut self.v4
        } else {
            &mut self.v6
        }
    }

    fn trace_preference_change_if_needed(&mut self, host: &str) {
        let next = address_family_preference_from_health(self);
        if next == self.last_family_preference {
            return;
        }

        let previous = self.last_family_preference;
        self.last_family_preference = next;
        tracing::debug!(
            host = %host,
            previous = previous.as_str(),
            current = next.as_str(),
            dns_a_count = self.last_dns_a_count,
            dns_aaaa_count = self.last_dns_aaaa_count,
            v4_success = self.v4.success_count,
            v4_fail = self.v4.fail_count,
            v6_success = self.v6.success_count,
            v6_fail = self.v6.fail_count,
            "origin connect address family preference changed"
        );
    }

    fn refresh_dns_context_if_needed(&mut self, addrs: &[IpAddr], now: Instant) -> bool {
        let next_a_count = addrs.iter().filter(|addr| addr.is_ipv4()).count();
        let next_aaaa_count = addrs.iter().filter(|addr| addr.is_ipv6()).count();
        let counts_changed =
            self.last_dns_a_count != next_a_count || self.last_dns_aaaa_count != next_aaaa_count;
        let refresh_due = self
            .last_dns_seen
            .map(|seen| {
                now.duration_since(seen)
                    >= Duration::from_secs(ORIGIN_CONNECT_HEALTH_DNS_CONTEXT_REFRESH_SECS)
            })
            .unwrap_or(true);

        if !counts_changed && !refresh_due {
            return false;
        }

        self.last_dns_a_count = next_a_count;
        self.last_dns_aaaa_count = next_aaaa_count;
        self.last_dns_seen = Some(now);
        true
    }
}

impl OriginConnectFamilyHealth {
    fn record_success(&mut self, connect_ms: Option<u64>, now: Instant) {
        self.success_count = self.success_count.saturating_add(1);
        if let Some(connect_ms) = connect_ms {
            let connect_ms = connect_ms as f64;
            self.avg_connect_ms = Some(match self.avg_connect_ms {
                Some(avg) => {
                    let weight = self.success_count.min(64) as f64;
                    avg + ((connect_ms - avg) / weight)
                }
                None => connect_ms,
            });
        }
        self.last_success_at = Some(now);
        self.compact_samples_if_needed();
    }

    fn record_failure(&mut self, now: Instant) {
        self.fail_count = self.fail_count.saturating_add(1);
        self.last_failure_at = Some(now);
        self.compact_samples_if_needed();
    }

    fn compact_samples_if_needed(&mut self) {
        if self.sample_count() <= ORIGIN_CONNECT_HEALTH_MAX_SAMPLES_PER_FAMILY {
            return;
        }

        self.success_count = (self.success_count / 2).max(u32::from(self.success_count > 0));
        self.fail_count = (self.fail_count / 2).max(u32::from(self.fail_count > 0));
    }

    fn sample_count(&self) -> u32 {
        self.success_count.saturating_add(self.fail_count)
    }

    fn failure_rate(&self) -> f64 {
        let samples = self.sample_count();
        if samples == 0 {
            return 0.0;
        }
        self.fail_count as f64 / samples as f64
    }
}

fn record_origin_connect_entry(
    entry: &mut OriginConnectHealthEntry,
    ip: IpAddr,
    result: OriginConnectResult,
    connect_ms: Option<u64>,
    now: Instant,
) {
    entry.last_seen = now;
    entry.last_ip = Some(ip);
    entry.last_result = result;
    entry.last_connect_ms = connect_ms;
    let family = entry.family_mut(ip);
    match result {
        OriginConnectResult::Success => family.record_success(connect_ms, now),
        OriginConnectResult::Failure => family.record_failure(now),
        OriginConnectResult::None => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsNegativeKind {
    Nxdomain,
    NoRecords,
    Timeout,
    TemporaryFailure,
}

impl DnsNegativeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nxdomain => "nxdomain",
            Self::NoRecords => "no_records",
            Self::Timeout => "timeout",
            Self::TemporaryFailure => "temporary_failure",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DnsRefreshReason {
    BeforeExpire,
    Stale,
    WarmCache,
}

impl DnsRefreshReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::BeforeExpire => "before_expire",
            Self::Stale => "stale",
            Self::WarmCache => "warm_cache",
        }
    }
}

#[derive(Debug)]
struct DnsLookupResult {
    addrs: Vec<IpAddr>,
    ttl_secs: Option<u64>,
    first_usable_latency_ms: Option<u64>,
    late_merge: Option<DnsLateMerge>,
}

struct DnsLateMerge {
    receiver: oneshot::Receiver<Option<DnsLateMergeResult>>,
}

impl std::fmt::Debug for DnsLateMerge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsLateMerge").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct DnsLateMergeResult {
    addrs: Vec<IpAddr>,
    ttl_secs: Option<u64>,
}

#[derive(Debug)]
struct DnsRaceProfileResult {
    observation: DnsProfileObservationResult,
    positive: Option<DnsRacePositiveResult>,
    negative_kind: Option<DnsNegativeKind>,
}

#[derive(Debug)]
struct DnsRacePositiveResult {
    addrs: Vec<IpAddr>,
    ttl_secs: u64,
    stale_fallback_secs: u64,
    late_merge: Option<DnsLateMerge>,
}

type DnsInflightResult = std::result::Result<Vec<IpAddr>, String>;

enum DnsInflightLookup {
    Leader {
        guard: DnsInflightLeaderGuard,
    },
    Waiter {
        receiver: watch::Receiver<Option<DnsInflightResult>>,
    },
}

struct DnsInflightLeaderGuard {
    key: DnsInflightKey,
    sender: watch::Sender<Option<DnsInflightResult>>,
    inflight: Arc<RwLock<HashMap<DnsInflightKey, watch::Sender<Option<DnsInflightResult>>>>>,
    finished: bool,
}

impl DnsInflightLeaderGuard {
    fn new(
        key: DnsInflightKey,
        sender: watch::Sender<Option<DnsInflightResult>>,
        inflight: Arc<RwLock<HashMap<DnsInflightKey, watch::Sender<Option<DnsInflightResult>>>>>,
    ) -> Self {
        Self {
            key,
            sender,
            inflight,
            finished: false,
        }
    }

    fn finish(mut self, result: DnsInflightResult) {
        let _ = self.sender.send(Some(result));
        self.cleanup();
        self.finished = true;
    }

    fn cleanup(&mut self) {
        match self.inflight.write() {
            Ok(mut inflight) => {
                inflight.remove(&self.key);
            }
            Err(_) => {
                tracing::warn!(
                    cache_scope = %self.key.cache.profile_id,
                    host = %self.key.cache.host,
                    "DNS in-flight entry cleanup skipped because lock poisoned"
                );
            }
        }
    }
}

impl Drop for DnsInflightLeaderGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.sender.send(Some(Err(
            "DNS in-flight lookup was cancelled before producing a result".to_string(),
        )));
        self.cleanup();
    }
}

impl DnsLookupResult {
    fn without_ttl(addrs: Vec<IpAddr>) -> Self {
        Self {
            addrs,
            ttl_secs: None,
            first_usable_latency_ms: None,
            late_merge: None,
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedDnsRoute {
    profile_id: String,
    strict: bool,
}

#[derive(Debug, Clone, Default)]
struct DnsRouteMatcher {
    routes: Vec<DnsRouteEntry>,
    compiled_route_indexes: Vec<usize>,
    globset: Option<GlobSet>,
}

#[derive(Debug, Clone)]
struct DnsRouteEntry {
    profile_id: String,
    strict: bool,
    enabled: bool,
}

impl RelayGateDnsResolver {
    pub fn new(config: DnsConfig) -> Self {
        let state = DnsState::from_config(config);
        let (cache, learned_observation) =
            dns_state_store::load_snapshots(state.config.max_cache_entries);
        let origin_connect_health = origin_connect_health_from_snapshot(
            origin_connect_health_store::load_snapshot(ORIGIN_CONNECT_HEALTH_MAX_HOSTS),
            Instant::now(),
        );
        Self {
            state: Arc::new(RwLock::new(state)),
            cache: Arc::new(RwLock::new(cache)),
            warm_cache: Arc::new(RwLock::new(HashMap::new())),
            observations: Arc::new(RwLock::new(DnsObservationStore::default())),
            learned_observation: Arc::new(RwLock::new(learned_observation)),
            auto_select: Arc::new(RwLock::new(DnsAutoSelectState::default())),
            refreshing: Arc::new(RwLock::new(HashSet::new())),
            inflight: Arc::new(RwLock::new(HashMap::new())),
            negative_failures: Arc::new(RwLock::new(HashMap::new())),
            origin_connect_health: Arc::new(RwLock::new(origin_connect_health)),
            origin_connect_health_last_prune: Arc::new(Mutex::new(Instant::now())),
            origin_connect_health_dirty: Arc::new(AtomicBool::new(false)),
            cache_dirty: Arc::new(AtomicBool::new(false)),
            learned_dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    fn start_warm_cache_worker(resolver: &SharedDnsResolver) {
        if Handle::try_current().is_err() {
            return;
        }

        let resolver = Arc::downgrade(resolver);
        tokio::spawn(async move {
            run_warm_cache_worker(resolver).await;
        });
    }

    fn start_cache_persistence_worker(resolver: &SharedDnsResolver) {
        if Handle::try_current().is_err() {
            return;
        }

        let resolver = Arc::downgrade(resolver);
        tokio::spawn(async move {
            run_cache_persistence_worker(resolver).await;
        });
    }

    pub fn replace_config(&self, config: DnsConfig) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("DNS resolver state lock poisoned"))?;
        *state = DnsState::from_config(config);
        self.cache
            .write()
            .map_err(|_| anyhow::anyhow!("DNS cache lock poisoned"))?
            .clear();
        self.mark_cache_dirty();
        self.refreshing
            .write()
            .map_err(|_| anyhow::anyhow!("DNS refresh lock poisoned"))?
            .clear();
        self.inflight
            .write()
            .map_err(|_| anyhow::anyhow!("DNS in-flight lock poisoned"))?
            .clear();
        self.warm_cache
            .write()
            .map_err(|_| anyhow::anyhow!("DNS warm cache metadata lock poisoned"))?
            .clear();
        *self
            .observations
            .write()
            .map_err(|_| anyhow::anyhow!("DNS observation lock poisoned"))? =
            DnsObservationStore::default();
        *self
            .auto_select
            .write()
            .map_err(|_| anyhow::anyhow!("DNS auto-select lock poisoned"))? =
            DnsAutoSelectState::default();
        self.negative_failures
            .write()
            .map_err(|_| anyhow::anyhow!("DNS negative failure lock poisoned"))?
            .clear();
        Ok(())
    }

    pub fn config_snapshot(&self) -> DnsConfig {
        self.state
            .read()
            .map(|state| state.config.clone())
            .unwrap_or_default()
    }

    pub fn cache_len(&self) -> usize {
        self.cache.read().map(|cache| cache.len()).unwrap_or(0)
    }

    fn should_prune_origin_connect_health(&self, now: Instant) -> bool {
        let Ok(mut last_prune) = self.origin_connect_health_last_prune.lock() else {
            return false;
        };

        if now.duration_since(*last_prune)
            < Duration::from_secs(ORIGIN_CONNECT_HEALTH_PRUNE_INTERVAL_SECS)
        {
            return false;
        }

        *last_prune = now;
        true
    }

    pub(crate) fn connection_info_snapshot(&self) -> ConnectionInfoSnapshot {
        let now = Instant::now();
        let dns_by_host = self
            .cache
            .read()
            .ok()
            .map(|cache| latest_dns_profiles_by_host(&cache, now))
            .unwrap_or_default();
        let mut items = self
            .origin_connect_health
            .read()
            .map(|health| {
                health
                    .iter()
                    .filter(|(_, entry)| {
                        now.duration_since(entry.last_seen)
                            <= Duration::from_secs(ORIGIN_CONNECT_HEALTH_IDLE_TTL_SECS)
                            && entry.last_result != OriginConnectResult::None
                    })
                    .map(|(host, entry)| ConnectionInfoHostSnapshot {
                        host: host.clone(),
                        route: "direct".to_string(),
                        dns_profile: dns_by_host.get(host).cloned(),
                        dns_a_count: entry.last_dns_a_count,
                        dns_aaaa_count: entry.last_dns_aaaa_count,
                        last_ip: entry.last_ip,
                        last_family: entry
                            .last_ip
                            .map(|ip| if ip.is_ipv4() { "IPv4" } else { "IPv6" }.to_string()),
                        last_result: entry.last_result.as_str().to_string(),
                        last_connect_ms: entry.last_connect_ms,
                        last_seen_age_secs: age_secs(now, entry.last_seen),
                        family_preference: address_family_preference_from_health(entry)
                            .as_str()
                            .to_string(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        items.sort_by_key(|item| item.last_seen_age_secs);
        items.truncate(CONNECTION_INFO_SNAPSHOT_MAX_ITEMS);

        ConnectionInfoSnapshot {
            max_items: CONNECTION_INFO_SNAPSHOT_MAX_ITEMS,
            items,
        }
    }

    pub fn flush_cache_snapshot(&self) {
        let cache_snapshot = self.take_dirty_cache_snapshot();
        let learned_snapshot = self.take_dirty_learned_snapshot();
        let origin_connect_health_snapshot = self.take_dirty_origin_connect_health_snapshot();
        let has_cache_snapshot = cache_snapshot.is_some();
        let has_learned_snapshot = learned_snapshot.is_some();
        let has_origin_connect_health_snapshot = origin_connect_health_snapshot.is_some();

        if (has_cache_snapshot || has_learned_snapshot)
            && !dns_state_store::save_snapshots(cache_snapshot.as_ref(), learned_snapshot.as_ref())
        {
            if has_cache_snapshot {
                self.cache_dirty.store(true, Ordering::Release);
            }
            if has_learned_snapshot {
                self.learned_dirty.store(true, Ordering::Release);
            }
        }

        if has_origin_connect_health_snapshot
            && !origin_connect_health_store::save_snapshot(origin_connect_health_snapshot.as_ref())
        {
            self.origin_connect_health_dirty
                .store(true, Ordering::Release);
        }
    }

    fn mark_cache_dirty(&self) {
        self.cache_dirty.store(true, Ordering::Release);
    }

    fn mark_learned_dirty(&self) {
        mark_learned_dirty_flag(&self.learned_dirty);
    }

    fn mark_origin_connect_health_dirty(&self) {
        self.origin_connect_health_dirty
            .store(true, Ordering::Release);
    }

    fn take_dirty_cache_snapshot(&self) -> Option<HashMap<DnsCacheKey, DnsCacheEntry>> {
        if !self.cache_dirty.swap(false, Ordering::AcqRel) {
            return None;
        }

        match self.cache.read() {
            Ok(cache) => Some(cache.clone()),
            Err(_) => {
                self.cache_dirty.store(true, Ordering::Release);
                tracing::warn!("DNS cache snapshot skipped because cache lock poisoned");
                None
            }
        }
    }

    fn take_dirty_learned_snapshot(&self) -> Option<DnsObservationSnapshot> {
        if !self.learned_dirty.swap(false, Ordering::AcqRel) {
            return None;
        }

        let snapshot = self.observation_snapshot();
        match self.learned_observation.write() {
            Ok(mut learned) => {
                *learned = snapshot.clone();
            }
            Err(_) => {
                self.learned_dirty.store(true, Ordering::Release);
                tracing::warn!(
                    "DNS learned state update skipped because learned state lock poisoned"
                );
            }
        }
        Some(snapshot)
    }

    fn take_dirty_origin_connect_health_snapshot(&self) -> Option<OriginConnectHealthSnapshot> {
        if !self
            .origin_connect_health_dirty
            .swap(false, Ordering::AcqRel)
        {
            return None;
        }

        match self.origin_connect_health.read() {
            Ok(health) => Some(origin_connect_health_to_snapshot(&health, Instant::now())),
            Err(_) => {
                self.origin_connect_health_dirty
                    .store(true, Ordering::Release);
                tracing::warn!(
                    "origin connect health snapshot skipped because health lock poisoned"
                );
                None
            }
        }
    }

    pub(crate) fn observation_snapshot(&self) -> DnsObservationSnapshot {
        let current = self
            .observations
            .read()
            .map(|observations| observations.snapshot(Instant::now()))
            .unwrap_or_default();
        let learned = self
            .learned_observation
            .read()
            .map(|learned| learned.clone())
            .unwrap_or_default();
        merge_observation_snapshots(learned, current)
    }

    fn warm_cache_scan_interval(&self) -> Duration {
        let seconds = self
            .state
            .read()
            .map(|state| state.config.warm_cache.scan_interval_secs.max(1))
            .unwrap_or(30);
        Duration::from_secs(seconds)
    }

    fn collect_warm_cache_candidates(&self) -> Vec<DnsWarmCacheCandidate> {
        let state = match self.state.read() {
            Ok(state) => state.clone(),
            Err(_) => {
                tracing::warn!("DNS warm cache scan skipped because resolver state lock poisoned");
                return Vec::new();
            }
        };
        if !state.config.enabled || !state.config.warm_cache.enabled {
            return Vec::new();
        }

        let now = Instant::now();
        let cache = match self.cache.read() {
            Ok(cache) => cache,
            Err(_) => {
                tracing::warn!("DNS warm cache scan skipped because DNS cache lock poisoned");
                return Vec::new();
            }
        };
        let refreshing = match self.refreshing.read() {
            Ok(refreshing) => refreshing,
            Err(_) => {
                tracing::warn!("DNS warm cache scan skipped because refresh lock poisoned");
                return Vec::new();
            }
        };

        match self.warm_cache.write() {
            Ok(mut metadata) => {
                dns_warm_cache::prune_missing_metadata(&mut metadata, &cache);
                dns_warm_cache::select_warm_cache_candidates(
                    &state.config.warm_cache,
                    &cache,
                    &metadata,
                    &refreshing,
                    now,
                )
            }
            Err(_) => {
                tracing::warn!("DNS warm cache scan skipped because metadata lock poisoned");
                Vec::new()
            }
        }
    }

    fn schedule_warm_cache_refreshes(&self) {
        let state = match self.state.read() {
            Ok(state) => state.clone(),
            Err(_) => {
                tracing::warn!(
                    "DNS warm cache refresh skipped because resolver state lock poisoned"
                );
                return;
            }
        };
        let candidates = self.collect_warm_cache_candidates();
        if candidates.is_empty() {
            return;
        }

        self.schedule_observation_probes(&state, &candidates);

        for candidate in candidates {
            let route =
                route_for_cache_scope(&state, &candidate.key.host, &candidate.key.profile_id);
            let Some(profile) = self
                .select_racing_profiles(
                    &state,
                    &candidate.key.host,
                    &route,
                    DnsResolveIngress::ProxyInternal,
                )
                .into_iter()
                .next()
            else {
                continue;
            };
            self.schedule_refresh(
                &candidate.key.host,
                &candidate.key.profile_id,
                &profile,
                state.config.max_cache_entries,
                DnsRefreshReason::WarmCache,
                candidate.stale_remaining_secs,
            );
        }
    }

    fn schedule_observation_probes(&self, state: &DnsState, candidates: &[DnsWarmCacheCandidate]) {
        let config = &state.config.observation;
        if !state.config.enabled || !config.enabled {
            return;
        }

        let profiles = state
            .config
            .profiles
            .iter()
            .filter(|profile| profile.enabled)
            .take(config.max_profiles_per_host)
            .cloned()
            .collect::<Vec<_>>();
        if profiles.is_empty() {
            return;
        }

        let mut scheduled = 0_usize;
        for candidate in candidates.iter().take(config.max_hosts_per_scan) {
            if scheduled >= config.max_hosts_per_scan {
                break;
            }
            let host = candidate.key.host.clone();
            let should_probe = match self.observations.write() {
                Ok(mut observations) => observations.reserve_host(
                    &host,
                    Instant::now(),
                    Duration::from_secs(config.min_interval_secs_per_host),
                ),
                Err(_) => {
                    tracing::warn!("DNS observation skipped because observation lock poisoned");
                    false
                }
            };
            if !should_probe {
                continue;
            }

            scheduled += 1;
            self.spawn_observation_probe(host, profiles.clone());
        }
    }

    fn spawn_observation_probe(&self, host: String, profiles: Vec<DnsProfileConfig>) {
        let observations = self.observations.clone();
        let learned_dirty = self.learned_dirty.clone();
        tokio::spawn(async move {
            let mut results = Vec::with_capacity(profiles.len());
            for profile in profiles {
                results.push(observe_profile_dns(&host, &profile).await);
            }

            if record_dns_observations_locked(&observations, &host, results) {
                mark_learned_dirty_flag(&learned_dirty);
            }
        });
    }

    pub(crate) fn record_origin_connect_success_observed(&self, host: &str, ip: IpAddr) {
        self.record_origin_connect_attempt(host, &[], Some(ip), None);
    }

    #[cfg(test)]
    pub(crate) fn record_origin_connect_failures(&self, host: &str, addrs: &[SocketAddr]) {
        self.record_origin_connect_attempt(host, addrs, None, None);
    }

    pub(crate) fn record_origin_connect_attempt(
        &self,
        host: &str,
        failed_addrs: &[SocketAddr],
        selected_ip: Option<IpAddr>,
        connect_ms: Option<u64>,
    ) {
        let host = normalize_dns_host(host);
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return;
        }
        if failed_addrs.is_empty() && selected_ip.is_none() {
            return;
        }

        let now = Instant::now();
        let should_prune = self.should_prune_origin_connect_health(now);
        let Ok(mut health) = self.origin_connect_health.write() else {
            tracing::warn!(
                host = %host,
                "origin connect health skipped because lock poisoned"
            );
            return;
        };

        if should_prune || health.len() > ORIGIN_CONNECT_HEALTH_MAX_HOSTS.saturating_mul(2) {
            prune_origin_connect_health(&mut health, now);
        }

        let entry = health
            .entry(host.clone())
            .or_insert_with(|| OriginConnectHealthEntry::new(now));
        let mut recorded_v4_failure = false;
        let mut recorded_v6_failure = false;
        for addr in failed_addrs {
            let ip = addr.ip();
            if ip.is_ipv4() {
                if recorded_v4_failure {
                    continue;
                }
                recorded_v4_failure = true;
            } else {
                if recorded_v6_failure {
                    continue;
                }
                recorded_v6_failure = true;
            }
            record_origin_connect_entry(entry, ip, OriginConnectResult::Failure, None, now);
        }

        if let Some(ip) = selected_ip {
            record_origin_connect_entry(entry, ip, OriginConnectResult::Success, connect_ms, now);
        }
        entry.trace_preference_change_if_needed(&host);
        self.mark_origin_connect_health_dirty();
    }

    fn record_origin_dns_observed(&self, host: &str, ingress: DnsResolveIngress, addrs: &[IpAddr]) {
        if ingress != DnsResolveIngress::ProxyInternal {
            return;
        }

        let host = normalize_dns_host(host);
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return;
        }

        let now = Instant::now();
        let Ok(mut health) = self.origin_connect_health.write() else {
            tracing::warn!(
                host = %host,
                "connection info DNS observation skipped because lock poisoned"
            );
            return;
        };

        let Some(entry) = health.get_mut(&host) else {
            return;
        };

        if !entry.refresh_dns_context_if_needed(addrs, now) {
            return;
        }

        entry.trace_preference_change_if_needed(&host);
        self.mark_origin_connect_health_dirty();
    }

    #[cfg(test)]
    fn clear_origin_connect_health_for_test(&self) {
        if let Ok(mut health) = self.origin_connect_health.write() {
            health.clear();
        }
    }

    #[cfg(test)]
    fn seed_origin_dns_observed_for_test(
        &self,
        host: &str,
        ingress: DnsResolveIngress,
        addrs: &[IpAddr],
    ) {
        if ingress != DnsResolveIngress::ProxyInternal {
            return;
        }

        let host = normalize_dns_host(host);
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return;
        }

        let now = Instant::now();
        let Ok(mut health) = self.origin_connect_health.write() else {
            return;
        };
        let entry = health
            .entry(host.clone())
            .or_insert_with(|| OriginConnectHealthEntry::new(now));
        entry.last_dns_a_count = addrs.iter().filter(|addr| addr.is_ipv4()).count();
        entry.last_dns_aaaa_count = addrs.iter().filter(|addr| addr.is_ipv6()).count();
        entry.last_dns_seen = Some(now);
    }

    fn address_family_preference(&self, host: &str) -> AddressFamilyPreference {
        let host = normalize_dns_host(host);
        if host.is_empty() {
            return AddressFamilyPreference::Neutral;
        }

        let now = Instant::now();
        let Ok(health) = self.origin_connect_health.read() else {
            tracing::warn!(
                host = %host,
                "origin connect family preference skipped because lock poisoned"
            );
            return AddressFamilyPreference::Neutral;
        };

        let Some(entry) = health.get(&host) else {
            return AddressFamilyPreference::Neutral;
        };
        if now.duration_since(entry.last_seen)
            > Duration::from_secs(ORIGIN_CONNECT_HEALTH_IDLE_TTL_SECS)
        {
            return AddressFamilyPreference::Neutral;
        }

        address_family_preference_from_health(entry)
    }

    fn apply_address_family_preference_for_ingress(
        &self,
        host: &str,
        ingress: DnsResolveIngress,
        addrs: Vec<IpAddr>,
    ) -> Vec<IpAddr> {
        if ingress != DnsResolveIngress::ProxyInternal {
            return addrs;
        }
        self.apply_address_family_preference(host, addrs)
    }

    fn apply_address_family_preference(&self, host: &str, addrs: Vec<IpAddr>) -> Vec<IpAddr> {
        if addrs.len() < 2 || !has_both_address_families(&addrs) {
            return addrs;
        }

        let preference = self.address_family_preference(host);
        if preference == AddressFamilyPreference::Neutral {
            return addrs;
        }

        let mut preferred = Vec::with_capacity(addrs.len());
        let mut fallback = Vec::new();
        for addr in addrs {
            if address_matches_family_preference(addr, preference) {
                preferred.push(addr);
            } else {
                fallback.push(addr);
            }
        }

        if preferred.is_empty() || fallback.is_empty() {
            preferred.extend(fallback);
            return preferred;
        }

        preferred.extend(fallback);
        preferred
    }

    pub async fn resolve_socket_addrs(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let ips = self.resolve_host(host).await?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    pub async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.resolve_host_with_ingress(host, DnsResolveIngress::ProxyInternal)
            .await
    }

    pub async fn resolve_host_for_dns_server(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.resolve_host_with_ingress(host, DnsResolveIngress::DnsServer)
            .await
    }

    pub async fn resolve_host_with_ingress(
        &self,
        host: &str,
        ingress: DnsResolveIngress,
    ) -> Result<Vec<IpAddr>> {
        let host = normalize_dns_host(host);
        if host.is_empty() {
            bail!("DNS host cannot be empty");
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let (state, route) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow::anyhow!("DNS resolver state lock poisoned"))?
                .clone();
            let route = state.resolve_route(&host);
            (state, route)
        };

        if !state.config.enabled {
            if ingress.allows_system_profile() {
                return system_resolve_host(&host).await;
            }
            bail!(
                "DNS resolver is disabled and `{}` ingress cannot use System DNS",
                ingress.as_str()
            );
        }

        let cache_scope = dns_cache_scope_for_route(&route);
        let lookup = self.cache_lookup(&host, &cache_scope, &state.config)?;
        match lookup.lookup {
            DnsCacheLookup::Hit(addrs) => {
                if let Some(reason) = lookup.refresh {
                    if let Some(profile) = self
                        .select_racing_profiles(&state, &host, &route, ingress)
                        .into_iter()
                        .next()
                    {
                        self.schedule_refresh(
                            &host,
                            &cache_scope,
                            &profile,
                            state.config.max_cache_entries,
                            reason,
                            lookup.stale_remaining_secs,
                        );
                    }
                }
                self.record_origin_dns_observed(&host, ingress, &addrs);
                return Ok(self.apply_address_family_preference_for_ingress(&host, ingress, addrs));
            }
            DnsCacheLookup::Negative => return Ok(Vec::new()),
            DnsCacheLookup::Miss => {}
        }

        let addrs = self
            .resolve_cache_miss_with_racing(&state, &host, &route, &cache_scope, ingress)
            .await?;
        if !addrs.is_empty() {
            self.record_origin_dns_observed(&host, ingress, &addrs);
        }
        Ok(self.apply_address_family_preference_for_ingress(&host, ingress, addrs))
    }

    fn select_first_profile(
        &self,
        state: &DnsState,
        host: &str,
        route: &ResolvedDnsRoute,
        snapshot: &DnsObservationSnapshot,
        ingress: DnsResolveIngress,
    ) -> String {
        let enabled_profile_ids = state
            .profiles
            .iter()
            .filter(|(_, profile)| profile_enabled_for_ingress(profile, ingress))
            .map(|(profile_id, _)| profile_id.clone())
            .collect::<HashSet<_>>();
        match self.auto_select.write() {
            Ok(mut auto_select) => {
                let decision = auto_select.select_profile(
                    &state.config.auto_select,
                    snapshot,
                    host,
                    &route.profile_id,
                    &enabled_profile_ids,
                    route.strict,
                    Instant::now(),
                );
                if decision.auto_selected && decision.profile_id != route.profile_id {
                    tracing::debug!(
                        dns_auto_select = "selected",
                        host = %host,
                        selected_profile_id = %decision.profile_id,
                        fallback_profile_id = %route.profile_id,
                        "DNS auto-select chose initial profile"
                    );
                }
                decision.profile_id
            }
            Err(_) => {
                tracing::warn!(
                    host = %host,
                    "DNS auto-select skipped because auto-select lock poisoned"
                );
                route.profile_id.clone()
            }
        }
    }

    fn select_racing_profiles(
        &self,
        state: &DnsState,
        host: &str,
        route: &ResolvedDnsRoute,
        ingress: DnsResolveIngress,
    ) -> Vec<DnsProfileConfig> {
        let enabled_order = state
            .config
            .profiles
            .iter()
            .filter(|profile| profile_enabled_for_ingress(profile, ingress))
            .map(|profile| profile.id.clone())
            .collect::<Vec<_>>();

        if route.strict {
            return state
                .profiles
                .get(&route.profile_id)
                .filter(|profile| profile_enabled_for_ingress(profile, ingress))
                .cloned()
                .into_iter()
                .collect();
        }

        let snapshot = self.observation_snapshot();
        let primary_id = self.select_first_profile(state, host, route, &snapshot, ingress);
        let enabled_ids = enabled_order.iter().cloned().collect::<HashSet<_>>();
        let mut ranked_ids = snapshot
            .profiles
            .iter()
            .filter(|profile| enabled_ids.contains(&profile.profile_id))
            .map(|profile| profile.profile_id.clone())
            .collect::<Vec<_>>();
        for profile_id in &enabled_order {
            if !ranked_ids.contains(profile_id) {
                ranked_ids.push(profile_id.clone());
            }
        }

        let mut selected_ids = Vec::<String>::new();
        let mut selected_set = HashSet::<String>::new();
        push_dns_profile_id(
            &mut selected_ids,
            &mut selected_set,
            &enabled_ids,
            primary_id,
        );

        for profile_id in &ranked_ids {
            if selected_ids.len() >= DNS_RACING_MAX_PROFILES.saturating_sub(1) {
                break;
            }
            push_dns_profile_id(
                &mut selected_ids,
                &mut selected_set,
                &enabled_ids,
                profile_id.clone(),
            );
        }

        let probe_profile_id = self.auto_select.write().ok().and_then(|mut auto_select| {
            auto_select.select_probe_profile(host, &ranked_ids, &selected_set, Instant::now())
        });
        if let Some(profile_id) = probe_profile_id {
            push_dns_profile_id(
                &mut selected_ids,
                &mut selected_set,
                &enabled_ids,
                profile_id,
            );
        }

        for profile_id in &ranked_ids {
            if selected_ids.len() >= DNS_RACING_MAX_PROFILES {
                break;
            }
            push_dns_profile_id(
                &mut selected_ids,
                &mut selected_set,
                &enabled_ids,
                profile_id.clone(),
            );
        }

        selected_ids
            .into_iter()
            .filter_map(|profile_id| state.profiles.get(&profile_id).cloned())
            .collect()
    }

    async fn resolve_cache_miss_with_racing(
        &self,
        state: &DnsState,
        host: &str,
        route: &ResolvedDnsRoute,
        cache_scope: &str,
        ingress: DnsResolveIngress,
    ) -> Result<Vec<IpAddr>> {
        let key = DnsInflightKey {
            cache: DnsCacheKey {
                profile_id: cache_scope.to_string(),
                host: host.to_string(),
            },
            allow_system_profile: ingress.allows_system_profile(),
        };
        match self.reserve_inflight_lookup(&key)? {
            DnsInflightLookup::Waiter { receiver } => {
                return wait_for_inflight_dns_result(receiver).await;
            }
            DnsInflightLookup::Leader { guard } => {
                let result = self
                    .resolve_cache_miss_with_racing_uncached(
                        state,
                        host,
                        route,
                        cache_scope,
                        ingress,
                    )
                    .await;
                guard.finish(clone_inflight_dns_result(&result));
                return result;
            }
        }
    }

    async fn resolve_cache_miss_with_racing_uncached(
        &self,
        state: &DnsState,
        host: &str,
        route: &ResolvedDnsRoute,
        cache_scope: &str,
        ingress: DnsResolveIngress,
    ) -> Result<Vec<IpAddr>> {
        let profiles = self.select_racing_profiles(state, host, route, ingress);
        if profiles.is_empty() {
            if route.strict {
                bail!(
                    "strict DNS route profile `{}` is not available",
                    route.profile_id
                );
            }
            return self
                .resolve_with_system_fallback(state, host, cache_scope, ingress)
                .await;
        }

        let system_profile_already_raced = profiles
            .iter()
            .any(|profile| profile.id == SYSTEM_DNS_PROFILE_ID);
        let (tx, mut rx) = mpsc::channel(profiles.len());
        for profile in profiles {
            let tx = tx.clone();
            let host = host.to_string();
            tokio::spawn(async move {
                let result = race_profile_dns(host, profile).await;
                let _ = tx.send(result).await;
            });
        }
        drop(tx);

        let mut observations = Vec::new();
        let mut first_negative_kind = None;
        while let Some(result) = rx.recv().await {
            let DnsRaceProfileResult {
                observation,
                positive,
                negative_kind,
            } = result;
            if first_negative_kind.is_none() {
                first_negative_kind = negative_kind;
            }

            let source_profile_id = observation.profile_id.clone();
            observations.push(observation);

            if let Some(positive) = positive {
                if dns_answer_is_trusted(&positive.addrs, route.strict) {
                    self.cache_store_positive_for_scope(
                        host,
                        cache_scope,
                        &source_profile_id,
                        positive.addrs.clone(),
                        positive.ttl_secs,
                        positive.stale_fallback_secs,
                        state.config.max_cache_entries,
                    )?;
                    if let Some(late_merge) = positive.late_merge {
                        self.spawn_late_dns_cache_merge(
                            host.to_string(),
                            cache_scope.to_string(),
                            source_profile_id.clone(),
                            positive.ttl_secs,
                            positive.stale_fallback_secs,
                            late_merge,
                        );
                    }
                    self.spawn_racing_observation_collector(host.to_string(), observations, rx);
                    tracing::debug!(
                        dns_racing = "first_trusted",
                        host = %host,
                        source_profile_id = %source_profile_id,
                        cache_scope = %cache_scope,
                        ttl_secs = positive.ttl_secs,
                        "DNS racing returned first trusted answer"
                    );
                    return Ok(positive.addrs);
                }
            }
        }

        self.record_dns_observations(host, observations);

        if route.strict {
            let negative_kind = first_negative_kind.unwrap_or(DnsNegativeKind::TemporaryFailure);
            self.cache_store_negative_for_scope(
                host,
                cache_scope,
                &route.profile_id,
                state.config.max_cache_entries,
                negative_kind,
            )?;
            if matches!(
                negative_kind,
                DnsNegativeKind::Nxdomain | DnsNegativeKind::NoRecords
            ) {
                return Ok(Vec::new());
            }
            bail!("strict DNS racing failed for {host}");
        }

        if system_profile_already_raced {
            let negative_kind = first_negative_kind.unwrap_or(DnsNegativeKind::TemporaryFailure);
            self.cache_store_negative_for_scope(
                host,
                cache_scope,
                SYSTEM_DNS_PROFILE_ID,
                state.config.max_cache_entries,
                negative_kind,
            )?;
            if matches!(
                negative_kind,
                DnsNegativeKind::Nxdomain | DnsNegativeKind::NoRecords
            ) {
                return Ok(Vec::new());
            }
            bail!("DNS racing failed for {host}");
        }

        self.resolve_with_system_fallback(state, host, cache_scope, ingress)
            .await
    }

    async fn resolve_with_system_fallback(
        &self,
        state: &DnsState,
        host: &str,
        cache_scope: &str,
        ingress: DnsResolveIngress,
    ) -> Result<Vec<IpAddr>> {
        if !ingress.allows_system_profile() {
            bail!(
                "no explicit DNS profile is available for {host}; `{}` ingress cannot use System DNS",
                ingress.as_str()
            );
        }

        let started = Instant::now();
        let result = system_resolve_host(host)
            .await
            .map(DnsLookupResult::without_ttl);
        let latency_ms = elapsed_millis(started);
        match result {
            Ok(result) if !result.addrs.is_empty() => {
                self.record_dns_observations(
                    host,
                    vec![DnsProfileObservationResult::success(
                        SYSTEM_DNS_PROFILE_ID.to_string(),
                        latency_ms,
                        result.ttl_secs,
                        result.addrs.clone(),
                    )],
                );
                let ttl_secs =
                    positive_cache_ttl_secs(host, &DnsProfileConfig::system(), result.ttl_secs);
                let stale_fallback_secs =
                    positive_stale_fallback_secs(host, default_system_stale_fallback_secs(state));
                self.cache_store_positive_for_scope(
                    host,
                    cache_scope,
                    SYSTEM_DNS_PROFILE_ID,
                    result.addrs.clone(),
                    ttl_secs,
                    stale_fallback_secs,
                    state.config.max_cache_entries,
                )?;
                Ok(result.addrs)
            }
            Ok(_) => {
                self.record_dns_observations(
                    host,
                    vec![DnsProfileObservationResult::failure(
                        SYSTEM_DNS_PROFILE_ID.to_string(),
                        latency_ms,
                        DnsObservationErrorKind::NoRecords,
                    )],
                );
                self.cache_store_negative_for_scope(
                    host,
                    cache_scope,
                    SYSTEM_DNS_PROFILE_ID,
                    state.config.max_cache_entries,
                    DnsNegativeKind::NoRecords,
                )?;
                Ok(Vec::new())
            }
            Err(error) => {
                let negative_kind = classify_dns_negative_kind(&error);
                self.record_dns_observations(
                    host,
                    vec![DnsProfileObservationResult::failure(
                        SYSTEM_DNS_PROFILE_ID.to_string(),
                        latency_ms,
                        observation_error_kind(&error),
                    )],
                );
                self.cache_store_negative_for_scope(
                    host,
                    cache_scope,
                    SYSTEM_DNS_PROFILE_ID,
                    state.config.max_cache_entries,
                    negative_kind,
                )?;
                Err(error)
            }
        }
    }

    fn reserve_inflight_lookup(&self, key: &DnsInflightKey) -> Result<DnsInflightLookup> {
        let mut inflight = self
            .inflight
            .write()
            .map_err(|_| anyhow::anyhow!("DNS in-flight lock poisoned"))?;

        if let Some(sender) = inflight.get(key) {
            tracing::debug!(
                dns_inflight = "join",
                cache_scope = %key.cache.profile_id,
                host = %key.cache.host,
                "DNS cache miss joined existing in-flight lookup"
            );
            return Ok(DnsInflightLookup::Waiter {
                receiver: sender.subscribe(),
            });
        }

        let (sender, _receiver) = watch::channel(None);
        inflight.insert(key.clone(), sender.clone());
        tracing::debug!(
            dns_inflight = "leader",
            cache_scope = %key.cache.profile_id,
            host = %key.cache.host,
            "DNS cache miss reserved new in-flight lookup"
        );
        Ok(DnsInflightLookup::Leader {
            guard: DnsInflightLeaderGuard::new(key.clone(), sender, self.inflight.clone()),
        })
    }

    fn spawn_racing_observation_collector(
        &self,
        host: String,
        mut observations: Vec<DnsProfileObservationResult>,
        mut rx: mpsc::Receiver<DnsRaceProfileResult>,
    ) {
        let observation_store = self.observations.clone();
        let learned_dirty = self.learned_dirty.clone();
        tokio::spawn(async move {
            while let Some(result) = rx.recv().await {
                observations.push(result.observation);
            }
            if record_dns_observations_locked(&observation_store, &host, observations) {
                mark_learned_dirty_flag(&learned_dirty);
            }
        });
    }

    fn record_dns_observations(&self, host: &str, observations: Vec<DnsProfileObservationResult>) {
        if record_dns_observations_locked(&self.observations, host, observations) {
            self.mark_learned_dirty();
        }
    }

    fn cache_lookup(
        &self,
        host: &str,
        cache_scope: &str,
        config: &DnsConfig,
    ) -> Result<DnsCacheLookupOutcome> {
        let key = DnsCacheKey {
            profile_id: cache_scope.to_string(),
            host: host.to_string(),
        };
        let now = Instant::now();
        let entry = match self.cache.read() {
            Ok(cache) => cache.get(&key).cloned(),
            Err(_) => return Err(anyhow::anyhow!("DNS cache lock poisoned")),
        };
        let Some(entry) = entry else {
            tracing::debug!(
                dns_cache = "miss",
                cache_scope = %cache_scope,
                host = %host,
                ttl_secs = 0_u64,
                stale_remaining_secs = 0_u64,
                "DNS cache miss"
            );
            return Ok(DnsCacheLookupOutcome {
                lookup: DnsCacheLookup::Miss,
                refresh: None,
                stale_remaining_secs: 0,
            });
        };

        if entry.negative {
            if now <= entry.expires_at {
                let ttl_secs = remaining_secs(now, entry.expires_at);
                let stale_remaining_secs = remaining_secs(now, entry.stale_until);
                if !entry.addrs.is_empty()
                    && !is_ephemeral_dns_host(host)
                    && now <= entry.stale_until
                {
                    tracing::debug!(
                        dns_cache = "negative_stale_hit",
                        cache_scope = %cache_scope,
                        host = %host,
                        ttl_secs,
                        stale_remaining_secs,
                        "DNS negative cache hit; serving stale positive shared address"
                    );
                    return Ok(DnsCacheLookupOutcome {
                        lookup: DnsCacheLookup::Hit(entry.addrs),
                        refresh: None,
                        stale_remaining_secs,
                    });
                }

                tracing::debug!(
                    dns_cache = "negative",
                    cache_scope = %cache_scope,
                    host = %host,
                    ttl_secs,
                    stale_remaining_secs = 0_u64,
                    "DNS negative cache hit"
                );
                return Ok(DnsCacheLookupOutcome {
                    lookup: DnsCacheLookup::Negative,
                    refresh: None,
                    stale_remaining_secs: 0,
                });
            }

            tracing::debug!(
                dns_cache = "stale",
                cache_scope = %cache_scope,
                host = %host,
                ttl_secs = 0_u64,
                stale_remaining_secs = 0_u64,
                "DNS negative cache entry expired"
            );
            self.remove_cache_entry_if_not_newer(&key, entry.stale_until);
            return Ok(DnsCacheLookupOutcome {
                lookup: DnsCacheLookup::Miss,
                refresh: None,
                stale_remaining_secs: 0,
            });
        }

        if now <= entry.expires_at {
            let ttl_secs = remaining_secs(now, entry.expires_at);
            let stale_remaining_secs = remaining_secs(now, entry.stale_until);
            if config.stale_while_revalidate
                && !is_ephemeral_dns_host(host)
                && config.refresh_before_expire_secs > 0
                && ttl_secs <= config.refresh_before_expire_secs
            {
                tracing::debug!(
                    dns_cache = "stale_refreshing",
                    cache_scope = %cache_scope,
                    host = %host,
                    ttl_secs,
                    stale_remaining_secs,
                    "DNS shared cache hit near expiry; serving cached address and scheduling refresh"
                );
                if let Ok(mut metadata) = self.warm_cache.write() {
                    dns_warm_cache::record_positive_cache_hit(&mut metadata, key.clone(), now);
                }
                return Ok(DnsCacheLookupOutcome {
                    lookup: DnsCacheLookup::Hit(entry.addrs),
                    refresh: Some(DnsRefreshReason::BeforeExpire),
                    stale_remaining_secs,
                });
            }

            tracing::debug!(
                dns_cache = "hit",
                cache_scope = %cache_scope,
                host = %host,
                ttl_secs,
                stale_remaining_secs,
                "DNS shared cache hit"
            );
            return Ok(DnsCacheLookupOutcome {
                lookup: DnsCacheLookup::Hit(entry.addrs),
                refresh: None,
                stale_remaining_secs,
            });
        }

        if config.stale_while_revalidate && !is_ephemeral_dns_host(host) && now <= entry.stale_until
        {
            let stale_remaining_secs = remaining_secs(now, entry.stale_until);
            tracing::debug!(
                dns_cache = "stale_refreshing",
                cache_scope = %cache_scope,
                host = %host,
                ttl_secs = 0_u64,
                stale_remaining_secs,
                "DNS shared cache stale hit; serving stale address and scheduling refresh"
            );
            if let Ok(mut metadata) = self.warm_cache.write() {
                dns_warm_cache::record_positive_cache_hit(&mut metadata, key.clone(), now);
            }
            return Ok(DnsCacheLookupOutcome {
                lookup: DnsCacheLookup::Hit(entry.addrs),
                refresh: Some(DnsRefreshReason::Stale),
                stale_remaining_secs,
            });
        }

        tracing::debug!(
            dns_cache = "stale",
            cache_scope = %cache_scope,
            host = %host,
            ttl_secs = 0_u64,
            stale_remaining_secs = 0_u64,
            "DNS cache entry expired"
        );
        self.remove_cache_entry_if_not_newer(&key, entry.stale_until);
        Ok(DnsCacheLookupOutcome {
            lookup: DnsCacheLookup::Miss,
            refresh: None,
            stale_remaining_secs: 0,
        })
    }

    fn remove_cache_entry_if_not_newer(&self, key: &DnsCacheKey, stale_until: Instant) {
        let removed = match self.cache.write() {
            Ok(mut cache) => {
                let should_remove = cache
                    .get(key)
                    .map(|entry| entry.stale_until <= stale_until)
                    .unwrap_or(false);
                should_remove && cache.remove(key).is_some()
            }
            Err(_) => {
                tracing::warn!("DNS cache entry removal skipped because cache lock poisoned");
                false
            }
        };
        if removed {
            self.mark_cache_dirty();
        }
    }

    fn schedule_refresh(
        &self,
        host: &str,
        cache_scope: &str,
        profile: &DnsProfileConfig,
        max_cache_entries: usize,
        reason: DnsRefreshReason,
        stale_remaining_secs: u64,
    ) {
        let key = DnsCacheKey {
            profile_id: cache_scope.to_string(),
            host: host.to_string(),
        };

        let mut refreshing = match self.refreshing.write() {
            Ok(refreshing) => refreshing,
            Err(_) => {
                tracing::warn!(
                    dns_refresh = "failed",
                    source_profile_id = %profile.id,
                    cache_scope = %cache_scope,
                    host = %host,
                    reason = reason.as_str(),
                    stale_remaining_secs,
                    error = "DNS refresh lock poisoned",
                    "failed to schedule DNS refresh"
                );
                return;
            }
        };

        if refreshing.len() >= DNS_MAX_BACKGROUND_REFRESHES {
            tracing::debug!(
                dns_refresh = "skipped_busy",
                source_profile_id = %profile.id,
                cache_scope = %cache_scope,
                host = %host,
                reason = reason.as_str(),
                active_refreshes = refreshing.len(),
                max_refreshes = DNS_MAX_BACKGROUND_REFRESHES,
                "DNS refresh skipped because background refresh queue is busy"
            );
            return;
        }

        if !refreshing.insert(key.clone()) {
            tracing::debug!(
                dns_refresh = "skipped_already_running",
                source_profile_id = %profile.id,
                cache_scope = %cache_scope,
                host = %host,
                reason = reason.as_str(),
                stale_remaining_secs,
                "DNS refresh already running"
            );
            return;
        }
        drop(refreshing);

        if let Ok(mut metadata) = self.warm_cache.write() {
            dns_warm_cache::record_refresh_attempt(&mut metadata, &key, Instant::now());
        }

        tracing::debug!(
            dns_refresh = "scheduled",
            source_profile_id = %profile.id,
            cache_scope = %cache_scope,
            host = %host,
            reason = reason.as_str(),
            stale_remaining_secs,
            "DNS background refresh scheduled"
        );

        let cache = self.cache.clone();
        let warm_cache = self.warm_cache.clone();
        let observations = self.observations.clone();
        let refreshing = self.refreshing.clone();
        let cache_dirty = self.cache_dirty.clone();
        let learned_dirty = self.learned_dirty.clone();
        let host = host.to_string();
        let profile = profile.clone();
        let key_for_task = key.clone();

        tokio::spawn(async move {
            let result = race_profile_dns(host.clone(), profile.clone()).await;
            if record_dns_observations_locked(
                &observations,
                &host,
                vec![result.observation.clone()],
            ) {
                mark_learned_dirty_flag(&learned_dirty);
            }

            if let Some(positive) = result.positive {
                let DnsRacePositiveResult {
                    addrs,
                    ttl_secs,
                    stale_fallback_secs,
                    late_merge,
                } = positive;
                let now = Instant::now();
                let entry = DnsCacheEntry {
                    addrs,
                    expires_at: now + Duration::from_secs(ttl_secs),
                    stale_until: now + Duration::from_secs(ttl_secs + stale_fallback_secs),
                    negative: false,
                    source_profile_id: profile.id.clone(),
                };
                let mut stored = false;
                match cache.write() {
                    Ok(mut cache) => {
                        prune_expired_locked(&mut cache, now);
                        if cache.len() >= max_cache_entries.max(1) {
                            evict_one_cache_entry(&mut cache);
                        }
                        cache.insert(key_for_task.clone(), entry);
                        cache_dirty.store(true, Ordering::Release);
                        stored = true;
                        if let Ok(mut metadata) = warm_cache.write() {
                            dns_warm_cache::record_refresh_success(
                                &mut metadata,
                                &key_for_task,
                                now,
                            );
                        }
                        tracing::debug!(
                            dns_refresh = "success",
                            source_profile_id = %profile.id,
                            cache_scope = %key_for_task.profile_id,
                            host = %host,
                            ttl_secs,
                            stale_remaining_secs = ttl_secs + stale_fallback_secs,
                            "DNS background refresh succeeded"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            dns_refresh = "failed",
                            source_profile_id = %profile.id,
                            cache_scope = %key_for_task.profile_id,
                            host = %host,
                            error = "DNS cache lock poisoned",
                            "DNS background refresh could not update cache"
                        );
                    }
                }

                if stored {
                    if let Some(late_merge) = late_merge {
                        spawn_late_dns_cache_merge_task(
                            cache.clone(),
                            warm_cache.clone(),
                            cache_dirty.clone(),
                            host.clone(),
                            key_for_task.profile_id.clone(),
                            profile.id.clone(),
                            ttl_secs,
                            stale_fallback_secs,
                            late_merge,
                        );
                    }
                }
            } else {
                if let Ok(mut metadata) = warm_cache.write() {
                    dns_warm_cache::record_refresh_failure(&mut metadata, &key_for_task);
                }
                tracing::warn!(
                    dns_refresh = "failed",
                    source_profile_id = %profile.id,
                    cache_scope = %key_for_task.profile_id,
                    host = %host,
                    error = ?result.negative_kind,
                    "DNS background refresh failed"
                );
            }

            if let Ok(mut refreshing) = refreshing.write() {
                refreshing.remove(&key_for_task);
            }
        });
    }

    fn cache_store_positive_for_scope(
        &self,
        host: &str,
        cache_scope: &str,
        source_profile_id: &str,
        addrs: Vec<IpAddr>,
        ttl_secs: u64,
        stale_fallback_secs: u64,
        max_cache_entries: usize,
    ) -> Result<()> {
        let ttl_secs = cap_ephemeral_positive_ttl_secs(host, ttl_secs);
        let stale_fallback_secs = positive_stale_fallback_secs(host, stale_fallback_secs);
        let now = Instant::now();
        let entry = DnsCacheEntry {
            addrs,
            expires_at: now + Duration::from_secs(ttl_secs),
            stale_until: now + Duration::from_secs(ttl_secs + stale_fallback_secs),
            negative: false,
            source_profile_id: source_profile_id.to_string(),
        };
        self.cache_store_entry_for_scope(host, cache_scope, entry, max_cache_entries)?;
        let key = DnsCacheKey {
            profile_id: cache_scope.to_string(),
            host: host.to_string(),
        };
        if let Ok(mut metadata) = self.warm_cache.write() {
            dns_warm_cache::record_positive_cache_store(&mut metadata, key, Instant::now());
        }
        self.clear_negative_failure(host, cache_scope)?;
        tracing::debug!(
            dns_cache = "store",
            source_profile_id = %source_profile_id,
            cache_scope = %cache_scope,
            host = %host,
            ttl_secs,
            "DNS positive shared cache stored"
        );
        Ok(())
    }

    fn spawn_late_dns_cache_merge(
        &self,
        host: String,
        cache_scope: String,
        source_profile_id: String,
        positive_ttl_secs: u64,
        stale_fallback_secs: u64,
        late_merge: DnsLateMerge,
    ) {
        spawn_late_dns_cache_merge_task(
            self.cache.clone(),
            self.warm_cache.clone(),
            self.cache_dirty.clone(),
            host,
            cache_scope,
            source_profile_id,
            positive_ttl_secs,
            stale_fallback_secs,
            late_merge,
        );
    }

    fn cache_store_negative_for_scope(
        &self,
        host: &str,
        cache_scope: &str,
        source_profile_id: &str,
        max_cache_entries: usize,
        kind: DnsNegativeKind,
    ) -> Result<()> {
        if !self.should_store_negative(host, cache_scope, kind)? {
            return Ok(());
        }

        let now = Instant::now();
        let key = DnsCacheKey {
            profile_id: cache_scope.to_string(),
            host: host.to_string(),
        };
        let (stale_addrs, stale_until, stale_source_profile_id) = if is_ephemeral_dns_host(host) {
            (Vec::new(), now, source_profile_id.to_string())
        } else {
            self.cache
                .read()
                .map_err(|_| anyhow::anyhow!("DNS cache lock poisoned"))?
                .get(&key)
                .filter(|entry| !entry.addrs.is_empty() && now <= entry.stale_until)
                .map(|entry| {
                    (
                        entry.addrs.clone(),
                        entry.stale_until,
                        entry.source_profile_id.clone(),
                    )
                })
                .unwrap_or_else(|| (Vec::new(), now, source_profile_id.to_string()))
        };
        let ttl_secs = negative_cache_ttl_secs(host, kind);
        let entry = DnsCacheEntry {
            addrs: stale_addrs,
            expires_at: now + Duration::from_secs(ttl_secs),
            stale_until,
            negative: true,
            source_profile_id: stale_source_profile_id,
        };
        self.cache_store_entry_for_scope(host, cache_scope, entry, max_cache_entries)?;
        tracing::debug!(
            dns_cache = "negative",
            source_profile_id = %source_profile_id,
            cache_scope = %cache_scope,
            host = %host,
            kind = kind.as_str(),
            ttl_secs,
            threshold = NEGATIVE_DNS_FAILURE_THRESHOLD,
            window_secs = NEGATIVE_DNS_FAILURE_WINDOW_SECS,
            "DNS negative shared cache stored after repeated failures"
        );
        Ok(())
    }

    fn should_store_negative(
        &self,
        host: &str,
        cache_scope: &str,
        kind: DnsNegativeKind,
    ) -> Result<bool> {
        let key = DnsCacheKey {
            profile_id: cache_scope.to_string(),
            host: host.to_string(),
        };
        let now = Instant::now();
        let window = Duration::from_secs(NEGATIVE_DNS_FAILURE_WINDOW_SECS);
        let mut failures = self
            .negative_failures
            .write()
            .map_err(|_| anyhow::anyhow!("DNS negative failure lock poisoned"))?;
        Self::prune_negative_failures_locked(&mut failures, now, window);

        let state = failures
            .entry(key.clone())
            .or_insert(NegativeDnsFailureState {
                kind,
                count: 0,
                first_seen: now,
            });

        let outside_window = now
            .checked_duration_since(state.first_seen)
            .unwrap_or_default()
            > window;
        if state.kind != kind || outside_window {
            *state = NegativeDnsFailureState {
                kind,
                count: 1,
                first_seen: now,
            };
        } else {
            state.count = state.count.saturating_add(1);
        }

        let count = state.count;
        if count >= NEGATIVE_DNS_FAILURE_THRESHOLD {
            failures.remove(&key);
            return Ok(true);
        }

        tracing::debug!(
            dns_cache = "negative_pending",
            cache_scope = %cache_scope,
            host = %host,
            kind = kind.as_str(),
            count,
            threshold = NEGATIVE_DNS_FAILURE_THRESHOLD,
            window_secs = NEGATIVE_DNS_FAILURE_WINDOW_SECS,
            "DNS failure recorded but not negative-cached yet"
        );
        Ok(false)
    }

    fn clear_negative_failure(&self, host: &str, cache_scope: &str) -> Result<()> {
        self.negative_failures
            .write()
            .map_err(|_| anyhow::anyhow!("DNS negative failure lock poisoned"))?
            .remove(&DnsCacheKey {
                profile_id: cache_scope.to_string(),
                host: host.to_string(),
            });
        Ok(())
    }

    fn prune_negative_failures_locked(
        failures: &mut HashMap<DnsCacheKey, NegativeDnsFailureState>,
        now: Instant,
        window: Duration,
    ) {
        failures.retain(|_, state| {
            now.checked_duration_since(state.first_seen)
                .is_none_or(|age| age <= window)
        });
    }

    fn cache_store_entry_for_scope(
        &self,
        host: &str,
        cache_scope: &str,
        entry: DnsCacheEntry,
        max_cache_entries: usize,
    ) -> Result<()> {
        let now = Instant::now();
        let mut cache = self
            .cache
            .write()
            .map_err(|_| anyhow::anyhow!("DNS cache lock poisoned"))?;
        prune_expired_locked(&mut cache, now);
        let max_cache_entries = max_cache_entries.max(1);
        if cache.len() >= max_cache_entries {
            evict_one_cache_entry(&mut cache);
        }
        cache.insert(
            DnsCacheKey {
                profile_id: cache_scope.to_string(),
                host: host.to_string(),
            },
            entry,
        );
        drop(cache);
        self.mark_cache_dirty();
        Ok(())
    }

    pub fn prune_expired(&self) -> Result<()> {
        let now = Instant::now();
        let mut cache = self
            .cache
            .write()
            .map_err(|_| anyhow::anyhow!("DNS cache lock poisoned"))?;
        if prune_expired_locked(&mut cache, now) {
            drop(cache);
            self.mark_cache_dirty();
        }
        Ok(())
    }
}

fn spawn_late_dns_cache_merge_task(
    cache: Arc<RwLock<HashMap<DnsCacheKey, DnsCacheEntry>>>,
    warm_cache: Arc<RwLock<HashMap<DnsCacheKey, DnsWarmCacheAccess>>>,
    cache_dirty: Arc<AtomicBool>,
    host: String,
    cache_scope: String,
    source_profile_id: String,
    positive_ttl_secs: u64,
    stale_fallback_secs: u64,
    late_merge: DnsLateMerge,
) {
    tokio::spawn(async move {
        let late_result = match late_merge.receiver.await {
            Ok(Some(result)) if !result.addrs.is_empty() => result,
            _ => return,
        };

        let ttl_secs = cap_ephemeral_positive_ttl_secs(
            &host,
            late_result.ttl_secs.unwrap_or(positive_ttl_secs),
        );
        let stale_fallback_secs = positive_stale_fallback_secs(&host, stale_fallback_secs);
        let now = Instant::now();
        let key = DnsCacheKey {
            profile_id: cache_scope.clone(),
            host: host.clone(),
        };

        match cache.write() {
            Ok(mut cache) => {
                prune_expired_locked(&mut cache, now);
                let updated = match cache.get_mut(&key) {
                    Some(entry)
                        if !entry.negative && entry.source_profile_id == source_profile_id =>
                    {
                        let before_len = entry.addrs.len();
                        entry.addrs.extend(late_result.addrs);
                        entry.addrs.sort();
                        entry.addrs.dedup();
                        let late_expires_at = now + Duration::from_secs(ttl_secs);
                        if late_expires_at < entry.expires_at {
                            entry.expires_at = late_expires_at;
                            entry.stale_until =
                                now + Duration::from_secs(ttl_secs + stale_fallback_secs);
                        }
                        entry.addrs.len() != before_len
                    }
                    _ => false,
                };

                if updated {
                    cache_dirty.store(true, Ordering::Release);
                    if let Ok(mut metadata) = warm_cache.write() {
                        dns_warm_cache::record_positive_cache_store(
                            &mut metadata,
                            key,
                            Instant::now(),
                        );
                    }
                    tracing::debug!(
                        dns_cache = "late_merge",
                        source_profile_id = %source_profile_id,
                        cache_scope = %cache_scope,
                        host = %host,
                        ttl_secs,
                        "DNS late A/AAAA result merged into cache"
                    );
                }
            }
            Err(_) => {
                tracing::warn!(
                    cache_scope = %cache_scope,
                    host = %host,
                    "DNS late A/AAAA merge skipped because cache lock poisoned"
                );
            }
        }
    });
}

impl Drop for RelayGateDnsResolver {
    fn drop(&mut self) {
        self.flush_cache_snapshot();
    }
}

impl Resolve for ReqwestDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let inner = self.inner.clone();
        Box::pin(async move {
            let addrs = inner.resolve_host(&host).await?;
            let socket_addrs = addrs
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect::<Vec<_>>();
            Ok(Box::new(socket_addrs.into_iter()) as Addrs)
        })
    }
}

async fn run_warm_cache_worker(resolver: Weak<RelayGateDnsResolver>) {
    loop {
        let Some(strong) = resolver.upgrade() else {
            return;
        };
        let scan_interval = strong.warm_cache_scan_interval();
        drop(strong);

        let mut ticker = time::interval(scan_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;
        ticker.tick().await;

        let Some(strong) = resolver.upgrade() else {
            return;
        };
        strong.schedule_warm_cache_refreshes();
    }
}

async fn run_cache_persistence_worker(resolver: Weak<RelayGateDnsResolver>) {
    let mut ticker = time::interval(Duration::from_secs(DNS_CACHE_SNAPSHOT_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let Some(strong) = resolver.upgrade() else {
            return;
        };
        let cache_snapshot = strong.take_dirty_cache_snapshot();
        let cache_dirty = strong.cache_dirty.clone();
        let learned_snapshot = strong.take_dirty_learned_snapshot();
        let learned_dirty = strong.learned_dirty.clone();
        let origin_connect_health_snapshot = strong.take_dirty_origin_connect_health_snapshot();
        let origin_connect_health_dirty = strong.origin_connect_health_dirty.clone();
        drop(strong);

        let has_cache_snapshot = cache_snapshot.is_some();
        let has_learned_snapshot = learned_snapshot.is_some();
        let has_origin_connect_health_snapshot = origin_connect_health_snapshot.is_some();
        if has_cache_snapshot || has_learned_snapshot || has_origin_connect_health_snapshot {
            match tokio::task::spawn_blocking(move || {
                let dns_saved = dns_state_store::save_snapshots(
                    cache_snapshot.as_ref(),
                    learned_snapshot.as_ref(),
                );
                let origin_connect_health_saved = origin_connect_health_store::save_snapshot(
                    origin_connect_health_snapshot.as_ref(),
                );
                (dns_saved, origin_connect_health_saved)
            })
            .await
            {
                Ok((dns_saved, origin_connect_health_saved)) => {
                    if !dns_saved {
                        if has_cache_snapshot {
                            cache_dirty.store(true, Ordering::Release);
                        }
                        if has_learned_snapshot {
                            learned_dirty.store(true, Ordering::Release);
                        }
                    }
                    if !origin_connect_health_saved && has_origin_connect_health_snapshot {
                        origin_connect_health_dirty.store(true, Ordering::Release);
                    }
                }
                Err(error) => {
                    if has_cache_snapshot {
                        cache_dirty.store(true, Ordering::Release);
                    }
                    if has_learned_snapshot {
                        learned_dirty.store(true, Ordering::Release);
                    }
                    if has_origin_connect_health_snapshot {
                        origin_connect_health_dirty.store(true, Ordering::Release);
                    }
                    tracing::warn!(error = %error, "DNS state snapshot worker failed");
                }
            }
        }
    }
}

async fn observe_profile_dns(
    host: &str,
    profile: &DnsProfileConfig,
) -> DnsProfileObservationResult {
    race_profile_dns(host.to_string(), profile.clone())
        .await
        .observation
}

async fn race_profile_dns(host: String, profile: DnsProfileConfig) -> DnsRaceProfileResult {
    let started = Instant::now();
    let result = query_profile_dns(&host, &profile).await;
    let elapsed_latency_ms = elapsed_millis(started);

    match result {
        Ok(result) if !result.addrs.is_empty() => {
            let latency_ms = result.first_usable_latency_ms.unwrap_or(elapsed_latency_ms);
            let observation = DnsProfileObservationResult::success(
                profile.id.clone(),
                latency_ms,
                result.ttl_secs,
                result.addrs.clone(),
            );
            let ttl_secs = positive_cache_ttl_secs(&host, &profile, result.ttl_secs);
            DnsRaceProfileResult {
                observation,
                positive: Some(DnsRacePositiveResult {
                    addrs: result.addrs,
                    ttl_secs,
                    stale_fallback_secs: positive_stale_fallback_secs(
                        &host,
                        profile.stale_fallback_secs,
                    ),
                    late_merge: result.late_merge,
                }),
                negative_kind: None,
            }
        }
        Ok(_) => DnsRaceProfileResult {
            observation: DnsProfileObservationResult::failure(
                profile.id.clone(),
                elapsed_latency_ms,
                DnsObservationErrorKind::NoRecords,
            ),
            positive: None,
            negative_kind: Some(DnsNegativeKind::NoRecords),
        },
        Err(error) => {
            let negative_kind = classify_dns_negative_kind(&error);
            DnsRaceProfileResult {
                observation: DnsProfileObservationResult::failure(
                    profile.id.clone(),
                    elapsed_latency_ms,
                    observation_error_kind(&error),
                ),
                positive: None,
                negative_kind: Some(negative_kind),
            }
        }
    }
}

async fn query_profile_dns(host: &str, profile: &DnsProfileConfig) -> Result<DnsLookupResult> {
    match profile.mode {
        DnsProfileMode::System => system_resolve_host(host)
            .await
            .map(DnsLookupResult::without_ttl),
        DnsProfileMode::Udp => udp_resolve_host(host, profile).await,
    }
}

fn clone_inflight_dns_result(result: &Result<Vec<IpAddr>>) -> DnsInflightResult {
    match result {
        Ok(addrs) => Ok(addrs.clone()),
        Err(error) => Err(error.to_string()),
    }
}

async fn wait_for_inflight_dns_result(
    mut receiver: watch::Receiver<Option<DnsInflightResult>>,
) -> Result<Vec<IpAddr>> {
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result.map_err(anyhow::Error::msg);
        }
        if receiver.changed().await.is_err() {
            bail!("DNS in-flight lookup ended before producing a result");
        }
    }
}

fn record_dns_observations_locked(
    observations: &Arc<RwLock<DnsObservationStore>>,
    host: &str,
    results: Vec<DnsProfileObservationResult>,
) -> bool {
    if results.is_empty() {
        return false;
    }
    let divergent = dns_observation_diverged(&results);
    match observations.write() {
        Ok(mut observations) => observations.record_host_results(host, Instant::now(), results),
        Err(_) => {
            tracing::warn!(
                host = %host,
                "DNS observation result dropped because observation lock poisoned"
            );
            return false;
        }
    }

    tracing::debug!(
        dns_observation = "recorded",
        host = %host,
        divergent,
        "DNS profile observation recorded"
    );
    true
}

fn mark_learned_dirty_flag(learned_dirty: &AtomicBool) {
    learned_dirty.store(true, Ordering::Release);
}

fn merge_observation_snapshots(
    learned: DnsObservationSnapshot,
    current: DnsObservationSnapshot,
) -> DnsObservationSnapshot {
    if learned.profiles.is_empty() {
        return current;
    }
    if current.profiles.is_empty() {
        return learned;
    }

    let mut profiles = learned
        .profiles
        .into_iter()
        .map(|profile| (profile.profile_id.clone(), profile))
        .collect::<HashMap<String, DnsProfileHealthSnapshot>>();
    for profile in current.profiles {
        profiles.insert(profile.profile_id.clone(), profile);
    }

    let mut profiles = profiles.into_values().collect::<Vec<_>>();
    sort_dns_observation_profiles(&mut profiles);
    DnsObservationSnapshot {
        observed_hosts: learned.observed_hosts.max(current.observed_hosts),
        profiles,
    }
}

fn sort_dns_observation_profiles(profiles: &mut [DnsProfileHealthSnapshot]) {
    profiles.sort_by(|left, right| {
        right
            .health_score
            .cmp(&left.health_score)
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
}

fn profile_enabled_for_ingress(profile: &DnsProfileConfig, ingress: DnsResolveIngress) -> bool {
    profile.enabled && (ingress.allows_system_profile() || profile.mode != DnsProfileMode::System)
}

fn push_dns_profile_id(
    selected_ids: &mut Vec<String>,
    selected_set: &mut HashSet<String>,
    enabled_ids: &HashSet<String>,
    profile_id: String,
) {
    if selected_ids.len() >= DNS_RACING_MAX_PROFILES {
        return;
    }
    if !enabled_ids.contains(&profile_id) || !selected_set.insert(profile_id.clone()) {
        return;
    }
    selected_ids.push(profile_id);
}

fn dns_cache_scope_for_route(route: &ResolvedDnsRoute) -> String {
    if route.strict {
        strict_dns_cache_scope(&route.profile_id)
    } else {
        SHARED_DNS_CACHE_SCOPE_ID.to_string()
    }
}

fn strict_dns_cache_scope(profile_id: &str) -> String {
    format!("{STRICT_DNS_CACHE_SCOPE_PREFIX}{profile_id}")
}

fn route_for_cache_scope(state: &DnsState, host: &str, cache_scope: &str) -> ResolvedDnsRoute {
    if let Some(profile_id) = cache_scope.strip_prefix(STRICT_DNS_CACHE_SCOPE_PREFIX) {
        return ResolvedDnsRoute {
            profile_id: profile_id.to_string(),
            strict: true,
        };
    }
    state.resolve_route(host)
}

fn default_system_stale_fallback_secs(state: &DnsState) -> u64 {
    state
        .profiles
        .get(SYSTEM_DNS_PROFILE_ID)
        .map(|profile| profile.stale_fallback_secs)
        .unwrap_or_else(default_system_profile_stale_fallback_secs)
}

const fn default_system_profile_stale_fallback_secs() -> u64 {
    86400
}

fn dns_answer_is_trusted(addrs: &[IpAddr], strict: bool) -> bool {
    if addrs.is_empty() {
        return false;
    }
    if strict {
        return true;
    }
    addrs
        .iter()
        .any(|addr| !addr.is_unspecified() && !addr.is_loopback())
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn observation_error_kind(error: &anyhow::Error) -> DnsObservationErrorKind {
    match classify_dns_negative_kind(error) {
        DnsNegativeKind::Nxdomain => DnsObservationErrorKind::Nxdomain,
        DnsNegativeKind::NoRecords => DnsObservationErrorKind::NoRecords,
        DnsNegativeKind::Timeout => DnsObservationErrorKind::Timeout,
        DnsNegativeKind::TemporaryFailure => DnsObservationErrorKind::TemporaryFailure,
    }
}

fn dns_observation_diverged(results: &[DnsProfileObservationResult]) -> bool {
    let mut signatures = HashSet::new();
    for result in results {
        if result.error.is_some() || result.addrs.is_empty() {
            continue;
        }
        let mut addrs = result.addrs.clone();
        addrs.sort();
        addrs.dedup();
        signatures.insert(
            addrs
                .into_iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    signatures.len() > 1
}

fn apply_lazy_dns_manager_policy(config: &mut DnsConfig) {
    config.warm_cache.enabled = true;
    config.warm_cache.max_hosts = config.warm_cache.max_hosts.min(8).max(1);
    config.warm_cache.scan_interval_secs = config.warm_cache.scan_interval_secs.max(300);
    config.warm_cache.refresh_when_ttl_below_secs =
        config.warm_cache.refresh_when_ttl_below_secs.min(60).max(1);
    config.warm_cache.min_hits = 1;
    config.warm_cache.active_within_secs = config.warm_cache.active_within_secs.min(900).max(60);
    config.warm_cache.min_refresh_interval_secs =
        config.warm_cache.min_refresh_interval_secs.max(300);

    config.observation.enabled = true;
    config.observation.max_hosts_per_scan = config.observation.max_hosts_per_scan.min(2).max(1);
    config.observation.min_interval_secs_per_host =
        config.observation.min_interval_secs_per_host.max(1800);
    config.observation.max_profiles_per_host =
        config.observation.max_profiles_per_host.min(3).max(1);

    config.auto_select.enabled = true;
}

fn origin_connect_health_to_snapshot(
    health: &HashMap<String, OriginConnectHealthEntry>,
    now: Instant,
) -> OriginConnectHealthSnapshot {
    let mut entries = health
        .iter()
        .filter_map(|(host, entry)| {
            let last_seen_age_secs = age_secs(now, entry.last_seen);
            if last_seen_age_secs > ORIGIN_CONNECT_HEALTH_IDLE_TTL_SECS {
                return None;
            }

            Some(OriginConnectHealthSnapshotEntry {
                host: host.clone(),
                v4: origin_connect_family_to_snapshot(&entry.v4, now),
                v6: origin_connect_family_to_snapshot(&entry.v6, now),
                last_seen_age_secs,
                last_ip: entry.last_ip,
                last_result: entry.last_result.as_str().to_string(),
                last_connect_ms: entry.last_connect_ms,
                last_dns_a_count: entry.last_dns_a_count,
                last_dns_aaaa_count: entry.last_dns_aaaa_count,
                last_dns_seen_age_secs: entry.last_dns_seen.map(|seen| age_secs(now, seen)),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.last_seen_age_secs);
    entries.truncate(ORIGIN_CONNECT_HEALTH_MAX_HOSTS);
    OriginConnectHealthSnapshot { entries }
}

fn origin_connect_family_to_snapshot(
    family: &OriginConnectFamilyHealth,
    now: Instant,
) -> OriginConnectFamilySnapshot {
    OriginConnectFamilySnapshot {
        success_count: family.success_count,
        fail_count: family.fail_count,
        avg_connect_ms: family.avg_connect_ms,
        last_success_age_secs: family.last_success_at.map(|seen| age_secs(now, seen)),
        last_failure_age_secs: family.last_failure_at.map(|seen| age_secs(now, seen)),
    }
}

fn origin_connect_health_from_snapshot(
    snapshot: OriginConnectHealthSnapshot,
    now: Instant,
) -> HashMap<String, OriginConnectHealthEntry> {
    let mut health = HashMap::new();
    for entry in snapshot.entries {
        let host = normalize_dns_host(&entry.host);
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            continue;
        }
        if entry.last_seen_age_secs > ORIGIN_CONNECT_HEALTH_PERSISTED_LOAD_TTL_SECS {
            continue;
        }

        let restored_last_seen_age = entry
            .last_seen_age_secs
            .min(ORIGIN_CONNECT_HEALTH_PERSISTED_RESTORE_AGE_SECS);
        let last_seen = now
            .checked_sub(Duration::from_secs(restored_last_seen_age))
            .unwrap_or(now);
        let last_dns_seen = entry.last_dns_seen_age_secs.and_then(|age| {
            if age > ORIGIN_CONNECT_HEALTH_PERSISTED_DNS_CONTEXT_TTL_SECS {
                return None;
            }
            let restored_age = age.min(ORIGIN_CONNECT_HEALTH_PERSISTED_RESTORE_AGE_SECS);
            Some(
                now.checked_sub(Duration::from_secs(restored_age))
                    .unwrap_or(now),
            )
        });
        let mut restored = OriginConnectHealthEntry {
            v4: origin_connect_family_from_snapshot(entry.v4, now, entry.last_seen_age_secs),
            v6: origin_connect_family_from_snapshot(entry.v6, now, entry.last_seen_age_secs),
            last_seen,
            last_ip: entry.last_ip,
            last_result: origin_connect_result_from_str(&entry.last_result),
            last_connect_ms: entry.last_connect_ms,
            last_dns_a_count: if last_dns_seen.is_some() {
                entry.last_dns_a_count
            } else {
                0
            },
            last_dns_aaaa_count: if last_dns_seen.is_some() {
                entry.last_dns_aaaa_count
            } else {
                0
            },
            last_dns_seen,
            last_family_preference: AddressFamilyPreference::Neutral,
        };
        if restored.v4.sample_count() == 0 && restored.v6.sample_count() == 0 {
            continue;
        }
        restored.last_family_preference = address_family_preference_from_health(&restored);
        health.insert(host, restored);
        if health.len() >= ORIGIN_CONNECT_HEALTH_MAX_HOSTS {
            break;
        }
    }
    health
}

fn origin_connect_family_from_snapshot(
    snapshot: OriginConnectFamilySnapshot,
    now: Instant,
    entry_age_secs: u64,
) -> OriginConnectFamilyHealth {
    let mut family = OriginConnectFamilyHealth {
        success_count: decay_loaded_origin_connect_samples(snapshot.success_count, entry_age_secs),
        fail_count: decay_loaded_origin_connect_samples(snapshot.fail_count, entry_age_secs),
        avg_connect_ms: snapshot.avg_connect_ms.filter(|value| value.is_finite()),
        last_success_at: snapshot
            .last_success_age_secs
            .map(|age| now.checked_sub(Duration::from_secs(age)).unwrap_or(now)),
        last_failure_at: snapshot
            .last_failure_age_secs
            .map(|age| now.checked_sub(Duration::from_secs(age)).unwrap_or(now)),
    };
    while family.sample_count() > ORIGIN_CONNECT_HEALTH_MAX_SAMPLES_PER_FAMILY {
        family.compact_samples_if_needed();
    }
    family
}

fn decay_loaded_origin_connect_samples(count: u32, entry_age_secs: u64) -> u32 {
    if count == 0 {
        return 0;
    }

    let decay_steps = entry_age_secs / ORIGIN_CONNECT_HEALTH_PERSISTED_SAMPLE_HALF_LIFE_SECS;
    if decay_steps == 0 {
        return count.min(ORIGIN_CONNECT_HEALTH_MAX_SAMPLES_PER_FAMILY);
    }

    let shift = decay_steps.min(31) as u32;
    (count >> shift)
        .max(1)
        .min(ORIGIN_CONNECT_HEALTH_MAX_SAMPLES_PER_FAMILY)
}

fn origin_connect_result_from_str(value: &str) -> OriginConnectResult {
    match value {
        "success" => OriginConnectResult::Success,
        "failure" => OriginConnectResult::Failure,
        _ => OriginConnectResult::None,
    }
}

fn latest_dns_profiles_by_host(
    cache: &HashMap<DnsCacheKey, DnsCacheEntry>,
    now: Instant,
) -> HashMap<String, String> {
    let mut latest = HashMap::<String, (&Instant, &str)>::new();
    for (key, entry) in cache {
        if entry.negative || entry.expires_at <= now {
            continue;
        }

        let replace = latest
            .get(&key.host)
            .map(|(expires_at, _)| entry.expires_at > **expires_at)
            .unwrap_or(true);
        if replace {
            latest.insert(
                key.host.clone(),
                (&entry.expires_at, entry.source_profile_id.as_str()),
            );
        }
    }

    latest
        .into_iter()
        .map(|(host, (_, profile_id))| (host, profile_id.to_string()))
        .collect()
}

fn age_secs(now: Instant, instant: Instant) -> u64 {
    now.saturating_duration_since(instant).as_secs()
}

fn address_family_preference_from_health(
    entry: &OriginConnectHealthEntry,
) -> AddressFamilyPreference {
    let v4_samples = entry.v4.sample_count();
    let v6_samples = entry.v6.sample_count();

    if v4_samples >= ORIGIN_CONNECT_HEALTH_MIN_SAMPLES_PER_FAMILY
        && v6_samples >= ORIGIN_CONNECT_HEALTH_MIN_SAMPLES_PER_FAMILY
    {
        let v4_failure_rate = entry.v4.failure_rate();
        let v6_failure_rate = entry.v6.failure_rate();
        let failure_count_gap = entry.v4.fail_count.abs_diff(entry.v6.fail_count);
        if failure_count_gap >= ORIGIN_CONNECT_HEALTH_FAILURE_COUNT_GAP {
            if v6_failure_rate - v4_failure_rate >= ORIGIN_CONNECT_HEALTH_FAILURE_RATE_GAP {
                return AddressFamilyPreference::PreferIpv4;
            }
            if v4_failure_rate - v6_failure_rate >= ORIGIN_CONNECT_HEALTH_FAILURE_RATE_GAP {
                return AddressFamilyPreference::PreferIpv6;
            }
        }

        if entry.v4.success_count >= ORIGIN_CONNECT_HEALTH_LATENCY_MIN_SUCCESSES_PER_FAMILY
            && entry.v6.success_count >= ORIGIN_CONNECT_HEALTH_LATENCY_MIN_SUCCESSES_PER_FAMILY
        {
            if let (Some(v4_avg), Some(v6_avg)) = (entry.v4.avg_connect_ms, entry.v6.avg_connect_ms)
            {
                if latency_is_meaningfully_faster(v4_avg, v6_avg) {
                    return AddressFamilyPreference::PreferIpv4;
                }
                if latency_is_meaningfully_faster(v6_avg, v4_avg) {
                    return AddressFamilyPreference::PreferIpv6;
                }
            }
        }
    }

    single_family_success_preference(entry).unwrap_or(AddressFamilyPreference::Neutral)
}

fn single_family_success_preference(
    entry: &OriginConnectHealthEntry,
) -> Option<AddressFamilyPreference> {
    if !origin_connect_health_has_dual_stack_context(entry) {
        return None;
    }

    let v4_success = entry.v4.success_count;
    let v6_success = entry.v6.success_count;
    let v4_fail = entry.v4.fail_count;
    let v6_fail = entry.v6.fail_count;

    if v4_success >= ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN
        && v6_success == 0
        && v6_fail == 0
    {
        return Some(AddressFamilyPreference::PreferIpv4);
    }

    if v6_success >= ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN
        && v4_success == 0
        && v4_fail == 0
    {
        return Some(AddressFamilyPreference::PreferIpv6);
    }

    if v4_success >= ORIGIN_CONNECT_HEALTH_MIN_SAMPLES_PER_FAMILY && v6_fail >= 1 && v6_success == 0
    {
        return Some(AddressFamilyPreference::PreferIpv4);
    }

    if v6_success >= ORIGIN_CONNECT_HEALTH_MIN_SAMPLES_PER_FAMILY && v4_fail >= 1 && v4_success == 0
    {
        return Some(AddressFamilyPreference::PreferIpv6);
    }

    None
}

fn origin_connect_health_has_dual_stack_context(entry: &OriginConnectHealthEntry) -> bool {
    (entry.last_dns_a_count > 0 && entry.last_dns_aaaa_count > 0)
        || (entry.v4.sample_count() > 0 && entry.v6.sample_count() > 0)
}

fn latency_is_meaningfully_faster(candidate_ms: f64, other_ms: f64) -> bool {
    other_ms - candidate_ms >= ORIGIN_CONNECT_HEALTH_LATENCY_GAP_MS
        && candidate_ms <= other_ms * ORIGIN_CONNECT_HEALTH_LATENCY_RATIO
}

fn has_both_address_families(addrs: &[IpAddr]) -> bool {
    addrs.iter().any(IpAddr::is_ipv4) && addrs.iter().any(IpAddr::is_ipv6)
}

fn address_matches_family_preference(addr: IpAddr, preference: AddressFamilyPreference) -> bool {
    match preference {
        AddressFamilyPreference::Neutral => false,
        AddressFamilyPreference::PreferIpv4 => addr.is_ipv4(),
        AddressFamilyPreference::PreferIpv6 => addr.is_ipv6(),
    }
}

fn prune_origin_connect_health(
    health: &mut HashMap<String, OriginConnectHealthEntry>,
    now: Instant,
) {
    let ttl = Duration::from_secs(ORIGIN_CONNECT_HEALTH_IDLE_TTL_SECS);
    health.retain(|_, entry| now.duration_since(entry.last_seen) <= ttl);

    if health.len() <= ORIGIN_CONNECT_HEALTH_MAX_HOSTS {
        return;
    }

    let mut entries = health
        .iter()
        .map(|(host, entry)| (host.clone(), entry.last_seen))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, last_seen)| *last_seen);
    let remove_count = entries
        .len()
        .saturating_sub(ORIGIN_CONNECT_HEALTH_MAX_HOSTS);
    for (host, _) in entries.into_iter().take(remove_count) {
        health.remove(&host);
    }
}

impl DnsState {
    fn from_config(mut config: DnsConfig) -> Self {
        apply_lazy_dns_manager_policy(&mut config);
        if config.profiles.is_empty() {
            config.profiles.push(DnsProfileConfig::system());
        }
        let profiles = config
            .profiles
            .iter()
            .cloned()
            .map(|profile| (profile.id.clone(), profile))
            .collect::<HashMap<_, _>>();
        let routes = DnsRouteMatcher::from_config(&config.routes).unwrap_or_else(|error| {
            tracing::warn!(error = %error, "failed to compile DNS routes; DNS routing table disabled");
            DnsRouteMatcher::default()
        });
        Self {
            config,
            profiles,
            routes,
        }
    }

    fn resolve_route(&self, host: &str) -> ResolvedDnsRoute {
        self.routes
            .resolve(host)
            .map(|route| ResolvedDnsRoute {
                profile_id: route.profile_id.clone(),
                strict: route.strict,
            })
            .unwrap_or_else(|| ResolvedDnsRoute {
                profile_id: self.config.default_profile.clone(),
                strict: false,
            })
    }

    #[cfg(test)]
    fn profile_resolution_order(&self, first_profile_id: &str, strict: bool) -> Vec<String> {
        if strict {
            return vec![first_profile_id.to_string()];
        }

        let mut order = Vec::new();
        if first_profile_id != SYSTEM_DNS_PROFILE_ID {
            order.push(first_profile_id.to_string());
        }
        for profile in &self.config.profiles {
            if profile.id == SYSTEM_DNS_PROFILE_ID || profile.id == first_profile_id {
                continue;
            }
            order.push(profile.id.clone());
        }
        order.push(SYSTEM_DNS_PROFILE_ID.to_string());
        order
    }
}

impl DnsRouteMatcher {
    fn from_config(items: &[DnsRouteConfig]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        let mut routes = Vec::new();
        let mut compiled_route_indexes = Vec::new();

        for item in items {
            let route_index = routes.len();
            let host_pattern = normalize_dns_pattern(&item.host_pattern);
            routes.push(DnsRouteEntry {
                profile_id: item.profile_id.clone(),
                strict: item.strict,
                enabled: item.enabled,
            });
            if !item.enabled {
                continue;
            }
            builder.add(Glob::new(&host_pattern).with_context(|| {
                format!(
                    "invalid DNS route host pattern `{}` in route `{}`",
                    item.host_pattern, item.id
                )
            })?);
            compiled_route_indexes.push(route_index);
        }

        let globset = if compiled_route_indexes.is_empty() {
            None
        } else {
            Some(
                builder
                    .build()
                    .context("failed to build DNS route matcher")?,
            )
        };

        Ok(Self {
            routes,
            compiled_route_indexes,
            globset,
        })
    }

    fn resolve(&self, host: &str) -> Option<&DnsRouteEntry> {
        let host = normalize_dns_host(host);
        let globset = self.globset.as_ref()?;
        let matches = globset.matches(&host);
        let first_match = matches.into_iter().min()?;
        let route_index = *self.compiled_route_indexes.get(first_match)?;
        self.routes.get(route_index).filter(|route| route.enabled)
    }
}

pub fn validate_host_pattern(pattern: &str) -> Result<()> {
    let pattern = normalize_dns_pattern(pattern);
    if pattern.is_empty() {
        bail!("host pattern cannot be empty");
    }
    Glob::new(&pattern).with_context(|| format!("invalid host pattern `{pattern}`"))?;
    Ok(())
}

pub fn normalize_dns_host(host: &str) -> String {
    upstream::normalize_host(host)
}

fn normalize_dns_pattern(pattern: &str) -> String {
    pattern.trim().trim_end_matches('.').to_ascii_lowercase()
}

async fn system_resolve_host(host: &str) -> Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("system DNS failed to resolve {host}"))?;
    Ok(addrs.map(|addr| addr.ip()).collect())
}

async fn udp_resolve_host(host: &str, profile: &DnsProfileConfig) -> Result<DnsLookupResult> {
    if profile.servers.is_empty() {
        bail!("DNS profile `{}` has no UDP servers", profile.id);
    }

    let mut output = Vec::new();
    let mut ttl_secs = None;
    let mut first_usable_latency_ms = None;
    for server in &profile.servers {
        let server_addr = server
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid DNS server address `{server}`"))?;
        for _ in 0..profile.attempts.max(1) {
            if let Ok(result) = udp_query_a_aaaa(host, server_addr, profile.timeout_ms).await {
                let DnsLookupResult {
                    addrs,
                    ttl_secs: result_ttl_secs,
                    first_usable_latency_ms: result_first_usable_latency_ms,
                    late_merge,
                } = result;
                first_usable_latency_ms =
                    min_optional_u64(first_usable_latency_ms, result_first_usable_latency_ms);
                output.extend(addrs);
                ttl_secs = min_optional_ttl(ttl_secs, result_ttl_secs);
                output.sort();
                output.dedup();
                if !output.is_empty() {
                    return Ok(DnsLookupResult {
                        addrs: output,
                        ttl_secs,
                        first_usable_latency_ms,
                        late_merge,
                    });
                }
            }
        }
    }

    bail!("all UDP DNS servers failed for {host}")
}

async fn udp_query_a_aaaa(
    host: &str,
    server: SocketAddr,
    timeout_ms: u64,
) -> Result<DnsLookupResult> {
    let (tx, mut rx) = mpsc::channel(2);
    for qtype in [1_u16, 28_u16] {
        let tx = tx.clone();
        let host = host.to_string();
        tokio::spawn(async move {
            let result = udp_query_timed(&host, server, qtype, timeout_ms).await;
            let _ = tx.send(result).await;
        });
    }
    drop(tx);

    let mut completed = Vec::new();
    while let Some(timed) = rx.recv().await {
        match timed.result {
            Ok(mut result) if !result.addrs.is_empty() => {
                result.first_usable_latency_ms = Some(timed.latency_ms);
                result.late_merge = Some(spawn_late_dns_merge_receiver(rx));
                return Ok(result);
            }
            result => completed.push(TimedDnsLookupResult {
                result,
                latency_ms: timed.latency_ms,
            }),
        }
    }

    merge_dns_query_results(completed)
}

fn spawn_late_dns_merge_receiver(mut rx: mpsc::Receiver<TimedDnsLookupResult>) -> DnsLateMerge {
    let (tx, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let mut output = Vec::new();
        let mut ttl_secs = None;
        while let Some(timed) = rx.recv().await {
            if let Ok(result) = timed.result {
                output.extend(result.addrs);
                ttl_secs = min_optional_ttl(ttl_secs, result.ttl_secs);
            }
        }
        output.sort();
        output.dedup();
        let result = (!output.is_empty()).then_some(DnsLateMergeResult {
            addrs: output,
            ttl_secs,
        });
        let _ = tx.send(result);
    });
    DnsLateMerge { receiver }
}

#[derive(Debug)]
struct TimedDnsLookupResult {
    result: Result<DnsLookupResult>,
    latency_ms: u64,
}

async fn udp_query_timed(
    host: &str,
    server: SocketAddr,
    qtype: u16,
    timeout_ms: u64,
) -> TimedDnsLookupResult {
    let started = Instant::now();
    let result = udp_query(host, server, qtype, timeout_ms).await;
    TimedDnsLookupResult {
        result,
        latency_ms: elapsed_millis(started),
    }
}

fn merge_dns_query_results(results: Vec<TimedDnsLookupResult>) -> Result<DnsLookupResult> {
    let mut output = Vec::new();
    let mut ttl_secs = None;
    let mut first_usable_latency_ms = None;
    let mut first_error = None;

    for timed in results {
        match timed.result {
            Ok(result) => {
                if !result.addrs.is_empty() {
                    first_usable_latency_ms =
                        min_optional_u64(first_usable_latency_ms, Some(timed.latency_ms));
                }
                output.extend(result.addrs);
                ttl_secs = min_optional_ttl(ttl_secs, result.ttl_secs);
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    output.sort();
    output.dedup();
    if !output.is_empty() {
        return Ok(DnsLookupResult {
            addrs: output,
            ttl_secs,
            first_usable_latency_ms,
            late_merge: None,
        });
    }

    if let Some(error) = first_error {
        return Err(error);
    }

    Ok(DnsLookupResult {
        addrs: output,
        ttl_secs,
        first_usable_latency_ms: None,
        late_merge: None,
    })
}

async fn udp_query(
    host: &str,
    server: SocketAddr,
    qtype: u16,
    timeout_ms: u64,
) -> Result<DnsLookupResult> {
    let socket = UdpSocket::bind(match server {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .await?;
    let id = dns_query_id(host, qtype);
    let query = build_dns_query(host, qtype, id)?;
    socket.send_to(&query, server).await?;

    let mut buffer = [0_u8; 1500];
    let (len, _) = tokio::time::timeout(
        Duration::from_millis(timeout_ms.max(1)),
        socket.recv_from(&mut buffer),
    )
    .await
    .context("DNS UDP query timed out")??;
    parse_dns_response(&buffer[..len], id, qtype)
}

fn build_dns_query(host: &str, qtype: u16, id: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label in host `{host}`");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    Ok(out)
}

fn parse_dns_response(bytes: &[u8], expected_id: u16, qtype: u16) -> Result<DnsLookupResult> {
    if bytes.len() < 12 {
        bail!("DNS response too short");
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != expected_id {
        bail!("DNS response ID mismatch");
    }
    let rcode = bytes[3] & 0x0f;
    match rcode {
        0 => {}
        3 => bail!("DNS response returned NXDOMAIN"),
        2 => bail!("DNS response returned SERVFAIL"),
        _ => bail!("DNS response returned error code {rcode}"),
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        skip_dns_name(bytes, &mut pos)?;
        pos += 4;
        if pos > bytes.len() {
            bail!("DNS response question is truncated");
        }
    }

    let mut addrs = Vec::new();
    let mut ttl_secs = None;
    for _ in 0..ancount {
        skip_dns_name(bytes, &mut pos)?;
        if pos + 10 > bytes.len() {
            bail!("DNS answer is truncated");
        }
        let answer_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let class = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]);
        let answer_ttl_secs = u32::from_be_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as u64;
        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > bytes.len() {
            bail!("DNS answer data is truncated");
        }
        if class == 1 && answer_type == qtype {
            let before_len = addrs.len();
            match (answer_type, rdlen) {
                (1, 4) => addrs.push(IpAddr::from([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ])),
                (28, 16) => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&bytes[pos..pos + 16]);
                    addrs.push(IpAddr::from(octets));
                }
                _ => {}
            }
            if addrs.len() != before_len {
                ttl_secs = min_optional_ttl(ttl_secs, Some(answer_ttl_secs));
            }
        }
        pos += rdlen;
    }
    Ok(DnsLookupResult {
        addrs,
        ttl_secs,
        first_usable_latency_ms: None,
        late_merge: None,
    })
}

fn skip_dns_name(bytes: &[u8], pos: &mut usize) -> Result<()> {
    let mut jumps = 0;
    loop {
        if *pos >= bytes.len() {
            bail!("DNS name is truncated");
        }
        let len = bytes[*pos];
        if len & 0xc0 == 0xc0 {
            if *pos + 1 >= bytes.len() {
                bail!("DNS compressed name is truncated");
            }
            *pos += 2;
            return Ok(());
        }
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        *pos += 1 + len as usize;
        jumps += 1;
        if jumps > 128 {
            bail!("DNS name is too deep");
        }
    }
}

fn dns_query_id(host: &str, qtype: u16) -> u16 {
    let mut value = qtype ^ 0x5247;
    for byte in host.as_bytes() {
        value = value.rotate_left(5) ^ *byte as u16;
    }
    value
}

fn classify_dns_negative_kind(error: &anyhow::Error) -> DnsNegativeKind {
    let message = error
        .chain()
        .map(|cause| cause.to_string().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" | ");
    if message.contains("nxdomain")
        || message.contains("no such host")
        || message.contains("name or service not known")
        || message.contains("nodename nor servname")
    {
        return DnsNegativeKind::Nxdomain;
    }
    if message.contains("timed out") || message.contains("timeout") || message.contains("10060") {
        return DnsNegativeKind::Timeout;
    }
    DnsNegativeKind::TemporaryFailure
}

fn negative_cache_ttl_secs(host: &str, kind: DnsNegativeKind) -> u64 {
    let ttl_secs = match kind {
        DnsNegativeKind::Nxdomain => NEGATIVE_DNS_TTL_NXDOMAIN_SECS,
        DnsNegativeKind::NoRecords => NEGATIVE_DNS_TTL_NO_RECORDS_SECS,
        DnsNegativeKind::Timeout | DnsNegativeKind::TemporaryFailure => {
            NEGATIVE_DNS_TTL_TEMPORARY_SECS
        }
    };

    if is_ephemeral_dns_host(host) {
        ttl_secs.min(NEGATIVE_DNS_TTL_EPHEMERAL_HOST_SECS)
    } else {
        ttl_secs
    }
}

pub(crate) fn is_ephemeral_dns_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    const EPHEMERAL_SUFFIXES: &[&str] = &[
        ".googlevideo.com",
        ".cloudfront.net",
        ".akamaized.net",
        ".akamaihd.net",
        ".akadns.net",
        ".fastly.net",
        ".fastlylb.net",
        ".cdn77.org",
    ];
    EPHEMERAL_SUFFIXES
        .iter()
        .any(|suffix| host.ends_with(suffix))
}

fn positive_cache_ttl_secs(
    host: &str,
    profile: &DnsProfileConfig,
    answer_ttl_secs: Option<u64>,
) -> u64 {
    let min_ttl = profile
        .cache_ttl_min_secs
        .min(profile.cache_ttl_max_secs)
        .max(1);
    let max_ttl = profile
        .cache_ttl_max_secs
        .max(profile.cache_ttl_min_secs)
        .max(min_ttl);
    let ttl = answer_ttl_secs.unwrap_or(max_ttl).clamp(min_ttl, max_ttl);
    cap_ephemeral_positive_ttl_secs(host, ttl)
}

fn cap_ephemeral_positive_ttl_secs(host: &str, ttl_secs: u64) -> u64 {
    if is_ephemeral_dns_host(host) {
        ttl_secs.min(POSITIVE_DNS_TTL_EPHEMERAL_HOST_MAX_SECS)
    } else {
        ttl_secs
    }
}

fn positive_stale_fallback_secs(host: &str, stale_fallback_secs: u64) -> u64 {
    if is_ephemeral_dns_host(host) {
        0
    } else {
        stale_fallback_secs
    }
}

fn min_optional_ttl(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    min_optional_u64(left, right)
}

fn min_optional_u64(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn remaining_secs(now: Instant, expires_at: Instant) -> u64 {
    expires_at
        .checked_duration_since(now)
        .unwrap_or_default()
        .as_secs()
}

fn prune_expired_locked(cache: &mut HashMap<DnsCacheKey, DnsCacheEntry>, now: Instant) -> bool {
    let before = cache.len();
    cache.retain(|_, entry| {
        if entry.negative {
            now <= entry.expires_at
        } else {
            now <= entry.stale_until
        }
    });
    cache.len() != before
}

fn evict_one_cache_entry(cache: &mut HashMap<DnsCacheKey, DnsCacheEntry>) {
    let Some(key) = cache
        .iter()
        .min_by_key(|(_, entry)| {
            if entry.negative {
                entry.expires_at
            } else {
                entry.stale_until
            }
        })
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    cache.remove(&key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_route_uses_first_matching_glob() {
        let config = DnsConfig {
            enabled: true,
            default_profile: "system".to_string(),
            max_cache_entries: 10_000,
            stale_while_revalidate: true,
            refresh_before_expire_secs: 60,
            warm_cache: Default::default(),
            observation: Default::default(),
            auto_select: Default::default(),
            profiles: vec![
                DnsProfileConfig::system(),
                DnsProfileConfig {
                    id: "primary".to_string(),
                    mode: DnsProfileMode::Udp,
                    servers: vec!["1.1.1.1:53".to_string()],
                    enabled: true,
                    timeout_ms: 2000,
                    attempts: 2,
                    cache_ttl_min_secs: 300,
                    cache_ttl_max_secs: 86400,
                    negative_ttl_secs: 30,
                    stale_fallback_secs: 86400,
                    fallback_profiles: Vec::new(),
                },
            ],
            routes: vec![DnsRouteConfig {
                id: "route-example".to_string(),
                host_pattern: "*.example.com".to_string(),
                profile_id: "primary".to_string(),
                strict: true,
                enabled: true,
            }],
        };
        let state = DnsState::from_config(config);
        let route = state.resolve_route("www.example.com");

        assert_eq!(route.profile_id, "primary");
    }

    #[test]
    fn validates_dns_host_patterns() {
        assert!(validate_host_pattern("*.example.com").is_ok());
        assert!(validate_host_pattern("").is_err());
    }

    #[test]
    fn merges_parallel_a_aaaa_results_with_fastest_usable_latency() {
        let merged = merge_dns_query_results(vec![
            TimedDnsLookupResult {
                result: Ok(DnsLookupResult {
                    addrs: vec!["93.184.216.34".parse().unwrap()],
                    ttl_secs: Some(120),
                    first_usable_latency_ms: None,
                    late_merge: None,
                }),
                latency_ms: 30,
            },
            TimedDnsLookupResult {
                result: Ok(DnsLookupResult {
                    addrs: vec!["2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()],
                    ttl_secs: Some(60),
                    first_usable_latency_ms: None,
                    late_merge: None,
                }),
                latency_ms: 10,
            },
        ])
        .unwrap();

        assert_eq!(merged.addrs.len(), 2);
        assert_eq!(merged.ttl_secs, Some(60));
        assert_eq!(merged.first_usable_latency_ms, Some(10));
    }

    #[test]
    fn merge_parallel_a_aaaa_accepts_single_family_success() {
        let merged = merge_dns_query_results(vec![
            TimedDnsLookupResult {
                result: Ok(DnsLookupResult {
                    addrs: vec!["93.184.216.34".parse().unwrap()],
                    ttl_secs: Some(120),
                    first_usable_latency_ms: None,
                    late_merge: None,
                }),
                latency_ms: 12,
            },
            TimedDnsLookupResult {
                result: Err(anyhow::anyhow!("AAAA lookup failed")),
                latency_ms: 200,
            },
        ])
        .unwrap();

        assert_eq!(
            merged.addrs,
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(merged.ttl_secs, Some(120));
        assert_eq!(merged.first_usable_latency_ms, Some(12));
    }

    #[test]
    fn strict_dns_route_does_not_add_fallback_profiles() {
        let config = DnsConfig {
            enabled: true,
            default_profile: "system".to_string(),
            max_cache_entries: 10_000,
            stale_while_revalidate: true,
            refresh_before_expire_secs: 60,
            warm_cache: Default::default(),
            observation: Default::default(),
            auto_select: Default::default(),
            profiles: vec![
                DnsProfileConfig::system(),
                DnsProfileConfig {
                    id: "primary".to_string(),
                    mode: DnsProfileMode::Udp,
                    servers: vec!["1.1.1.1:53".to_string()],
                    enabled: true,
                    timeout_ms: 2000,
                    attempts: 2,
                    cache_ttl_min_secs: 300,
                    cache_ttl_max_secs: 86400,
                    negative_ttl_secs: 30,
                    stale_fallback_secs: 86400,
                    fallback_profiles: Vec::new(),
                },
                DnsProfileConfig {
                    id: "backup".to_string(),
                    mode: DnsProfileMode::Udp,
                    servers: vec!["8.8.8.8:53".to_string()],
                    enabled: true,
                    timeout_ms: 2000,
                    attempts: 2,
                    cache_ttl_min_secs: 300,
                    cache_ttl_max_secs: 86400,
                    negative_ttl_secs: 30,
                    stale_fallback_secs: 86400,
                    fallback_profiles: Vec::new(),
                },
            ],
            routes: vec![DnsRouteConfig {
                id: "strict-example".to_string(),
                host_pattern: "*.example.com".to_string(),
                profile_id: "primary".to_string(),
                strict: true,
                enabled: true,
            }],
        };
        let state = DnsState::from_config(config);
        let route = state.resolve_route("www.example.com");

        assert!(route.strict);
        assert_eq!(
            state.profile_resolution_order(&route.profile_id, route.strict),
            vec!["primary"]
        );
    }

    #[test]
    fn dns_server_ingress_excludes_system_profile() {
        let config = DnsConfig {
            enabled: true,
            default_profile: "system".to_string(),
            max_cache_entries: 10_000,
            stale_while_revalidate: true,
            refresh_before_expire_secs: 60,
            warm_cache: Default::default(),
            observation: Default::default(),
            auto_select: Default::default(),
            profiles: vec![
                DnsProfileConfig::system(),
                DnsProfileConfig {
                    id: "cloudflare".to_string(),
                    mode: DnsProfileMode::Udp,
                    servers: vec!["1.1.1.1:53".to_string()],
                    enabled: true,
                    timeout_ms: 2000,
                    attempts: 2,
                    cache_ttl_min_secs: 300,
                    cache_ttl_max_secs: 86400,
                    negative_ttl_secs: 30,
                    stale_fallback_secs: 86400,
                    fallback_profiles: Vec::new(),
                },
            ],
            routes: Vec::new(),
        };
        let resolver = RelayGateDnsResolver::new(config.clone());
        let state = DnsState::from_config(config);
        let route = state.resolve_route("www.example.com");

        let selected = resolver
            .select_racing_profiles(
                &state,
                "www.example.com",
                &route,
                DnsResolveIngress::DnsServer,
            )
            .into_iter()
            .map(|profile| profile.id)
            .collect::<Vec<_>>();

        assert_eq!(selected, vec!["cloudflare"]);
    }

    #[test]
    fn dns_server_ingress_has_no_system_only_candidate() {
        let config = DnsConfig {
            enabled: true,
            default_profile: "system".to_string(),
            max_cache_entries: 10_000,
            stale_while_revalidate: true,
            refresh_before_expire_secs: 60,
            warm_cache: Default::default(),
            observation: Default::default(),
            auto_select: Default::default(),
            profiles: vec![DnsProfileConfig::system()],
            routes: Vec::new(),
        };
        let resolver = RelayGateDnsResolver::new(config.clone());
        let state = DnsState::from_config(config);
        let route = state.resolve_route("www.example.com");

        let selected = resolver.select_racing_profiles(
            &state,
            "www.example.com",
            &route,
            DnsResolveIngress::DnsServer,
        );

        assert!(selected.is_empty());
    }

    #[test]
    fn proxy_internal_applies_origin_family_preference_to_dns_order() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "dual.example";
        let dns_addrs = vec![
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ];

        resolver.seed_origin_dns_observed_for_test(
            host,
            DnsResolveIngress::ProxyInternal,
            &dns_addrs,
        );
        for _ in 0..ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN {
            resolver.record_origin_connect_success_observed(
                host,
                "192.0.2.1".parse::<IpAddr>().unwrap(),
            );
        }

        let ordered = resolver.apply_address_family_preference_for_ingress(
            host,
            DnsResolveIngress::ProxyInternal,
            dns_addrs.clone(),
        );

        assert!(ordered[0].is_ipv4());
        assert!(ordered[1].is_ipv6());
    }

    #[test]
    fn dns_server_ingress_does_not_apply_proxy_origin_family_preference() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "dual.example";
        let dns_addrs = vec![
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ];

        resolver.seed_origin_dns_observed_for_test(
            host,
            DnsResolveIngress::ProxyInternal,
            &dns_addrs,
        );
        for _ in 0..ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN {
            resolver.record_origin_connect_success_observed(
                host,
                "192.0.2.1".parse::<IpAddr>().unwrap(),
            );
        }

        let ordered = resolver.apply_address_family_preference_for_ingress(
            host,
            DnsResolveIngress::DnsServer,
            dns_addrs.clone(),
        );

        assert_eq!(ordered, dns_addrs);
    }

    #[test]
    fn dns_observation_without_connect_does_not_create_connection_info_row() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        resolver.clear_origin_connect_health_for_test();
        let host = "dns-only.example";
        let dns_addrs = vec![
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ];

        resolver.record_origin_dns_observed(host, DnsResolveIngress::ProxyInternal, &dns_addrs);

        assert!(resolver.connection_info_snapshot().items.is_empty());
        assert_eq!(
            resolver.address_family_preference(host),
            AddressFamilyPreference::Neutral
        );
    }

    #[test]
    fn repeated_same_dns_context_does_not_dirty_origin_health_snapshot() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "stable-dual.example";
        let dual_stack_addrs = vec![
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ];
        let v4_only_addrs = vec!["192.0.2.1".parse::<IpAddr>().unwrap()];

        resolver
            .record_origin_connect_success_observed(host, "192.0.2.1".parse::<IpAddr>().unwrap());
        resolver
            .origin_connect_health_dirty
            .store(false, Ordering::Release);

        resolver.record_origin_dns_observed(
            host,
            DnsResolveIngress::ProxyInternal,
            &dual_stack_addrs,
        );
        assert!(resolver.origin_connect_health_dirty.load(Ordering::Acquire));

        resolver
            .origin_connect_health_dirty
            .store(false, Ordering::Release);
        resolver.record_origin_dns_observed(
            host,
            DnsResolveIngress::ProxyInternal,
            &dual_stack_addrs,
        );
        assert!(!resolver.origin_connect_health_dirty.load(Ordering::Acquire));

        resolver.record_origin_dns_observed(host, DnsResolveIngress::ProxyInternal, &v4_only_addrs);
        assert!(resolver.origin_connect_health_dirty.load(Ordering::Acquire));
    }

    #[test]
    fn single_stack_dns_does_not_create_origin_family_preference() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "v4-only.example";
        let dns_addrs = vec!["192.0.2.1".parse::<IpAddr>().unwrap()];

        resolver.seed_origin_dns_observed_for_test(
            host,
            DnsResolveIngress::ProxyInternal,
            &dns_addrs,
        );
        for _ in 0..ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN {
            resolver.record_origin_connect_success_observed(
                host,
                "192.0.2.1".parse::<IpAddr>().unwrap(),
            );
        }

        assert_eq!(
            resolver.address_family_preference(host),
            AddressFamilyPreference::Neutral
        );
    }

    #[test]
    fn dns_server_observation_does_not_create_origin_family_preference() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "dns-server-client.example";
        let dns_addrs = vec![
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ];

        resolver.seed_origin_dns_observed_for_test(host, DnsResolveIngress::DnsServer, &dns_addrs);
        for _ in 0..ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN {
            resolver.record_origin_connect_success_observed(
                host,
                "192.0.2.1".parse::<IpAddr>().unwrap(),
            );
        }

        assert_eq!(
            resolver.address_family_preference(host),
            AddressFamilyPreference::Neutral
        );
    }

    #[test]
    fn low_pure_single_family_success_does_not_create_preference() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "low-observed-v4.example";
        let dns_addrs = vec![
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ];

        resolver.seed_origin_dns_observed_for_test(
            host,
            DnsResolveIngress::ProxyInternal,
            &dns_addrs,
        );
        for _ in 0..(ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN - 1) {
            resolver.record_origin_connect_success_observed(
                host,
                "192.0.2.1".parse::<IpAddr>().unwrap(),
            );
        }

        assert_eq!(
            resolver.address_family_preference(host),
            AddressFamilyPreference::Neutral
        );
    }

    #[test]
    fn failure_assisted_single_family_success_can_create_preference_sooner() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "v6-fails-v4-succeeds.example";
        let dns_addrs = vec![
            "2001:db8::1".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ];

        resolver.seed_origin_dns_observed_for_test(
            host,
            DnsResolveIngress::ProxyInternal,
            &dns_addrs,
        );
        resolver.record_origin_connect_failures(
            host,
            &[SocketAddr::new(
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                443,
            )],
        );
        for _ in 0..ORIGIN_CONNECT_HEALTH_MIN_SAMPLES_PER_FAMILY {
            resolver.record_origin_connect_success_observed(
                host,
                "192.0.2.1".parse::<IpAddr>().unwrap(),
            );
        }

        assert_eq!(
            resolver.address_family_preference(host),
            AddressFamilyPreference::PreferIpv4
        );
    }

    #[test]
    fn observed_dual_family_connect_results_can_create_preference_without_dns_row() {
        let resolver = RelayGateDnsResolver::new(DnsConfig::default());
        let host = "v6-fails-v4-succeeds-without-dns-row.example";

        resolver.record_origin_connect_failures(
            host,
            &[SocketAddr::new(
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                443,
            )],
        );
        for _ in 0..ORIGIN_CONNECT_HEALTH_MIN_SAMPLES_PER_FAMILY {
            resolver.record_origin_connect_success_observed(
                host,
                "192.0.2.1".parse::<IpAddr>().unwrap(),
            );
        }

        assert_eq!(
            resolver.address_family_preference(host),
            AddressFamilyPreference::PreferIpv4
        );
    }

    #[test]
    fn persisted_origin_health_restores_recent_stale_entries_with_decay() {
        let now = Instant::now();
        let host = "persisted-dual.example";
        let snapshot = OriginConnectHealthSnapshot {
            entries: vec![OriginConnectHealthSnapshotEntry {
                host: host.to_string(),
                v4: OriginConnectFamilySnapshot {
                    success_count: 64,
                    fail_count: 0,
                    avg_connect_ms: Some(25.0),
                    last_success_age_secs: Some(2 * 24 * 60 * 60),
                    last_failure_age_secs: None,
                },
                v6: OriginConnectFamilySnapshot {
                    success_count: 0,
                    fail_count: 64,
                    avg_connect_ms: None,
                    last_success_age_secs: None,
                    last_failure_age_secs: Some(2 * 24 * 60 * 60),
                },
                last_seen_age_secs: 2 * 24 * 60 * 60,
                last_ip: Some("192.0.2.1".parse::<IpAddr>().unwrap()),
                last_result: "success".to_string(),
                last_connect_ms: None,
                last_dns_a_count: 1,
                last_dns_aaaa_count: 1,
                last_dns_seen_age_secs: Some(2 * 24 * 60 * 60),
            }],
        };

        let health = origin_connect_health_from_snapshot(snapshot, now);
        let entry = health.get(host).expect("entry should be restored");

        assert!(
            now.duration_since(entry.last_seen)
                <= Duration::from_secs(ORIGIN_CONNECT_HEALTH_PERSISTED_RESTORE_AGE_SECS)
        );
        assert!(entry.v4.success_count < 64);
        assert!(entry.v4.success_count >= 1);
        assert!(entry.v6.fail_count < 64);
        assert!(entry.v6.fail_count >= 1);
        assert_eq!(entry.last_dns_a_count, 0);
        assert_eq!(entry.last_dns_aaaa_count, 0);
        assert!(entry.last_dns_seen.is_none());
    }

    #[test]
    fn stale_persisted_dns_context_does_not_enable_single_family_preference() {
        let now = Instant::now();
        let host = "stale-dns-context.example";
        let snapshot = OriginConnectHealthSnapshot {
            entries: vec![OriginConnectHealthSnapshotEntry {
                host: host.to_string(),
                v4: OriginConnectFamilySnapshot {
                    success_count: ORIGIN_CONNECT_HEALTH_SINGLE_FAMILY_SUCCESS_MIN * 4,
                    fail_count: 0,
                    avg_connect_ms: None,
                    last_success_age_secs: Some(2 * 24 * 60 * 60),
                    last_failure_age_secs: None,
                },
                v6: OriginConnectFamilySnapshot::default(),
                last_seen_age_secs: 2 * 24 * 60 * 60,
                last_ip: Some("192.0.2.1".parse::<IpAddr>().unwrap()),
                last_result: "success".to_string(),
                last_connect_ms: None,
                last_dns_a_count: 1,
                last_dns_aaaa_count: 1,
                last_dns_seen_age_secs: Some(2 * 24 * 60 * 60),
            }],
        };

        let health = origin_connect_health_from_snapshot(snapshot, now);
        let entry = health.get(host).expect("entry should be restored");

        assert_eq!(entry.last_dns_a_count, 0);
        assert_eq!(entry.last_dns_aaaa_count, 0);
        assert_eq!(
            address_family_preference_from_health(entry),
            AddressFamilyPreference::Neutral
        );
    }

    #[test]
    fn persisted_origin_health_drops_entries_beyond_load_ttl() {
        let now = Instant::now();
        let snapshot = OriginConnectHealthSnapshot {
            entries: vec![OriginConnectHealthSnapshotEntry {
                host: "expired-persisted.example".to_string(),
                v4: OriginConnectFamilySnapshot {
                    success_count: 8,
                    fail_count: 0,
                    avg_connect_ms: None,
                    last_success_age_secs: Some(8 * 24 * 60 * 60),
                    last_failure_age_secs: None,
                },
                v6: OriginConnectFamilySnapshot::default(),
                last_seen_age_secs: ORIGIN_CONNECT_HEALTH_PERSISTED_LOAD_TTL_SECS + 1,
                last_ip: Some("192.0.2.1".parse::<IpAddr>().unwrap()),
                last_result: "success".to_string(),
                last_connect_ms: None,
                last_dns_a_count: 1,
                last_dns_aaaa_count: 1,
                last_dns_seen_age_secs: Some(8 * 24 * 60 * 60),
            }],
        };

        let health = origin_connect_health_from_snapshot(snapshot, now);

        assert!(health.is_empty());
    }

    #[test]
    fn negative_cache_policy_uses_short_ttl_for_transient_failures() {
        assert_eq!(
            negative_cache_ttl_secs(
                "rr4---sn-5hnekn7k.googlevideo.com",
                DnsNegativeKind::Timeout
            ),
            1
        );
        assert_eq!(
            negative_cache_ttl_secs("example.invalid", DnsNegativeKind::Nxdomain),
            8
        );
        assert_eq!(
            negative_cache_ttl_secs("api.example.com", DnsNegativeKind::TemporaryFailure),
            2
        );
    }

    #[test]
    fn positive_cache_policy_caps_ephemeral_hosts() {
        let profile = DnsProfileConfig {
            cache_ttl_min_secs: 300,
            cache_ttl_max_secs: 86400,
            ..DnsProfileConfig::system()
        };

        assert_eq!(
            positive_cache_ttl_secs("rr4---sn.example.googlevideo.com", &profile, Some(3600),),
            POSITIVE_DNS_TTL_EPHEMERAL_HOST_MAX_SECS
        );
        assert_eq!(
            positive_stale_fallback_secs("rr4---sn.example.googlevideo.com", 86400),
            0
        );
    }

    #[test]
    fn classifies_dns_negative_error_kind() {
        assert_eq!(
            classify_dns_negative_kind(&anyhow::anyhow!("DNS response returned NXDOMAIN")),
            DnsNegativeKind::Nxdomain
        );
        assert_eq!(
            classify_dns_negative_kind(&anyhow::anyhow!("DNS UDP query timed out")),
            DnsNegativeKind::Timeout
        );
    }

    #[test]
    fn parses_dns_a_response() {
        let id = 0x1234;
        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        response.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        response.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[93, 184, 216, 34]);

        let result = parse_dns_response(&response, id, 1).unwrap();

        assert_eq!(result.addrs, vec![IpAddr::from([93, 184, 216, 34])]);
        assert_eq!(result.ttl_secs, Some(60));
    }
}
