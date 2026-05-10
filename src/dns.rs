use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::net::UdpSocket;

use crate::{
    config::{DnsConfig, DnsProfileConfig, DnsProfileMode, DnsRouteConfig},
    proxy::upstream,
};

pub type SharedDnsResolver = Arc<RelayGateDnsResolver>;

pub fn shared_from_config(config: DnsConfig) -> SharedDnsResolver {
    Arc::new(RelayGateDnsResolver::new(config))
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
const SYSTEM_DNS_PROFILE_ID: &str = "system";

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
    refreshing: Arc<RwLock<HashSet<DnsCacheKey>>>,
    negative_failures: Arc<RwLock<HashMap<DnsCacheKey, NegativeDnsFailureState>>>,
}

#[derive(Clone)]
struct DnsState {
    config: DnsConfig,
    profiles: HashMap<String, DnsProfileConfig>,
    routes: DnsRouteMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DnsCacheKey {
    pub(crate) profile_id: String,
    pub(crate) host: String,
}

#[derive(Debug, Clone)]
pub(crate) struct DnsCacheEntry {
    pub(crate) addrs: Vec<IpAddr>,
    pub(crate) expires_at: Instant,
    pub(crate) stale_until: Instant,
    pub(crate) negative: bool,
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
}

impl DnsRefreshReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::BeforeExpire => "before_expire",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone)]
struct DnsLookupResult {
    addrs: Vec<IpAddr>,
    ttl_secs: Option<u64>,
}

impl DnsLookupResult {
    fn without_ttl(addrs: Vec<IpAddr>) -> Self {
        Self {
            addrs,
            ttl_secs: None,
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedDnsRoute {
    profile_id: String,
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
    enabled: bool,
}

impl RelayGateDnsResolver {
    pub fn new(config: DnsConfig) -> Self {
        let state = DnsState::from_config(config);
        let cache = crate::dns_cache_store::load_cache(state.config.max_cache_entries);
        Self {
            state: Arc::new(RwLock::new(state)),
            cache: Arc::new(RwLock::new(cache)),
            refreshing: Arc::new(RwLock::new(HashSet::new())),
            negative_failures: Arc::new(RwLock::new(HashMap::new())),
        }
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
        crate::dns_cache_store::save_cache(&HashMap::new());
        self.refreshing
            .write()
            .map_err(|_| anyhow::anyhow!("DNS refresh lock poisoned"))?
            .clear();
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

    pub async fn resolve_socket_addrs(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let ips = self.resolve_host(host).await?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    pub async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>> {
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
            return system_resolve_host(&host).await;
        }

        self.resolve_with_profile_order(&state, &host, &route.profile_id)
            .await
    }

    async fn resolve_with_profile_order(
        &self,
        state: &DnsState,
        host: &str,
        first_profile_id: &str,
    ) -> Result<Vec<IpAddr>> {
        let mut visited = HashSet::new();
        for profile_id in state.profile_resolution_order(first_profile_id) {
            if !visited.insert(profile_id.clone()) {
                continue;
            }
            let Some(profile) = state
                .profiles
                .get(&profile_id)
                .filter(|profile| profile.enabled)
            else {
                continue;
            };
            if let Ok(addrs) = self
                .resolve_with_profile(host, profile, &state.config)
                .await
            {
                if !addrs.is_empty() {
                    return Ok(addrs);
                }
            }
        }

        system_resolve_host(host).await
    }

    async fn resolve_with_profile(
        &self,
        host: &str,
        profile: &DnsProfileConfig,
        config: &DnsConfig,
    ) -> Result<Vec<IpAddr>> {
        let lookup = self.cache_lookup(host, profile, config)?;
        match lookup.lookup {
            DnsCacheLookup::Hit(addrs) => {
                if let Some(reason) = lookup.refresh {
                    self.schedule_refresh(
                        host,
                        profile,
                        config.max_cache_entries,
                        reason,
                        lookup.stale_remaining_secs,
                    );
                }
                return Ok(addrs);
            }
            DnsCacheLookup::Negative => return Ok(Vec::new()),
            DnsCacheLookup::Miss => {}
        }

        let result = match profile.mode {
            DnsProfileMode::System => system_resolve_host(host)
                .await
                .map(DnsLookupResult::without_ttl),
            DnsProfileMode::Udp => udp_resolve_host(host, profile).await,
        };

        match result {
            Ok(result) if !result.addrs.is_empty() => {
                let addrs = result.addrs;
                let ttl_secs = positive_cache_ttl_secs(profile, result.ttl_secs);
                self.cache_store_positive(
                    host,
                    profile,
                    addrs.clone(),
                    ttl_secs,
                    config.max_cache_entries,
                )?;
                Ok(addrs)
            }
            Ok(_) => {
                self.cache_store_negative(
                    host,
                    profile,
                    config.max_cache_entries,
                    DnsNegativeKind::NoRecords,
                )?;
                Ok(Vec::new())
            }
            Err(error) => {
                let negative_kind = classify_dns_negative_kind(&error);
                self.cache_store_negative(host, profile, config.max_cache_entries, negative_kind)?;
                Err(error)
            }
        }
    }

    fn cache_lookup(
        &self,
        host: &str,
        profile: &DnsProfileConfig,
        config: &DnsConfig,
    ) -> Result<DnsCacheLookupOutcome> {
        let key = DnsCacheKey {
            profile_id: profile.id.clone(),
            host: host.to_string(),
        };
        let now = Instant::now();
        let mut cache = self
            .cache
            .write()
            .map_err(|_| anyhow::anyhow!("DNS cache lock poisoned"))?;
        let Some(entry) = cache.get(&key) else {
            tracing::debug!(
                dns_cache = "miss",
                profile_id = %profile.id,
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
                if !entry.addrs.is_empty() && now <= entry.stale_until {
                    tracing::debug!(
                        dns_cache = "negative_stale_hit",
                        profile_id = %profile.id,
                        host = %host,
                        ttl_secs,
                        stale_remaining_secs,
                        "DNS negative cache hit; serving stale positive address"
                    );
                    return Ok(DnsCacheLookupOutcome {
                        lookup: DnsCacheLookup::Hit(entry.addrs.clone()),
                        refresh: None,
                        stale_remaining_secs,
                    });
                }

                tracing::debug!(
                    dns_cache = "negative",
                    profile_id = %profile.id,
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
                profile_id = %profile.id,
                host = %host,
                ttl_secs = 0_u64,
                stale_remaining_secs = 0_u64,
                "DNS negative cache entry expired"
            );
            cache.remove(&key);
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
                && config.refresh_before_expire_secs > 0
                && ttl_secs <= config.refresh_before_expire_secs
            {
                tracing::debug!(
                    dns_cache = "stale_refreshing",
                    profile_id = %profile.id,
                    host = %host,
                    ttl_secs,
                    stale_remaining_secs,
                    "DNS cache hit near expiry; serving cached address and scheduling refresh"
                );
                return Ok(DnsCacheLookupOutcome {
                    lookup: DnsCacheLookup::Hit(entry.addrs.clone()),
                    refresh: Some(DnsRefreshReason::BeforeExpire),
                    stale_remaining_secs,
                });
            }

            tracing::debug!(
                dns_cache = "hit",
                profile_id = %profile.id,
                host = %host,
                ttl_secs,
                stale_remaining_secs,
                "DNS cache hit"
            );
            return Ok(DnsCacheLookupOutcome {
                lookup: DnsCacheLookup::Hit(entry.addrs.clone()),
                refresh: None,
                stale_remaining_secs,
            });
        }

        if config.stale_while_revalidate && now <= entry.stale_until {
            let stale_remaining_secs = remaining_secs(now, entry.stale_until);
            tracing::debug!(
                dns_cache = "stale_refreshing",
                profile_id = %profile.id,
                host = %host,
                ttl_secs = 0_u64,
                stale_remaining_secs,
                "DNS cache stale hit; serving stale address and scheduling refresh"
            );
            return Ok(DnsCacheLookupOutcome {
                lookup: DnsCacheLookup::Hit(entry.addrs.clone()),
                refresh: Some(DnsRefreshReason::Stale),
                stale_remaining_secs,
            });
        }

        tracing::debug!(
            dns_cache = "stale",
            profile_id = %profile.id,
            host = %host,
            ttl_secs = 0_u64,
            stale_remaining_secs = 0_u64,
            "DNS cache entry expired"
        );
        cache.remove(&key);
        Ok(DnsCacheLookupOutcome {
            lookup: DnsCacheLookup::Miss,
            refresh: None,
            stale_remaining_secs: 0,
        })
    }

    fn schedule_refresh(
        &self,
        host: &str,
        profile: &DnsProfileConfig,
        max_cache_entries: usize,
        reason: DnsRefreshReason,
        stale_remaining_secs: u64,
    ) {
        let key = DnsCacheKey {
            profile_id: profile.id.clone(),
            host: host.to_string(),
        };

        let mut refreshing = match self.refreshing.write() {
            Ok(refreshing) => refreshing,
            Err(_) => {
                tracing::warn!(
                    dns_refresh = "failed",
                    profile_id = %profile.id,
                    host = %host,
                    reason = reason.as_str(),
                    stale_remaining_secs,
                    error = "DNS refresh lock poisoned",
                    "failed to schedule DNS refresh"
                );
                return;
            }
        };

        if !refreshing.insert(key.clone()) {
            tracing::debug!(
                dns_refresh = "skipped_already_running",
                profile_id = %profile.id,
                host = %host,
                reason = reason.as_str(),
                stale_remaining_secs,
                "DNS refresh already running"
            );
            return;
        }
        drop(refreshing);

        tracing::debug!(
            dns_refresh = "scheduled",
            profile_id = %profile.id,
            host = %host,
            reason = reason.as_str(),
            stale_remaining_secs,
            "DNS background refresh scheduled"
        );

        let cache = self.cache.clone();
        let refreshing = self.refreshing.clone();
        let host = host.to_string();
        let profile = profile.clone();
        let key_for_task = key.clone();

        tokio::spawn(async move {
            let refresh_result = match profile.mode {
                DnsProfileMode::System => system_resolve_host(&host)
                    .await
                    .map(DnsLookupResult::without_ttl),
                DnsProfileMode::Udp => udp_resolve_host(&host, &profile).await,
            };

            match refresh_result {
                Ok(result) if !result.addrs.is_empty() => {
                    let ttl_secs = positive_cache_ttl_secs(&profile, result.ttl_secs);
                    let now = Instant::now();
                    let entry = DnsCacheEntry {
                        addrs: result.addrs,
                        expires_at: now + Duration::from_secs(ttl_secs),
                        stale_until: now
                            + Duration::from_secs(ttl_secs + profile.stale_fallback_secs),
                        negative: false,
                    };
                    match cache.write() {
                        Ok(mut cache) => {
                            prune_expired_locked(&mut cache, now);
                            if cache.len() >= max_cache_entries.max(1) {
                                evict_one_cache_entry(&mut cache);
                            }
                            cache.insert(key_for_task.clone(), entry);
                            crate::dns_cache_store::save_cache(&cache);
                            tracing::debug!(
                                dns_refresh = "success",
                                profile_id = %profile.id,
                                host = %host,
                                ttl_secs,
                                stale_remaining_secs = ttl_secs + profile.stale_fallback_secs,
                                "DNS background refresh succeeded"
                            );
                        }
                        Err(_) => {
                            tracing::warn!(
                                dns_refresh = "failed",
                                profile_id = %profile.id,
                                host = %host,
                                error = "DNS cache lock poisoned",
                                "DNS background refresh could not update cache"
                            );
                        }
                    }
                }
                Ok(_) => {
                    tracing::warn!(
                        dns_refresh = "failed",
                        profile_id = %profile.id,
                        host = %host,
                        error = "DNS refresh returned no addresses",
                        "DNS background refresh failed"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        dns_refresh = "failed",
                        profile_id = %profile.id,
                        host = %host,
                        error = %error,
                        "DNS background refresh failed"
                    );
                }
            }

            if let Ok(mut refreshing) = refreshing.write() {
                refreshing.remove(&key_for_task);
            }
        });
    }

    fn cache_store_positive(
        &self,
        host: &str,
        profile: &DnsProfileConfig,
        addrs: Vec<IpAddr>,
        ttl_secs: u64,
        max_cache_entries: usize,
    ) -> Result<()> {
        let now = Instant::now();
        let entry = DnsCacheEntry {
            addrs,
            expires_at: now + Duration::from_secs(ttl_secs),
            stale_until: now + Duration::from_secs(ttl_secs + profile.stale_fallback_secs),
            negative: false,
        };
        self.cache_store_entry(host, profile, entry, max_cache_entries)?;
        self.clear_negative_failure(host, profile)?;
        tracing::debug!(
            dns_cache = "store",
            profile_id = %profile.id,
            host = %host,
            ttl_secs,
            "DNS positive cache stored"
        );
        Ok(())
    }

    fn cache_store_negative(
        &self,
        host: &str,
        profile: &DnsProfileConfig,
        max_cache_entries: usize,
        kind: DnsNegativeKind,
    ) -> Result<()> {
        if !self.should_store_negative(host, profile, kind)? {
            return Ok(());
        }

        let now = Instant::now();
        let key = DnsCacheKey {
            profile_id: profile.id.clone(),
            host: host.to_string(),
        };
        let (stale_addrs, stale_until) = self
            .cache
            .read()
            .map_err(|_| anyhow::anyhow!("DNS cache lock poisoned"))?
            .get(&key)
            .filter(|entry| !entry.addrs.is_empty() && now <= entry.stale_until)
            .map(|entry| (entry.addrs.clone(), entry.stale_until))
            .unwrap_or_else(|| (Vec::new(), now));
        let ttl_secs = negative_cache_ttl_secs(host, kind);
        let entry = DnsCacheEntry {
            addrs: stale_addrs,
            expires_at: now + Duration::from_secs(ttl_secs),
            stale_until,
            negative: true,
        };
        self.cache_store_entry(host, profile, entry, max_cache_entries)?;
        tracing::debug!(
            dns_cache = "negative",
            profile_id = %profile.id,
            host = %host,
            kind = kind.as_str(),
            ttl_secs,
            threshold = NEGATIVE_DNS_FAILURE_THRESHOLD,
            window_secs = NEGATIVE_DNS_FAILURE_WINDOW_SECS,
            "DNS negative cache stored after repeated failures"
        );
        Ok(())
    }

    fn should_store_negative(
        &self,
        host: &str,
        profile: &DnsProfileConfig,
        kind: DnsNegativeKind,
    ) -> Result<bool> {
        let key = DnsCacheKey {
            profile_id: profile.id.clone(),
            host: host.to_string(),
        };
        let now = Instant::now();
        let window = Duration::from_secs(NEGATIVE_DNS_FAILURE_WINDOW_SECS);
        let mut failures = self
            .negative_failures
            .write()
            .map_err(|_| anyhow::anyhow!("DNS negative failure lock poisoned"))?;

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
            profile_id = %profile.id,
            host = %host,
            kind = kind.as_str(),
            count,
            threshold = NEGATIVE_DNS_FAILURE_THRESHOLD,
            window_secs = NEGATIVE_DNS_FAILURE_WINDOW_SECS,
            "DNS failure recorded but not negative-cached yet"
        );
        Ok(false)
    }

    fn clear_negative_failure(&self, host: &str, profile: &DnsProfileConfig) -> Result<()> {
        self.negative_failures
            .write()
            .map_err(|_| anyhow::anyhow!("DNS negative failure lock poisoned"))?
            .remove(&DnsCacheKey {
                profile_id: profile.id.clone(),
                host: host.to_string(),
            });
        Ok(())
    }

    fn cache_store_entry(
        &self,
        host: &str,
        profile: &DnsProfileConfig,
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
                profile_id: profile.id.clone(),
                host: host.to_string(),
            },
            entry,
        );
        crate::dns_cache_store::save_cache(&cache);
        Ok(())
    }

    pub fn prune_expired(&self) -> Result<()> {
        let now = Instant::now();
        let mut cache = self
            .cache
            .write()
            .map_err(|_| anyhow::anyhow!("DNS cache lock poisoned"))?;
        prune_expired_locked(&mut cache, now);
        Ok(())
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

impl DnsState {
    fn from_config(mut config: DnsConfig) -> Self {
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
            })
            .unwrap_or_else(|| ResolvedDnsRoute {
                profile_id: self.config.default_profile.clone(),
            })
    }

    fn profile_resolution_order(&self, first_profile_id: &str) -> Vec<String> {
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
    for server in &profile.servers {
        let server_addr = server
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid DNS server address `{server}`"))?;
        for _ in 0..profile.attempts.max(1) {
            if let Ok(result) = udp_query_a_aaaa(host, server_addr, profile.timeout_ms).await {
                output.extend(result.addrs);
                ttl_secs = min_optional_ttl(ttl_secs, result.ttl_secs);
                output.sort();
                output.dedup();
                if !output.is_empty() {
                    return Ok(DnsLookupResult {
                        addrs: output,
                        ttl_secs,
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
    let mut output = Vec::new();
    let mut ttl_secs = None;
    for qtype in [1_u16, 28_u16] {
        let result = udp_query(host, server, qtype, timeout_ms).await?;
        output.extend(result.addrs);
        ttl_secs = min_optional_ttl(ttl_secs, result.ttl_secs);
    }
    output.sort();
    output.dedup();
    Ok(DnsLookupResult {
        addrs: output,
        ttl_secs,
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
    Ok(DnsLookupResult { addrs, ttl_secs })
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

fn is_ephemeral_dns_host(host: &str) -> bool {
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

fn positive_cache_ttl_secs(profile: &DnsProfileConfig, answer_ttl_secs: Option<u64>) -> u64 {
    let min_ttl = profile
        .cache_ttl_min_secs
        .min(profile.cache_ttl_max_secs)
        .max(1);
    let max_ttl = profile
        .cache_ttl_max_secs
        .max(profile.cache_ttl_min_secs)
        .max(min_ttl);
    let ttl = answer_ttl_secs.unwrap_or(max_ttl);
    ttl.clamp(min_ttl, max_ttl)
}

fn min_optional_ttl(left: Option<u64>, right: Option<u64>) -> Option<u64> {
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

fn prune_expired_locked(cache: &mut HashMap<DnsCacheKey, DnsCacheEntry>, now: Instant) {
    cache.retain(|_, entry| {
        if entry.negative {
            now <= entry.expires_at
        } else {
            now <= entry.stale_until
        }
    });
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
            profiles: vec![DnsProfileConfig::system()],
            routes: vec![DnsRouteConfig {
                id: "route-example".to_string(),
                host_pattern: "*.example.com".to_string(),
                profile_id: "system".to_string(),
                strict: true,
                enabled: true,
            }],
        };
        let state = DnsState::from_config(config);
        let route = state.resolve_route("www.example.com");

        assert_eq!(route.profile_id, "system");
    }

    #[test]
    fn validates_dns_host_patterns() {
        assert!(validate_host_pattern("*.example.com").is_ok());
        assert!(validate_host_pattern("").is_err());
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
