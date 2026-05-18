use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use crate::{
    config::DnsWarmCacheConfig,
    dns::{is_ephemeral_dns_host, DnsCacheEntry, DnsCacheKey},
};

#[derive(Debug, Clone, Default)]
pub(crate) struct DnsWarmCacheAccess {
    pub(crate) hit_count: u64,
    pub(crate) last_accessed: Option<Instant>,
    pub(crate) last_refresh_attempt: Option<Instant>,
    pub(crate) last_refresh_success: Option<Instant>,
    pub(crate) consecutive_failures: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct DnsWarmCacheCandidate {
    pub(crate) key: DnsCacheKey,
    pub(crate) stale_remaining_secs: u64,
}

pub(crate) fn record_positive_cache_hit(
    metadata: &mut HashMap<DnsCacheKey, DnsWarmCacheAccess>,
    key: DnsCacheKey,
    now: Instant,
) {
    let access = metadata.entry(key).or_default();
    access.hit_count = access.hit_count.saturating_add(1);
    access.last_accessed = Some(now);
}

pub(crate) fn record_positive_cache_store(
    metadata: &mut HashMap<DnsCacheKey, DnsWarmCacheAccess>,
    key: DnsCacheKey,
    now: Instant,
) {
    let access = metadata.entry(key).or_default();
    access.hit_count = access.hit_count.max(1);
    access.last_accessed = Some(now);
    access.last_refresh_success = Some(now);
    access.consecutive_failures = 0;
}

pub(crate) fn record_refresh_attempt(
    metadata: &mut HashMap<DnsCacheKey, DnsWarmCacheAccess>,
    key: &DnsCacheKey,
    now: Instant,
) {
    metadata
        .entry(key.clone())
        .or_default()
        .last_refresh_attempt = Some(now);
}

pub(crate) fn record_refresh_success(
    metadata: &mut HashMap<DnsCacheKey, DnsWarmCacheAccess>,
    key: &DnsCacheKey,
    now: Instant,
) {
    let access = metadata.entry(key.clone()).or_default();
    access.last_refresh_success = Some(now);
    access.consecutive_failures = 0;
}

pub(crate) fn record_refresh_failure(
    metadata: &mut HashMap<DnsCacheKey, DnsWarmCacheAccess>,
    key: &DnsCacheKey,
) {
    let access = metadata.entry(key.clone()).or_default();
    access.consecutive_failures = access.consecutive_failures.saturating_add(1);
}

pub(crate) fn prune_missing_metadata(
    metadata: &mut HashMap<DnsCacheKey, DnsWarmCacheAccess>,
    cache: &HashMap<DnsCacheKey, DnsCacheEntry>,
) {
    metadata.retain(|key, _| cache.contains_key(key));
}

pub(crate) fn select_warm_cache_candidates(
    config: &DnsWarmCacheConfig,
    cache: &HashMap<DnsCacheKey, DnsCacheEntry>,
    metadata: &HashMap<DnsCacheKey, DnsWarmCacheAccess>,
    refreshing: &HashSet<DnsCacheKey>,
    now: Instant,
) -> Vec<DnsWarmCacheCandidate> {
    if !config.enabled || config.max_hosts == 0 {
        return Vec::new();
    }

    let mut candidates = cache
        .iter()
        .filter_map(|(key, entry)| {
            let access = metadata.get(key)?;
            if !is_warm_cache_candidate(config, key, entry, access, refreshing, now) {
                return None;
            }
            Some(DnsWarmCacheCandidate {
                key: key.clone(),
                stale_remaining_secs: remaining_secs(now, entry.stale_until),
            })
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|candidate| {
        cache
            .get(&candidate.key)
            .map(|entry| entry.expires_at)
            .unwrap_or(now)
    });
    candidates.truncate(config.max_hosts);
    candidates
}

fn is_warm_cache_candidate(
    config: &DnsWarmCacheConfig,
    key: &DnsCacheKey,
    entry: &DnsCacheEntry,
    access: &DnsWarmCacheAccess,
    refreshing: &HashSet<DnsCacheKey>,
    now: Instant,
) -> bool {
    if entry.negative || entry.addrs.is_empty() || now > entry.stale_until {
        return false;
    }
    if refreshing.contains(key) {
        return false;
    }
    if config.exclude_ephemeral_cdn_hosts && is_ephemeral_dns_host(&key.host) {
        return false;
    }
    if access.hit_count < config.min_hits {
        return false;
    }
    if access.consecutive_failures >= config.max_consecutive_failures {
        return false;
    }
    if access
        .last_accessed
        .and_then(|last_accessed| now.checked_duration_since(last_accessed))
        .map_or(true, |age| age.as_secs() > config.active_within_secs)
    {
        return false;
    }
    if access
        .last_refresh_attempt
        .and_then(|last_attempt| now.checked_duration_since(last_attempt))
        .is_some_and(|age| age.as_secs() < config.min_refresh_interval_secs)
    {
        return false;
    }
    remaining_secs(now, entry.expires_at) <= config.refresh_when_ttl_below_secs
}

fn remaining_secs(now: Instant, expires_at: Instant) -> u64 {
    expires_at
        .checked_duration_since(now)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use super::*;

    fn warm_config() -> DnsWarmCacheConfig {
        DnsWarmCacheConfig {
            enabled: true,
            max_hosts: 8,
            scan_interval_secs: 300,
            refresh_when_ttl_below_secs: 60,
            min_hits: 1,
            active_within_secs: 900,
            min_refresh_interval_secs: 300,
            max_consecutive_failures: 3,
            exclude_ephemeral_cdn_hosts: true,
        }
    }

    fn cache_entry(now: Instant, ttl_secs: u64) -> DnsCacheEntry {
        DnsCacheEntry {
            addrs: vec![IpAddr::from([203, 0, 113, 10])],
            expires_at: now + Duration::from_secs(ttl_secs),
            stale_until: now + Duration::from_secs(ttl_secs + 300),
            negative: false,
            source_profile_id: "system".to_string(),
        }
    }

    fn cache_key(host: &str) -> DnsCacheKey {
        DnsCacheKey {
            profile_id: "system".to_string(),
            host: host.to_string(),
        }
    }

    #[test]
    fn selects_hot_positive_entries_near_expiry() {
        let now = Instant::now();
        let key = cache_key("example.com");
        let mut cache = HashMap::new();
        cache.insert(key.clone(), cache_entry(now, 30));
        let mut metadata = HashMap::new();
        metadata.insert(
            key.clone(),
            DnsWarmCacheAccess {
                hit_count: 1,
                last_accessed: Some(now),
                ..Default::default()
            },
        );

        let selected =
            select_warm_cache_candidates(&warm_config(), &cache, &metadata, &HashSet::new(), now);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].key, key);
    }

    #[test]
    fn skips_candidates_when_warm_cache_disabled() {
        let now = Instant::now();
        let key = cache_key("example.com");
        let mut cache = HashMap::new();
        cache.insert(key.clone(), cache_entry(now, 30));
        let mut metadata = HashMap::new();
        metadata.insert(
            key,
            DnsWarmCacheAccess {
                hit_count: 1,
                last_accessed: Some(now),
                ..Default::default()
            },
        );
        let mut config = warm_config();
        config.enabled = false;

        let selected =
            select_warm_cache_candidates(&config, &cache, &metadata, &HashSet::new(), now);

        assert!(selected.is_empty());
    }

    #[test]
    fn skips_ephemeral_cdn_hosts_by_default() {
        let now = Instant::now();
        let key = cache_key("rr4---sn.example.googlevideo.com");
        let mut cache = HashMap::new();
        cache.insert(key.clone(), cache_entry(now, 30));
        let mut metadata = HashMap::new();
        metadata.insert(
            key,
            DnsWarmCacheAccess {
                hit_count: 1,
                last_accessed: Some(now),
                ..Default::default()
            },
        );

        let selected =
            select_warm_cache_candidates(&warm_config(), &cache, &metadata, &HashSet::new(), now);

        assert!(selected.is_empty());
    }
}
