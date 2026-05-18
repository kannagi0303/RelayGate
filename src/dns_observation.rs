use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Default)]
pub(crate) struct DnsObservationStore {
    hosts: HashMap<String, DnsHostObservation>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DnsObservationSnapshot {
    pub(crate) observed_hosts: usize,
    pub(crate) profiles: Vec<DnsProfileHealthSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DnsProfileHealthSnapshot {
    pub(crate) profile_id: String,
    pub(crate) observed_hosts: usize,
    pub(crate) samples: u64,
    pub(crate) successes: u64,
    pub(crate) failures: u64,
    pub(crate) success_rate: f64,
    pub(crate) timeout_rate: f64,
    pub(crate) nxdomain_rate: f64,
    pub(crate) no_records_rate: f64,
    pub(crate) divergent_success_rate: f64,
    pub(crate) average_latency_ms: Option<u64>,
    pub(crate) last_latency_ms: Option<u64>,
    pub(crate) last_ttl_secs: Option<u64>,
    pub(crate) last_error_kind: Option<&'static str>,
    pub(crate) last_observed_age_secs: Option<u64>,
    pub(crate) health_score: u8,
}

#[derive(Debug, Clone, Default)]
struct DnsHostObservation {
    last_started: Option<Instant>,
    profiles: HashMap<String, DnsProfileObservationStats>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DnsProfileObservationStats {
    pub(crate) samples: u64,
    pub(crate) successes: u64,
    pub(crate) failures: u64,
    pub(crate) timeouts: u64,
    pub(crate) nxdomain: u64,
    pub(crate) no_records: u64,
    pub(crate) divergent_successes: u64,
    pub(crate) total_latency_ms: u64,
    pub(crate) last_latency_ms: Option<u64>,
    pub(crate) last_ttl_secs: Option<u64>,
    pub(crate) last_answer_signature: Option<String>,
    pub(crate) last_error_kind: Option<DnsObservationErrorKind>,
    pub(crate) last_observed: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsObservationErrorKind {
    Timeout,
    Nxdomain,
    NoRecords,
    TemporaryFailure,
}

impl DnsObservationErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Nxdomain => "nxdomain",
            Self::NoRecords => "no_records",
            Self::TemporaryFailure => "temporary_failure",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DnsProfileObservationResult {
    pub(crate) profile_id: String,
    pub(crate) latency_ms: u64,
    pub(crate) ttl_secs: Option<u64>,
    pub(crate) addrs: Vec<IpAddr>,
    pub(crate) error: Option<DnsObservationErrorKind>,
}

impl DnsProfileObservationResult {
    pub(crate) fn success(
        profile_id: String,
        latency_ms: u64,
        ttl_secs: Option<u64>,
        mut addrs: Vec<IpAddr>,
    ) -> Self {
        addrs.sort();
        addrs.dedup();
        Self {
            profile_id,
            latency_ms,
            ttl_secs,
            addrs,
            error: None,
        }
    }

    pub(crate) fn failure(
        profile_id: String,
        latency_ms: u64,
        error: DnsObservationErrorKind,
    ) -> Self {
        Self {
            profile_id,
            latency_ms,
            ttl_secs: None,
            addrs: Vec::new(),
            error: Some(error),
        }
    }
}

impl DnsObservationStore {
    pub(crate) fn reserve_host(
        &mut self,
        host: &str,
        now: Instant,
        min_interval: Duration,
    ) -> bool {
        let host = host.to_ascii_lowercase();
        let observation = self.hosts.entry(host).or_default();
        if observation
            .last_started
            .and_then(|last_started| now.checked_duration_since(last_started))
            .is_some_and(|age| age < min_interval)
        {
            return false;
        }
        observation.last_started = Some(now);
        true
    }

    pub(crate) fn record_host_results(
        &mut self,
        host: &str,
        now: Instant,
        results: Vec<DnsProfileObservationResult>,
    ) {
        let host = host.to_ascii_lowercase();
        let divergent_signatures = successful_answer_signatures(&results);
        let divergent = divergent_signatures.len() > 1;
        let observation = self.hosts.entry(host).or_default();

        for result in results {
            let stats = observation.profiles.entry(result.profile_id).or_default();
            stats.samples = stats.samples.saturating_add(1);
            stats.total_latency_ms = stats.total_latency_ms.saturating_add(result.latency_ms);
            stats.last_latency_ms = Some(result.latency_ms);
            stats.last_ttl_secs = result.ttl_secs;
            stats.last_observed = Some(now);

            match result.error {
                None if result.addrs.is_empty() => {
                    stats.failures = stats.failures.saturating_add(1);
                    stats.no_records = stats.no_records.saturating_add(1);
                    stats.last_error_kind = Some(DnsObservationErrorKind::NoRecords);
                    stats.last_answer_signature = None;
                }
                None => {
                    stats.successes = stats.successes.saturating_add(1);
                    stats.last_error_kind = None;
                    stats.last_answer_signature = Some(answer_signature(&result.addrs));
                    if divergent {
                        stats.divergent_successes = stats.divergent_successes.saturating_add(1);
                    }
                }
                Some(error) => {
                    stats.failures = stats.failures.saturating_add(1);
                    stats.last_error_kind = Some(error);
                    stats.last_answer_signature = None;
                    match error {
                        DnsObservationErrorKind::Timeout => {
                            stats.timeouts = stats.timeouts.saturating_add(1);
                        }
                        DnsObservationErrorKind::Nxdomain => {
                            stats.nxdomain = stats.nxdomain.saturating_add(1);
                        }
                        DnsObservationErrorKind::NoRecords => {
                            stats.no_records = stats.no_records.saturating_add(1);
                        }
                        DnsObservationErrorKind::TemporaryFailure => {}
                    }
                }
            }
        }
    }

    pub(crate) fn snapshot(&self, now: Instant) -> DnsObservationSnapshot {
        let mut aggregates = HashMap::<String, DnsProfileObservationAggregate>::new();
        for host in self.hosts.values() {
            for (profile_id, stats) in &host.profiles {
                aggregates
                    .entry(profile_id.clone())
                    .or_insert_with(|| DnsProfileObservationAggregate::new(profile_id))
                    .record_profile_host(stats);
            }
        }

        let mut profiles = aggregates
            .into_values()
            .map(|aggregate| aggregate.into_snapshot(now))
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            right
                .health_score
                .cmp(&left.health_score)
                .then_with(|| left.profile_id.cmp(&right.profile_id))
        });

        DnsObservationSnapshot {
            observed_hosts: self.hosts.len(),
            profiles,
        }
    }
}

#[derive(Debug, Clone)]
struct DnsProfileObservationAggregate {
    profile_id: String,
    observed_hosts: usize,
    samples: u64,
    successes: u64,
    failures: u64,
    timeouts: u64,
    nxdomain: u64,
    no_records: u64,
    divergent_successes: u64,
    total_latency_ms: u64,
    last_latency_ms: Option<u64>,
    last_ttl_secs: Option<u64>,
    last_error_kind: Option<DnsObservationErrorKind>,
    last_observed: Option<Instant>,
}

impl DnsProfileObservationAggregate {
    fn new(profile_id: &str) -> Self {
        Self {
            profile_id: profile_id.to_string(),
            observed_hosts: 0,
            samples: 0,
            successes: 0,
            failures: 0,
            timeouts: 0,
            nxdomain: 0,
            no_records: 0,
            divergent_successes: 0,
            total_latency_ms: 0,
            last_latency_ms: None,
            last_ttl_secs: None,
            last_error_kind: None,
            last_observed: None,
        }
    }

    fn record_profile_host(&mut self, stats: &DnsProfileObservationStats) {
        if stats.samples == 0 {
            return;
        }
        self.observed_hosts = self.observed_hosts.saturating_add(1);
        self.samples = self.samples.saturating_add(stats.samples);
        self.successes = self.successes.saturating_add(stats.successes);
        self.failures = self.failures.saturating_add(stats.failures);
        self.timeouts = self.timeouts.saturating_add(stats.timeouts);
        self.nxdomain = self.nxdomain.saturating_add(stats.nxdomain);
        self.no_records = self.no_records.saturating_add(stats.no_records);
        self.divergent_successes = self
            .divergent_successes
            .saturating_add(stats.divergent_successes);
        self.total_latency_ms = self.total_latency_ms.saturating_add(stats.total_latency_ms);

        if stats.last_observed > self.last_observed {
            self.last_latency_ms = stats.last_latency_ms;
            self.last_ttl_secs = stats.last_ttl_secs;
            self.last_error_kind = stats.last_error_kind;
            self.last_observed = stats.last_observed;
        }
    }

    fn into_snapshot(self, now: Instant) -> DnsProfileHealthSnapshot {
        let average_latency_ms = average_latency_ms(self.total_latency_ms, self.samples);
        let success_rate = rate(self.successes, self.samples);
        let timeout_rate = rate(self.timeouts, self.samples);
        let nxdomain_rate = rate(self.nxdomain, self.samples);
        let no_records_rate = rate(self.no_records, self.samples);
        let divergent_success_rate = rate(self.divergent_successes, self.successes);
        let health_score = profile_health_score(
            success_rate,
            timeout_rate,
            divergent_success_rate,
            average_latency_ms,
        );

        DnsProfileHealthSnapshot {
            profile_id: self.profile_id,
            observed_hosts: self.observed_hosts,
            samples: self.samples,
            successes: self.successes,
            failures: self.failures,
            success_rate,
            timeout_rate,
            nxdomain_rate,
            no_records_rate,
            divergent_success_rate,
            average_latency_ms,
            last_latency_ms: self.last_latency_ms,
            last_ttl_secs: self.last_ttl_secs,
            last_error_kind: self.last_error_kind.map(DnsObservationErrorKind::as_str),
            last_observed_age_secs: self
                .last_observed
                .and_then(|last_observed| now.checked_duration_since(last_observed))
                .map(|age| age.as_secs()),
            health_score,
        }
    }
}

fn average_latency_ms(total_latency_ms: u64, samples: u64) -> Option<u64> {
    if samples == 0 {
        None
    } else {
        Some(total_latency_ms / samples)
    }
}

fn rate(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

fn profile_health_score(
    success_rate: f64,
    timeout_rate: f64,
    divergent_success_rate: f64,
    average_latency_ms: Option<u64>,
) -> u8 {
    let latency_score = latency_score(average_latency_ms);
    let timeout_score = 1.0 - timeout_rate.clamp(0.0, 1.0);
    let consistency_score = 1.0 - divergent_success_rate.clamp(0.0, 1.0);
    let score = (success_rate.clamp(0.0, 1.0) * 55.0)
        + (latency_score * 30.0)
        + (timeout_score * 10.0)
        + (consistency_score * 5.0);
    score.round().clamp(0.0, 100.0) as u8
}

fn latency_score(average_latency_ms: Option<u64>) -> f64 {
    let Some(latency) = average_latency_ms else {
        return 0.0;
    };
    if latency <= 20 {
        1.0
    } else if latency >= 500 {
        0.0
    } else {
        1.0 - ((latency - 20) as f64 / 480.0)
    }
}

fn successful_answer_signatures(results: &[DnsProfileObservationResult]) -> HashSet<String> {
    results
        .iter()
        .filter(|result| result.error.is_none() && !result.addrs.is_empty())
        .map(|result| answer_signature(&result.addrs))
        .collect()
}

fn answer_signature(addrs: &[IpAddr]) -> String {
    let mut addrs = addrs.to_vec();
    addrs.sort();
    addrs.dedup();
    addrs
        .into_iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_host_respects_min_interval() {
        let mut store = DnsObservationStore::default();
        let now = Instant::now();
        let min_interval = Duration::from_secs(300);

        assert!(store.reserve_host("Example.COM", now, min_interval));
        assert!(!store.reserve_host("example.com", now + Duration::from_secs(299), min_interval));
        assert!(store.reserve_host("example.com", now + Duration::from_secs(300), min_interval));
    }

    #[test]
    fn divergent_successes_are_counted_for_successful_profiles() {
        let mut store = DnsObservationStore::default();
        let now = Instant::now();
        store.record_host_results(
            "example.com",
            now,
            vec![
                DnsProfileObservationResult::success(
                    "a".to_string(),
                    10,
                    Some(60),
                    vec![IpAddr::from([203, 0, 113, 1])],
                ),
                DnsProfileObservationResult::success(
                    "b".to_string(),
                    20,
                    Some(60),
                    vec![IpAddr::from([203, 0, 113, 2])],
                ),
                DnsProfileObservationResult::failure(
                    "c".to_string(),
                    30,
                    DnsObservationErrorKind::Timeout,
                ),
            ],
        );

        let host = store.hosts.get("example.com").unwrap();
        assert_eq!(host.profiles["a"].successes, 1);
        assert_eq!(host.profiles["a"].divergent_successes, 1);
        assert_eq!(host.profiles["b"].divergent_successes, 1);
        assert_eq!(host.profiles["c"].timeouts, 1);
    }

    #[test]
    fn snapshot_orders_healthier_profiles_first() {
        let mut store = DnsObservationStore::default();
        let now = Instant::now();
        store.record_host_results(
            "example.com",
            now,
            vec![
                DnsProfileObservationResult::success(
                    "fast".to_string(),
                    20,
                    Some(120),
                    vec![IpAddr::from([203, 0, 113, 1])],
                ),
                DnsProfileObservationResult::success(
                    "slow".to_string(),
                    900,
                    Some(120),
                    vec![IpAddr::from([203, 0, 113, 1])],
                ),
                DnsProfileObservationResult::failure(
                    "broken".to_string(),
                    1000,
                    DnsObservationErrorKind::Timeout,
                ),
            ],
        );

        let snapshot = store.snapshot(now + Duration::from_secs(10));

        assert_eq!(snapshot.observed_hosts, 1);
        assert_eq!(snapshot.profiles[0].profile_id, "fast");
        assert_eq!(snapshot.profiles[0].health_score, 100);
        assert!(snapshot.profiles[0].health_score > snapshot.profiles[1].health_score);
        assert_eq!(snapshot.profiles[2].profile_id, "broken");
        assert_eq!(snapshot.profiles[2].timeout_rate, 1.0);
        assert_eq!(snapshot.profiles[0].last_observed_age_secs, Some(10));
    }

    #[test]
    fn snapshot_marks_divergence_without_marking_failure() {
        let mut store = DnsObservationStore::default();
        let now = Instant::now();
        store.record_host_results(
            "example.com",
            now,
            vec![
                DnsProfileObservationResult::success(
                    "a".to_string(),
                    20,
                    Some(120),
                    vec![IpAddr::from([203, 0, 113, 1])],
                ),
                DnsProfileObservationResult::success(
                    "b".to_string(),
                    20,
                    Some(120),
                    vec![IpAddr::from([203, 0, 113, 2])],
                ),
            ],
        );

        let snapshot = store.snapshot(now);

        let profile = snapshot
            .profiles
            .iter()
            .find(|profile| profile.profile_id == "a")
            .unwrap();
        assert_eq!(profile.success_rate, 1.0);
        assert_eq!(profile.divergent_success_rate, 1.0);
        assert_eq!(profile.failures, 0);
        assert!(profile.health_score < 100);
    }
}
