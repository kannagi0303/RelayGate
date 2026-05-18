use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

const MAX_PROBE_CURSORS: usize = 4096;
const PROBE_CURSOR_TTL_SECS: u64 = 15 * 60;

use crate::{config::DnsAutoSelectConfig, dns_observation::DnsObservationSnapshot};

#[derive(Debug, Clone, Default)]
pub(crate) struct DnsAutoSelectState {
    selected: HashMap<String, DnsAutoSelectChoice>,
    probe_cursor: HashMap<String, DnsAutoSelectProbeCursor>,
}

#[derive(Debug, Clone)]
struct DnsAutoSelectChoice {
    profile_id: String,
    selected_at: Instant,
}

#[derive(Debug, Clone)]
struct DnsAutoSelectProbeCursor {
    index: usize,
    last_used_at: Instant,
}

#[derive(Debug, Clone)]
pub(crate) struct DnsAutoSelectDecision {
    pub(crate) profile_id: String,
    pub(crate) auto_selected: bool,
}

impl DnsAutoSelectState {
    pub(crate) fn select_profile(
        &mut self,
        config: &DnsAutoSelectConfig,
        snapshot: &DnsObservationSnapshot,
        host: &str,
        fallback_profile_id: &str,
        enabled_profile_ids: &HashSet<String>,
        strict: bool,
        now: Instant,
    ) -> DnsAutoSelectDecision {
        let stickiness = Duration::from_secs(config.stickiness_secs.max(1));
        self.prune_expired_selected(now, stickiness);

        if strict || !config.enabled || enabled_profile_ids.is_empty() {
            return fallback_decision(fallback_profile_id);
        }

        let key = host.to_ascii_lowercase();
        if let Some(choice) = self.selected.get(&key) {
            let sticky = now
                .checked_duration_since(choice.selected_at)
                .is_some_and(|age| age < stickiness);
            if sticky && enabled_profile_ids.contains(&choice.profile_id) {
                return DnsAutoSelectDecision {
                    profile_id: choice.profile_id.clone(),
                    auto_selected: true,
                };
            }
        }

        let Some(profile_id) = best_profile(config, snapshot, enabled_profile_ids) else {
            self.selected.remove(&key);
            return fallback_decision(fallback_profile_id);
        };

        self.selected.insert(
            key,
            DnsAutoSelectChoice {
                profile_id: profile_id.clone(),
                selected_at: now,
            },
        );
        DnsAutoSelectDecision {
            profile_id,
            auto_selected: true,
        }
    }

    fn prune_expired_selected(&mut self, now: Instant, stickiness: Duration) {
        self.selected.retain(|_, choice| {
            now.checked_duration_since(choice.selected_at)
                .is_none_or(|age| age < stickiness)
        });
    }

    pub(crate) fn select_probe_profile(
        &mut self,
        host: &str,
        candidate_profile_ids: &[String],
        excluded_profile_ids: &HashSet<String>,
        now: Instant,
    ) -> Option<String> {
        self.prune_probe_cursors(now);
        let candidates = candidate_profile_ids
            .iter()
            .filter(|profile_id| !excluded_profile_ids.contains(*profile_id))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return None;
        }

        let key = host.to_ascii_lowercase();
        let cursor = self
            .probe_cursor
            .entry(key)
            .or_insert(DnsAutoSelectProbeCursor {
                index: 0,
                last_used_at: now,
            });
        cursor.last_used_at = now;
        let index = cursor.index % candidates.len();
        cursor.index = cursor.index.saturating_add(1);
        Some(candidates[index].to_string())
    }

    fn prune_probe_cursors(&mut self, now: Instant) {
        let ttl = Duration::from_secs(PROBE_CURSOR_TTL_SECS);
        self.probe_cursor.retain(|_, cursor| {
            now.checked_duration_since(cursor.last_used_at)
                .is_none_or(|age| age < ttl)
        });

        if self.probe_cursor.len() <= MAX_PROBE_CURSORS {
            return;
        }

        let overflow = self.probe_cursor.len() - MAX_PROBE_CURSORS;
        let mut stale_keys = self
            .probe_cursor
            .iter()
            .map(|(host, cursor)| (host.clone(), cursor.last_used_at))
            .collect::<Vec<_>>();
        stale_keys.sort_by_key(|(_, last_used_at)| *last_used_at);
        for (host, _) in stale_keys.into_iter().take(overflow) {
            self.probe_cursor.remove(&host);
        }
    }
}

fn fallback_decision(profile_id: &str) -> DnsAutoSelectDecision {
    DnsAutoSelectDecision {
        profile_id: profile_id.to_string(),
        auto_selected: false,
    }
}

pub(crate) fn best_profile(
    config: &DnsAutoSelectConfig,
    snapshot: &DnsObservationSnapshot,
    enabled_profile_ids: &HashSet<String>,
) -> Option<String> {
    if !config.enabled || enabled_profile_ids.is_empty() {
        return None;
    }

    snapshot
        .profiles
        .iter()
        .filter(|profile| enabled_profile_ids.contains(&profile.profile_id))
        .filter(|profile| profile.samples >= config.min_samples)
        .filter(|profile| profile.success_rate >= config.min_success_rate)
        .filter(|profile| profile.health_score >= config.min_health_score)
        .max_by(|left, right| {
            left.health_score
                .cmp(&right.health_score)
                .then_with(|| left.successes.cmp(&right.successes))
                .then_with(|| right.profile_id.cmp(&left.profile_id))
        })
        .map(|profile| profile.profile_id.clone())
}

#[cfg(test)]
mod tests {
    use crate::dns_observation::DnsProfileHealthSnapshot;

    use super::*;

    fn config() -> DnsAutoSelectConfig {
        DnsAutoSelectConfig {
            enabled: true,
            min_samples: 5,
            min_success_rate: 0.8,
            min_health_score: 75,
            stickiness_secs: 300,
        }
    }

    fn profile(
        profile_id: &str,
        samples: u64,
        success_rate: f64,
        health_score: u8,
    ) -> DnsProfileHealthSnapshot {
        DnsProfileHealthSnapshot {
            profile_id: profile_id.to_string(),
            observed_hosts: 1,
            samples,
            successes: (samples as f64 * success_rate).round() as u64,
            failures: 0,
            success_rate,
            timeout_rate: 0.0,
            nxdomain_rate: 0.0,
            no_records_rate: 0.0,
            divergent_success_rate: 0.0,
            average_latency_ms: Some(20),
            last_latency_ms: Some(20),
            last_ttl_secs: Some(60),
            last_error_kind: None,
            last_observed_age_secs: Some(1),
            health_score,
        }
    }

    fn enabled(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|id| (*id).to_string()).collect()
    }

    #[test]
    fn selects_best_eligible_profile() {
        let snapshot = DnsObservationSnapshot {
            observed_hosts: 1,
            profiles: vec![profile("slow", 10, 1.0, 80), profile("fast", 10, 1.0, 95)],
        };
        let mut state = DnsAutoSelectState::default();

        let decision = state.select_profile(
            &config(),
            &snapshot,
            "example.com",
            "system",
            &enabled(&["system", "slow", "fast"]),
            false,
            Instant::now(),
        );

        assert!(decision.auto_selected);
        assert_eq!(decision.profile_id, "fast");
    }

    #[test]
    fn strict_route_uses_fallback_profile() {
        let snapshot = DnsObservationSnapshot {
            observed_hosts: 1,
            profiles: vec![profile("fast", 10, 1.0, 95)],
        };
        let mut state = DnsAutoSelectState::default();

        let decision = state.select_profile(
            &config(),
            &snapshot,
            "example.com",
            "primary",
            &enabled(&["primary", "fast"]),
            true,
            Instant::now(),
        );

        assert!(!decision.auto_selected);
        assert_eq!(decision.profile_id, "primary");
    }

    #[test]
    fn prunes_expired_sticky_choices_before_returning_fallback() {
        let now = Instant::now();
        let mut state = DnsAutoSelectState::default();
        state.selected.insert(
            "old.example".to_string(),
            DnsAutoSelectChoice {
                profile_id: "fast".to_string(),
                selected_at: now - Duration::from_secs(600),
            },
        );

        let decision = state.select_profile(
            &config(),
            &DnsObservationSnapshot::default(),
            "old.example",
            "system",
            &HashSet::new(),
            false,
            now,
        );

        assert!(!decision.auto_selected);
        assert_eq!(decision.profile_id, "system");
        assert!(state.selected.is_empty());
    }

    #[test]
    fn keeps_sticky_choice_until_stickiness_expires() {
        let now = Instant::now();
        let first_snapshot = DnsObservationSnapshot {
            observed_hosts: 1,
            profiles: vec![
                profile("first", 10, 1.0, 95),
                profile("second", 10, 1.0, 80),
            ],
        };
        let second_snapshot = DnsObservationSnapshot {
            observed_hosts: 1,
            profiles: vec![
                profile("first", 10, 1.0, 80),
                profile("second", 10, 1.0, 99),
            ],
        };
        let mut state = DnsAutoSelectState::default();

        let first = state.select_profile(
            &config(),
            &first_snapshot,
            "example.com",
            "system",
            &enabled(&["first", "second", "system"]),
            false,
            now,
        );
        let second = state.select_profile(
            &config(),
            &second_snapshot,
            "example.com",
            "system",
            &enabled(&["first", "second", "system"]),
            false,
            now + Duration::from_secs(120),
        );

        assert_eq!(first.profile_id, "first");
        assert_eq!(second.profile_id, "first");
    }
}
