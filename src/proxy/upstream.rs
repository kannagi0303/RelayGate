use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::{UpstreamConfig, UpstreamRouteConfig};

pub type SharedUpstreamRegistry = Arc<RwLock<UpstreamRegistry>>;

/// Central registry for upstream proxies.
/// When a rule matches `use_upstream`, lookup happens here by ID.
#[derive(Debug, Clone, Default)]
pub struct UpstreamRegistry {
    entries: HashMap<String, UpstreamEntry>,
    routes: UpstreamRouteMatcher,
}

#[derive(Debug, Clone)]
pub struct UpstreamEntry {
    /// Upstream proxy ID.
    pub id: String,
    /// Upstream proxy address, for example `http://127.0.0.1:8888`.
    pub address: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct UpstreamRouteEntry {
    pub id: String,
    pub host_pattern: String,
    pub upstream_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
struct UpstreamRouteMatcher {
    routes: Vec<UpstreamRouteEntry>,
    compiled_route_indexes: Vec<usize>,
    globset: Option<GlobSet>,
}

impl UpstreamRegistry {
    pub fn from_config(items: &[UpstreamConfig], routes: &[UpstreamRouteConfig]) -> Self {
        let mut entries = HashMap::new();

        // Convert the config list into a HashMap on startup for easier lookup later.
        for item in items {
            entries.insert(
                item.id.clone(),
                UpstreamEntry {
                    id: item.id.clone(),
                    address: item.address.clone(),
                    enabled: item.enabled,
                },
            );
        }

        let routes = UpstreamRouteMatcher::from_config(routes).unwrap_or_else(|error| {
            tracing::warn!(error = %error, "failed to compile upstream routes; routing table disabled");
            UpstreamRouteMatcher::default()
        });

        Self { entries, routes }
    }

    pub fn resolve(&self, id: &str) -> Option<&UpstreamEntry> {
        // Only return enabled upstreams.
        self.entries.get(id).filter(|entry| entry.enabled)
    }

    pub fn resolve_route_for_host(&self, host: &str) -> Option<&UpstreamRouteEntry> {
        self.routes
            .resolve(host)
            .filter(|route| self.resolve(&route.upstream_id).is_some())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn route_len(&self) -> usize {
        self.routes.routes.len()
    }
}

pub fn shared_from_config(
    items: &[UpstreamConfig],
    routes: &[UpstreamRouteConfig],
) -> SharedUpstreamRegistry {
    Arc::new(RwLock::new(UpstreamRegistry::from_config(items, routes)))
}

pub fn replace_shared_registry(
    registry: &SharedUpstreamRegistry,
    items: &[UpstreamConfig],
    routes: &[UpstreamRouteConfig],
) -> Result<()> {
    let next = UpstreamRegistry::from_config(items, routes);
    let mut guard = registry
        .write()
        .map_err(|_| anyhow::anyhow!("upstream registry lock poisoned"))?;
    *guard = next;
    Ok(())
}

impl UpstreamRouteMatcher {
    fn from_config(items: &[UpstreamRouteConfig]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        let mut routes = Vec::new();
        let mut compiled_route_indexes = Vec::new();

        for item in items {
            let route_index = routes.len();
            routes.push(UpstreamRouteEntry {
                id: item.id.clone(),
                host_pattern: normalize_host_pattern(&item.host_pattern),
                upstream_id: item.upstream_id.clone(),
                enabled: item.enabled,
            });

            if !item.enabled {
                continue;
            }

            let pattern = normalize_host_pattern(&item.host_pattern);
            builder.add(Glob::new(&pattern).with_context(|| {
                format!(
                    "invalid upstream route host pattern `{}` in route `{}`",
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
                    .context("failed to build upstream route matcher")?,
            )
        };

        Ok(Self {
            routes,
            compiled_route_indexes,
            globset,
        })
    }

    fn resolve(&self, host: &str) -> Option<&UpstreamRouteEntry> {
        let normalized_host = normalize_host(host);
        let globset = self.globset.as_ref()?;
        let matches = globset.matches(&normalized_host);
        let first_match = matches.into_iter().min()?;
        let route_index = *self.compiled_route_indexes.get(first_match)?;
        self.routes.get(route_index)
    }
}

pub fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn validate_host_pattern(pattern: &str) -> Result<()> {
    let pattern = normalize_host_pattern(pattern);
    if pattern.is_empty() {
        anyhow::bail!("host pattern cannot be empty");
    }
    Glob::new(&pattern).with_context(|| format!("invalid host pattern `{pattern}`"))?;
    Ok(())
}

fn normalize_host_pattern(pattern: &str) -> String {
    pattern.trim().trim_end_matches('.').to_ascii_lowercase()
}
