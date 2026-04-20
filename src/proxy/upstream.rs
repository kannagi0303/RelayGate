use std::collections::HashMap;

use crate::config::UpstreamConfig;

/// Central registry for upstream proxies.
/// When a rule matches `use_upstream`, lookup happens here by ID.
#[derive(Debug, Clone, Default)]
pub struct UpstreamRegistry {
    entries: HashMap<String, UpstreamEntry>,
}

#[derive(Debug, Clone)]
pub struct UpstreamEntry {
    /// Upstream proxy ID.
    pub id: String,
    /// Upstream proxy address, for example `http://127.0.0.1:8888`.
    pub address: String,
    pub enabled: bool,
}

impl UpstreamRegistry {
    pub fn from_config(items: &[UpstreamConfig]) -> Self {
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

        Self { entries }
    }

    pub fn resolve(&self, id: &str) -> Option<&UpstreamEntry> {
        // Only return enabled upstreams.
        self.entries.get(id).filter(|entry| entry.enabled)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
