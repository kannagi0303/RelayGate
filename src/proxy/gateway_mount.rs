use std::sync::{Arc, RwLock};

use anyhow::Result;

use crate::config::MountSiteConfig;

pub type SharedGatewayMountRegistry = Arc<RwLock<GatewayMountRegistry>>;

/// Runtime lookup table for local gateway mounts.
///
/// The proxy hot path should not reload `data/user/settings.yaml` while resolving a
/// request target. The control panel updates this registry when gateway mount
/// settings are changed, so request handling can stay memory-only.
#[derive(Debug, Clone, Default)]
pub struct GatewayMountRegistry {
    mounts: Vec<MountSiteConfig>,
}

impl GatewayMountRegistry {
    pub fn from_config(mounts: &[MountSiteConfig]) -> Self {
        Self {
            mounts: mounts.to_vec(),
        }
    }

    pub fn find_by_path(&self, request_path: &str) -> Option<MountSiteConfig> {
        self.mounts
            .iter()
            .find(|mount| {
                mount.enabled && request_path.starts_with(mount.mount_path.trim_end_matches('/'))
            })
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    pub fn enabled_len(&self) -> usize {
        self.mounts.iter().filter(|mount| mount.enabled).count()
    }
}

pub fn shared_from_config(mounts: &[MountSiteConfig]) -> SharedGatewayMountRegistry {
    Arc::new(RwLock::new(GatewayMountRegistry::from_config(mounts)))
}

pub fn replace_shared_registry(
    registry: &SharedGatewayMountRegistry,
    mounts: &[MountSiteConfig],
) -> Result<()> {
    let next = GatewayMountRegistry::from_config(mounts);
    let mut guard = registry
        .write()
        .map_err(|_| anyhow::anyhow!("gateway mount registry lock poisoned"))?;
    *guard = next;
    Ok(())
}

pub fn find_by_path(
    registry: &SharedGatewayMountRegistry,
    request_path: &str,
) -> Option<MountSiteConfig> {
    registry
        .read()
        .ok()
        .and_then(|registry| registry.find_by_path(request_path))
}
