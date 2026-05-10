use std::sync::{Arc, RwLock};

use crate::{
    config::{
        DownstreamProtocolPreferenceConfig, Http3StreamingResponseModeConfig, RelayGateConfig,
        UpstreamProtocolPolicyConfig, UpstreamProtocolPreferenceConfig,
    },
    proxy::mitm_upstream::MitmUpstreamProtocolPolicy,
};

#[derive(Clone)]
pub(crate) struct ProtocolRuntimeConfig {
    inner: Arc<RwLock<ProtocolRuntimeSnapshot>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProtocolRuntimeSnapshot {
    pub(crate) upstream_preference: UpstreamProtocolPreferenceConfig,
    pub(crate) downstream_preference: DownstreamProtocolPreferenceConfig,
    pub(crate) upstream_protocol_policy: MitmUpstreamProtocolPolicy,
    pub(crate) upstream_protocol_policy_config: UpstreamProtocolPolicyConfig,
    pub(crate) upstream_http3_buffered_enabled: bool,
    pub(crate) upstream_http3_probe_enabled: bool,
    pub(crate) upstream_http3_streaming_enabled: bool,
    pub(crate) upstream_http3_streaming_mode: Http3StreamingResponseModeConfig,
    pub(crate) downstream_http2_enabled: bool,
}

impl ProtocolRuntimeConfig {
    pub(crate) fn from_config(config: &RelayGateConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(snapshot_from_config(config))),
        }
    }

    pub(crate) fn replace_from_config(&self, config: &RelayGateConfig) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = snapshot_from_config(config);
        }
    }

    pub(crate) fn snapshot(&self) -> ProtocolRuntimeSnapshot {
        self.inner
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| snapshot_from_config(&RelayGateConfig::default()))
    }
}

fn snapshot_from_config(config: &RelayGateConfig) -> ProtocolRuntimeSnapshot {
    ProtocolRuntimeSnapshot {
        upstream_preference: config.upstream_protocol.clone(),
        downstream_preference: config.downstream_protocol.clone(),
        upstream_protocol_policy: MitmUpstreamProtocolPolicy::from(
            config.proxy.upstream.protocol_policy,
        ),
        upstream_protocol_policy_config: config.proxy.upstream.protocol_policy,
        upstream_http3_buffered_enabled: config.proxy.upstream.http3_buffered_response_enabled,
        upstream_http3_probe_enabled: config.proxy.upstream.http3_probe_enabled,
        upstream_http3_streaming_enabled: config.proxy.upstream.http3_streaming_response_enabled,
        upstream_http3_streaming_mode: config.proxy.upstream.http3_streaming_response_mode,
        downstream_http2_enabled: config.proxy.mitm.downstream_http2,
    }
}
