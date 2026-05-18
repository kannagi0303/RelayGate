use std::collections::HashMap;

use anyhow::Context;
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct UpdateSettingForm {
    pub(crate) key: String,
    pub(crate) value: String,
}

#[derive(Debug)]
pub(crate) struct UpdateProtocolSettingsForm {
    pub(crate) upstream_protocol: String,
    pub(crate) downstream_protocol: String,
}

#[derive(Debug)]
pub(crate) struct UpstreamForm {
    pub(crate) address: String,
}

#[derive(Debug)]
pub(crate) struct UpstreamRouteForm {
    pub(crate) host_pattern: String,
    pub(crate) upstream_id: String,
}

#[derive(Debug)]
pub(crate) struct DnsProfileForm {
    pub(crate) id: String,
    pub(crate) mode: String,
    pub(crate) servers: String,
    pub(crate) fallback_profiles: String,
    pub(crate) server_ip: String,
    pub(crate) server_port: String,
}

#[derive(Debug)]
pub(crate) struct DnsRouteForm {
    pub(crate) host_pattern: String,
    pub(crate) profile_id: String,
}

#[derive(Debug)]
pub(crate) struct DnsFeatureToggleForm {
    pub(crate) feature: String,
    pub(crate) enabled: String,
}

#[derive(Debug)]
pub(crate) struct GatewayMountForm {
    pub(crate) mount_path: String,
    pub(crate) target_base_url: String,
    pub(crate) upstream_id: String,
    pub(crate) rewrite_links: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ToggleItemForm {
    pub(crate) id: String,
    pub(crate) enabled: String,
}

#[derive(Debug)]
pub(crate) struct DeleteItemForm {
    pub(crate) id: String,
}

#[derive(Debug)]
pub(crate) struct MoveItemForm {
    pub(crate) id: String,
    pub(crate) direction: String,
}

pub(crate) fn parse_toggle_item_from_body(body: &[u8]) -> anyhow::Result<ToggleItemForm> {
    let mut params = parse_action_body_params(body)?;

    let id = params
        .remove("id")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `id`")?;
    let enabled = params
        .remove("enabled")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `enabled`")?;
    Ok(ToggleItemForm { id, enabled })
}

pub(crate) fn parse_update_setting_from_body(body: &[u8]) -> anyhow::Result<UpdateSettingForm> {
    let mut params = parse_action_body_params(body)?;
    let key = params
        .remove("key")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `key`")?;
    let value = params
        .remove("value")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `value`")?;
    Ok(UpdateSettingForm { key, value })
}

pub(crate) fn parse_protocol_settings_from_body(
    body: &[u8],
) -> anyhow::Result<UpdateProtocolSettingsForm> {
    let mut params = parse_action_body_params(body)?;
    let upstream_protocol = params
        .remove("upstream_protocol")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `upstream_protocol`")?;
    let downstream_protocol = params
        .remove("downstream_protocol")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `downstream_protocol`")?;
    Ok(UpdateProtocolSettingsForm {
        upstream_protocol,
        downstream_protocol,
    })
}

pub(crate) fn parse_delete_item_from_body(body: &[u8]) -> anyhow::Result<DeleteItemForm> {
    let mut params = parse_action_body_params(body)?;
    let id = params
        .remove("id")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `id`")?;
    Ok(DeleteItemForm { id })
}

pub(crate) fn parse_move_item_from_body(body: &[u8]) -> anyhow::Result<MoveItemForm> {
    let mut params = parse_action_body_params(body)?;
    let id = params
        .remove("id")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `id`")?;
    let direction = params
        .remove("direction")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `direction`")?;
    Ok(MoveItemForm { id, direction })
}

pub(crate) fn parse_upstream_form_from_body(body: &[u8]) -> anyhow::Result<UpstreamForm> {
    let mut params = parse_action_body_params(body)?;
    let address = params
        .remove("address")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `address`")?;
    Ok(UpstreamForm { address })
}

pub(crate) fn parse_upstream_route_form_from_body(
    body: &[u8],
) -> anyhow::Result<UpstreamRouteForm> {
    let mut params = parse_action_body_params(body)?;
    let host_pattern = params
        .remove("host_pattern")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `host_pattern`")?;
    let upstream_id = params
        .remove("upstream_id")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `upstream_id`")?;
    Ok(UpstreamRouteForm {
        host_pattern,
        upstream_id,
    })
}

pub(crate) fn parse_dns_profile_form_from_body(body: &[u8]) -> anyhow::Result<DnsProfileForm> {
    let mut params = parse_action_body_params(body)?;
    let id = params.remove("id").unwrap_or_default();
    let mode = params.remove("mode").unwrap_or_default();
    let servers = params.remove("servers").unwrap_or_default();
    let fallback_profiles = params.remove("fallback_profiles").unwrap_or_default();
    let server_ip = params.remove("server_ip").unwrap_or_default();
    let server_port = params.remove("server_port").unwrap_or_default();
    Ok(DnsProfileForm {
        id,
        mode,
        servers,
        fallback_profiles,
        server_ip,
        server_port,
    })
}

pub(crate) fn parse_dns_route_form_from_body(body: &[u8]) -> anyhow::Result<DnsRouteForm> {
    let mut params = parse_action_body_params(body)?;
    let host_pattern = params
        .remove("host_pattern")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `host_pattern`")?;
    let profile_id = params
        .remove("profile_id")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `profile_id`")?;
    Ok(DnsRouteForm {
        host_pattern,
        profile_id,
    })
}

pub(crate) fn parse_dns_feature_toggle_from_body(
    body: &[u8],
) -> anyhow::Result<DnsFeatureToggleForm> {
    let mut params = parse_action_body_params(body)?;
    let feature = params
        .remove("feature")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `feature`")?;
    let enabled = params
        .remove("enabled")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `enabled`")?;
    Ok(DnsFeatureToggleForm { feature, enabled })
}

pub(crate) fn parse_gateway_mount_form_from_body(body: &[u8]) -> anyhow::Result<GatewayMountForm> {
    let mut params = parse_action_body_params(body)?;
    let mount_path = params
        .remove("mount_path")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `mount_path`")?;
    let target_base_url = params
        .remove("target_base_url")
        .filter(|value| !value.trim().is_empty())
        .context("missing field `target_base_url`")?;
    let upstream_id = params.remove("upstream_id").unwrap_or_default();
    let rewrite_links = params
        .remove("rewrite_links")
        .filter(|value| !value.trim().is_empty());
    Ok(GatewayMountForm {
        mount_path,
        target_base_url,
        upstream_id,
        rewrite_links,
    })
}

fn parse_action_body_params(body: &[u8]) -> anyhow::Result<HashMap<String, String>> {
    if body.is_empty() {
        return Ok(HashMap::new());
    }
    let is_json = body
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| byte == b'{');
    if !is_json {
        anyhow::bail!("invalid action body: expected JSON object");
    }
    parse_json_body_params(body)
}

fn parse_json_body_params(body: &[u8]) -> anyhow::Result<HashMap<String, String>> {
    let payload = serde_json::from_slice::<HashMap<String, Value>>(body)
        .context("invalid JSON action body")?;
    let mut params = HashMap::<String, String>::new();
    for (key, value) in payload {
        if let Some(value) = json_value_to_action_param(value) {
            params.insert(key, value);
        }
    }
    Ok(params)
}

fn json_value_to_action_param(value: Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value),
        Value::Bool(value) => Some(if value { "true" } else { "false" }.to_string()),
        Value::Number(value) => Some(value.to_string()),
        other => Some(other.to_string()),
    }
}
