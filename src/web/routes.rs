use std::{collections::HashSet, convert::Infallible, time::Duration};

use crate::{
    adblock,
    config::{DnsConfig, RelayGateConfig},
    dns, lang,
    proxy::{gateway_mount, mitm, resource_replace, upstream},
    user_script,
    web::{
        action_forms::{
            parse_delete_item_from_body, parse_dns_feature_toggle_from_body,
            parse_dns_profile_form_from_body, parse_dns_route_form_from_body,
            parse_gateway_mount_form_from_body, parse_move_item_from_body,
            parse_protocol_settings_from_body, parse_toggle_item_from_body,
            parse_update_setting_from_body, parse_upstream_form_from_body,
            parse_upstream_route_form_from_body,
        },
        backend_payloads,
        config_actions::{
            add_dns_profile_config, add_dns_route_config, add_gateway_mount_config,
            add_upstream_config, add_upstream_route_config, current_config,
            current_upstream_routing, delete_dns_profile_config, delete_dns_route_config,
            delete_gateway_mount_config, delete_upstream_config, delete_upstream_route_config,
            move_dns_profile_config, parse_bool, reload_resource_replace_runtime,
            reload_rewrite_runtime, reload_user_script_runtime, store_current_config,
            toggle_dns_feature_config, toggle_dns_profile_config, toggle_dns_route_config,
            toggle_gateway_mount_config, toggle_resource_replace_rule_config,
            toggle_upstream_config, toggle_upstream_route_config, update_protocol_settings_config,
            update_single_setting,
        },
        server::WebAppState,
        system_actions::{
            build_mitm_status, build_mitm_status_fast, open_folder, remove_ca_windows_trust_only,
            remove_windows_relaygate_ca,
        },
    },
};
use async_stream::stream;
use axum::{
    body::Bytes,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use serde::Serialize;

fn success_feedback(message: impl Into<String>) -> Json<ActionFeedbackPayload> {
    Json(ActionFeedbackPayload {
        ok: true,
        level: "success",
        message: message.into(),
    })
}

fn error_feedback(message: impl Into<String>) -> Json<ActionFeedbackPayload> {
    Json(ActionFeedbackPayload {
        ok: false,
        level: "error",
        message: message.into(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DashboardEventClass {
    Immediate,
    Burst,
    Slow,
}

fn dashboard_event_class(changed: &[String]) -> DashboardEventClass {
    if changed.is_empty() {
        return DashboardEventClass::Immediate;
    }

    if changed.iter().any(|item| is_immediate_dashboard_key(item)) {
        return DashboardEventClass::Immediate;
    }

    if changed.iter().all(|item| is_slow_dashboard_key(item)) {
        return DashboardEventClass::Slow;
    }

    DashboardEventClass::Burst
}

fn is_immediate_dashboard_key(key: &str) -> bool {
    matches!(
        key,
        "status"
            | "settings"
            | "i18n"
            | "patch"
            | "render"
            | "adblock"
            | "resource_replace"
            | "gateway"
            | "upstreams"
            | "upstream_routes"
            | "user_script"
    )
}

fn is_slow_dashboard_key(key: &str) -> bool {
    matches!(key, "dns" | "connection_info")
}

fn merge_changed_keys(target: &mut Vec<String>, changed: Vec<String>) {
    if changed.is_empty() {
        return;
    }
    let mut seen = target.iter().cloned().collect::<HashSet<_>>();
    for key in changed {
        if seen.insert(key.clone()) {
            target.push(key);
        }
    }
}

pub(crate) async fn backend_events(
    State(state): State<WebAppState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let stream = stream! {
        let mut changes = state.runtime.subscribe_backend_changes();
        let config = current_config(&state);
        let payload = backend_payloads::backend_payload_value(
            &state,
            &config,
            full_backend_changed_keys(),
        );
        yield Ok(json_named_event("i18n_full", &lang::web_i18n_payload()));
        yield Ok(json_named_event("backend_full", &payload));

        let mut pending_burst = Vec::<String>::new();
        let mut pending_slow = Vec::<String>::new();

        let mut burst_tick = tokio::time::interval(Duration::from_millis(350));
        burst_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut slow_tick = tokio::time::interval(Duration::from_secs(2));
        slow_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut metrics_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(5),
            Duration::from_secs(5),
        );
        metrics_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = changes.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let signal = changes.borrow().clone();
                    if signal.changed.iter().any(|item| item == "i18n") {
                        yield Ok(json_named_event("i18n_full", &lang::web_i18n_payload()));
                    }

                    match dashboard_event_class(&signal.changed) {
                        DashboardEventClass::Immediate => {
                            let config = current_config(&state);
                            yield Ok(backend_payloads::backend_event(&state, &config, signal.changed));
                        }
                        DashboardEventClass::Burst => merge_changed_keys(&mut pending_burst, signal.changed),
                        DashboardEventClass::Slow => merge_changed_keys(&mut pending_slow, signal.changed),
                    }
                }
                _ = burst_tick.tick() => {
                    if !pending_burst.is_empty() {
                        let changed = std::mem::take(&mut pending_burst);
                        let config = current_config(&state);
                        yield Ok(backend_payloads::backend_event(&state, &config, changed));
                    }
                }
                _ = slow_tick.tick() => {
                    if !pending_slow.is_empty() {
                        let changed = std::mem::take(&mut pending_slow);
                        let config = current_config(&state);
                        yield Ok(backend_payloads::backend_event(&state, &config, changed));
                    }
                }
                _ = metrics_tick.tick() => {
                    let config = current_config(&state);
                    let event = backend_payloads::backend_event(
                        &state,
                        &config,
                        vec!["process".to_string()],
                    );
                    yield Ok(event);
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub(crate) async fn i18n_payload() -> Json<lang::WebI18nPayload> {
    Json(lang::web_i18n_payload())
}

pub(crate) async fn backend_snapshot(State(state): State<WebAppState>) -> Json<serde_json::Value> {
    let config = current_config(&state);
    Json(backend_payloads::backend_payload_value(
        &state,
        &config,
        full_backend_changed_keys(),
    ))
}

pub(crate) async fn connection_info_snapshot(
    State(state): State<WebAppState>,
) -> Json<serde_json::Value> {
    let config = current_config(&state);
    Json(backend_payloads::backend_payload_value(
        &state,
        &config,
        vec!["connection_info".to_string()],
    ))
}

pub(crate) async fn mitm_status(
    State(state): State<WebAppState>,
) -> Json<backend_payloads::MitmStatusPayload> {
    let config = current_config(&state);
    let fallback = build_mitm_status_fast(&config);
    let status = tokio::task::spawn_blocking(move || build_mitm_status(&config))
        .await
        .unwrap_or(fallback);
    Json(status)
}

fn full_backend_changed_keys() -> Vec<String> {
    vec![
        "status".to_string(),
        "settings".to_string(),
        "traffic".to_string(),
        "patch".to_string(),
        "render".to_string(),
        "adblock".to_string(),
        "resource_replace".to_string(),
        "gateway".to_string(),
        "upstreams".to_string(),
        "upstream_routes".to_string(),
        "dns".to_string(),
        "user_script".to_string(),
    ]
}

pub(crate) async fn reload_rules(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match reload_rewrite_runtime(&state).await {
        Ok(rule_count) => success_feedback(format!(
            "Rewrite 規則已重新載入並熱套用。已載入 {rule_count} 條規則。"
        )),
        Err(error) => error_feedback(lang::format(
            "backend.reload.rules_fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn reload_config(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match RelayGateConfig::load_default_or_builtin().map(|(config, _)| config) {
        Ok(config) => {
            if let Err(error) =
                adblock::reload_shared_state_blocking(&state.adblock_state, &config).await
            {
                return error_feedback(lang::format(
                    "backend.config.adblock_fail",
                    &[("error", error.to_string())],
                ));
            }
            if let Err(error) =
                resource_replace::reload_shared_registry_blocking(&state.resource_replace_registry)
                    .await
            {
                return error_feedback(format!(
                    "Configuration loaded, but resource replacement reload failed: {error}"
                ));
            }
            let routing = current_upstream_routing(&config);
            if let Err(error) = upstream::replace_shared_registry(
                &state.upstreams,
                &routing.upstreams,
                &routing.upstream_routes,
            ) {
                return error_feedback(format!(
                    "Configuration loaded, but upstream reload failed: {error}"
                ));
            }
            if let Err(error) = gateway_mount::replace_shared_registry(
                &state.gateway_mounts,
                &config.gateway.mounts,
            ) {
                return error_feedback(format!(
                    "Configuration loaded, but gateway reload failed: {error}"
                ));
            }
            match DnsConfig::load_default_or_default() {
                Ok(dns_config) => {
                    if let Err(error) = dns_config.validate() {
                        return error_feedback(format!(
                            "Configuration loaded, but DNS reload failed: {error}"
                        ));
                    }
                    if let Err(error) = dns::replace_shared_config(&state.dns_resolver, dns_config)
                    {
                        return error_feedback(format!(
                            "Configuration loaded, but DNS reload failed: {error}"
                        ));
                    }
                }
                Err(error) => {
                    return error_feedback(format!(
                        "Configuration loaded, but DNS reload failed: {error}"
                    ));
                }
            }
            state.protocol_runtime.replace_from_config(&config);
            store_current_config(&state, config);
            state.runtime.notify_backend_changed(&[
                "status",
                "settings",
                "traffic",
                "patch",
                "render",
                "adblock",
                "resource_replace",
                "i18n",
                "gateway",
                "upstreams",
                "upstream_routes",
                "dns",
            ]);
            success_feedback(lang::text("backend.config.ok"))
        }
        Err(error) => error_feedback(lang::format(
            "backend.config.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn reload_resource_replace(
    State(state): State<WebAppState>,
) -> Json<ActionFeedbackPayload> {
    match reload_resource_replace_runtime(&state).await {
        Ok(rule_count) => success_feedback(format!(
            "Resource Replace 規則已重新載入並熱套用。已載入 {rule_count} 條規則。"
        )),
        Err(error) => error_feedback(format!(
            "Failed to reload resource replacement rules: {error}"
        )),
    }
}

pub(crate) async fn create_ca(State(_state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match mitm::create_and_trust_local_ca() {
        Ok(()) => {
            _state
                .runtime
                .notify_backend_changed(&["settings", "status"]);
            let config = current_config(&_state);
            let mitm = build_mitm_status(&config);
            if mitm.windows_user_root_trusted == Some(true) {
                success_feedback(lang::text("backend.ca.ok"))
            } else {
                success_feedback(lang::text("backend.ca.unverified"))
            }
        }
        Err(error) => error_feedback(lang::format(
            "backend.ca.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn remove_ca_trust(
    State(_state): State<WebAppState>,
) -> Json<ActionFeedbackPayload> {
    match remove_ca_windows_trust_only() {
        Ok(message) => {
            _state
                .runtime
                .notify_backend_changed(&["settings", "status"]);
            success_feedback(message)
        }
        Err(error) => error_feedback(lang::format(
            "backend.ca.remove_fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn remove_windows_relaygate_ca_trust(
    State(_state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_delete_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => {
            return error_feedback(format!("Invalid CA remove request: {error}"));
        }
    };

    match remove_windows_relaygate_ca(&form.id) {
        Ok(message) => {
            _state
                .runtime
                .notify_backend_changed(&["settings", "status"]);
            success_feedback(message)
        }
        Err(error) => error_feedback(lang::format(
            "backend.ca.remove_fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn exit_app(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    state.runtime.request_shutdown();
    success_feedback(lang::text("backend.exit.ok"))
}

pub(crate) async fn update_setting(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_update_setting_from_body(&body) {
        Ok(form) => form,
        Err(error) => {
            return error_feedback(lang::format(
                "backend.save.fail",
                &[("error", error.to_string())],
            ))
        }
    };
    match update_single_setting(&state, &form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(lang::format(
            "backend.save.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn update_protocol_settings(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_protocol_settings_from_body(&body) {
        Ok(form) => form,
        Err(error) => {
            return error_feedback(lang::format(
                "backend.save.fail",
                &[("error", error.to_string())],
            ))
        }
    };
    match update_protocol_settings_config(&state, &form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(lang::format(
            "backend.save.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn add_upstream(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_upstream_form_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match add_upstream_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn toggle_upstream(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_toggle_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match toggle_upstream_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn delete_upstream(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_delete_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match delete_upstream_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn add_upstream_route(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_upstream_route_form_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match add_upstream_route_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn toggle_upstream_route(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_toggle_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match toggle_upstream_route_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn delete_upstream_route(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_delete_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match delete_upstream_route_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn add_dns_profile(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_dns_profile_form_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match add_dns_profile_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn toggle_dns_profile(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_toggle_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match toggle_dns_profile_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn delete_dns_profile(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_delete_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match delete_dns_profile_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn move_dns_profile(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_move_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match move_dns_profile_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn add_dns_route(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_dns_route_form_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match add_dns_route_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn toggle_dns_route(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_toggle_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match toggle_dns_route_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn delete_dns_route(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_delete_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match delete_dns_route_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn toggle_dns_feature(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_dns_feature_toggle_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match toggle_dns_feature_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn add_gateway_mount(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_gateway_mount_form_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match add_gateway_mount_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn toggle_gateway_mount(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_toggle_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match toggle_gateway_mount_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn delete_gateway_mount(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_delete_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match delete_gateway_mount_config(&state, form) {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn toggle_resource_replace_rule(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_toggle_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("Save failed: {error}")),
    };
    match toggle_resource_replace_rule_config(&state, form).await {
        Ok(message) => success_feedback(message),
        Err(error) => error_feedback(format!("Save failed: {error}")),
    }
}

pub(crate) async fn rescan_user_scripts(
    State(state): State<WebAppState>,
) -> Json<ActionFeedbackPayload> {
    match reload_user_script_runtime(&state) {
        Ok(count) => success_feedback(format!(
            "User Script 已重新掃描並熱套用。已載入 {count} 個腳本。"
        )),
        Err(error) => error_feedback(format!("User Script rescan failed: {error}")),
    }
}

pub(crate) async fn toggle_user_script(
    State(state): State<WebAppState>,
    body: Bytes,
) -> Json<ActionFeedbackPayload> {
    let form = match parse_toggle_item_from_body(&body) {
        Ok(form) => form,
        Err(error) => return error_feedback(format!("User Script state update failed: {error}")),
    };
    match user_script::set_enabled_default(
        &state.user_script_registry,
        &form.id,
        parse_bool(&form.enabled).unwrap_or(false),
    ) {
        Ok(count) => {
            state
                .runtime
                .notify_backend_changed(&["status", "user_script"]);
            success_feedback(format!(
                "User Script 狀態已儲存並熱套用。已載入 {count} 個腳本。"
            ))
        }
        Err(error) => error_feedback(format!("User Script state update failed: {error}")),
    }
}

pub(crate) async fn open_user_script_folder(
    State(_state): State<WebAppState>,
) -> Json<ActionFeedbackPayload> {
    match open_folder(&user_script::script_dir()) {
        Ok(()) => success_feedback("User Script folder opened."),
        Err(error) => error_feedback(format!("Failed to open User Script folder: {error}")),
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ActionFeedbackPayload {
    ok: bool,
    level: &'static str,
    message: String,
}

fn json_named_event<T: Serialize>(name: &'static str, payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().event(name).data(data)
}
