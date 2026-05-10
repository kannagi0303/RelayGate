use std::{convert::Infallible, time::Duration};

use crate::{
    adblock,
    config::{DnsConfig, RelayGateConfig},
    dns, lang,
    proxy::{mitm, resource_replace, upstream},
    user_script,
    web::{
        action_forms::{
            parse_delete_item_from_body, parse_dns_profile_form_from_body,
            parse_dns_route_form_from_body, parse_gateway_mount_form_from_body,
            parse_move_item_from_body, parse_protocol_settings_from_body,
            parse_toggle_item_from_body, parse_update_setting_from_body,
            parse_upstream_form_from_body, parse_upstream_route_form_from_body,
        },
        backend_payloads,
        config_actions::{
            add_dns_profile_config, add_dns_route_config, add_gateway_mount_config,
            add_upstream_config, add_upstream_route_config, current_config,
            current_upstream_routing, delete_dns_profile_config, delete_dns_route_config,
            delete_gateway_mount_config, delete_upstream_config, delete_upstream_route_config,
            move_dns_profile_config, parse_bool, reload_resource_replace_runtime,
            reload_rewrite_runtime, reload_user_script_runtime, store_current_config,
            toggle_dns_profile_config, toggle_dns_route_config, toggle_gateway_mount_config,
            toggle_resource_replace_rule_config, toggle_upstream_config,
            toggle_upstream_route_config, update_protocol_settings_config, update_single_setting,
        },
        server::WebAppState,
        system_actions::{
            build_mitm_status, open_folder, remove_ca_windows_trust_only,
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

pub(crate) async fn backend_events(
    State(state): State<WebAppState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let stream = stream! {
        let mut changes = state.runtime.subscribe_backend_changes();
        let config = current_config(&state);
        let event = backend_payloads::backend_event(
            &state,
            &config,
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
            ],
        );
        yield Ok(json_named_event("i18n_full", &lang::web_i18n_payload()));
        yield Ok(event);

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
                    let config = current_config(&state);
                    yield Ok(backend_payloads::backend_event(&state, &config, signal.changed));
                }
                _ = metrics_tick.tick() => {
                    let config = current_config(&state);
                    let event = backend_payloads::backend_event(
                        &state,
                        &config,
                        vec!["status".to_string()],
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

pub(crate) async fn reload_rules(State(state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match reload_rewrite_runtime(&state) {
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
    match RelayGateConfig::load_from_path(state.config_path.as_ref()) {
        Ok(config) => {
            if let Err(error) = adblock::reload_shared_state(&state.adblock_state, &config) {
                return error_feedback(lang::format(
                    "backend.config.adblock_fail",
                    &[("error", error.to_string())],
                ));
            }
            if let Err(error) =
                resource_replace::reload_shared_registry(&state.resource_replace_registry)
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
            match DnsConfig::load_default_or_default() {
                Ok(dns_config) => {
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
            state.runtime.notify_status_changed();
            state.runtime.notify_settings_changed();
            state.runtime.notify_traffic_changed();
            state.runtime.notify_patch_changed();
            state.runtime.notify_render_changed();
            state.runtime.notify_adblock_changed();
            state.runtime.notify_resource_replace_changed();
            state.runtime.notify_i18n_changed();
            state.runtime.notify_backend_changed(&["gateway", "dns"]);
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
    match reload_resource_replace_runtime(&state) {
        Ok(rule_count) => success_feedback(format!(
            "Resource Replace 規則已重新載入並熱套用。已載入 {rule_count} 條規則。"
        )),
        Err(error) => error_feedback(format!(
            "Failed to reload resource replacement rules: {error}"
        )),
    }
}

pub(crate) async fn update_adblock_lists(
    State(state): State<WebAppState>,
) -> Json<ActionFeedbackPayload> {
    match adblock::sync_default_resources_forced().await {
        Ok(files) => {
            let config = current_config(&state);
            let count = match adblock::reload_shared_state(&state.adblock_state, &config) {
                Ok(count) => count,
                Err(error) => {
                    return error_feedback(lang::format(
                        "backend.sync.reload_fail",
                        &[("error", error.to_string())],
                    ));
                }
            };
            state.runtime.notify_status_changed();
            state.runtime.notify_patch_changed();
            state.runtime.notify_render_changed();
            state.runtime.notify_adblock_changed();
            success_feedback(lang::format(
                "backend.sync.ok",
                &[
                    ("files", files.join("、")),
                    ("rule_count", count.to_string()),
                    (
                        "resource_count",
                        adblock::resource_count(&state.adblock_state).to_string(),
                    ),
                ],
            ))
        }
        Err(error) => error_feedback(lang::format(
            "backend.sync.fail",
            &[("error", error.to_string())],
        )),
    }
}

pub(crate) async fn reload_adblock_rules(
    State(state): State<WebAppState>,
) -> Json<ActionFeedbackPayload> {
    let config = current_config(&state);
    match adblock::reload_shared_state(&state.adblock_state, &config) {
        Ok(count) => {
            state.runtime.notify_status_changed();
            state.runtime.notify_patch_changed();
            state.runtime.notify_render_changed();
            state.runtime.notify_adblock_changed();
            success_feedback(format!("Adblock 規則已重新載入。已載入 {count} 條規則。"))
        }
        Err(error) => error_feedback(format!("Adblock 規則重新載入失敗：{error}")),
    }
}

pub(crate) async fn open_adblock_rules_folder(
    State(_state): State<WebAppState>,
) -> Json<ActionFeedbackPayload> {
    match adblock::custom_rule_file_path() {
        Ok(_) => {
            let dir = adblock::adblock_rule_dir_path();
            match open_folder(&dir) {
                Ok(()) => success_feedback(format!("已開啟 Adblock 規則資料夾：{}", dir.display())),
                Err(error) => error_feedback(format!("無法開啟 Adblock 規則資料夾：{error}")),
            }
        }
        Err(error) => error_feedback(format!("無法建立 custom.txt：{error}")),
    }
}

pub(crate) async fn create_ca(State(_state): State<WebAppState>) -> Json<ActionFeedbackPayload> {
    match mitm::create_and_trust_local_ca() {
        Ok(()) => {
            _state.runtime.notify_settings_changed();
            _state.runtime.notify_status_changed();
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
            _state.runtime.notify_settings_changed();
            _state.runtime.notify_status_changed();
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
            _state.runtime.notify_settings_changed();
            _state.runtime.notify_status_changed();
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
    match toggle_resource_replace_rule_config(&state, form) {
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
            state.runtime.notify_status_changed();
            state.runtime.notify_user_script_changed();
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
