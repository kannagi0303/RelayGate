use crate::{
    config::{AdblockMode, RelayGateConfig},
    lang,
};

use super::routes::MitmStatusPayload;

const INDEX_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/index.html"
));
const STATUS_PANEL_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/panels/status.html"
));
const SETTINGS_PANEL_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/panels/settings.html"
));
const TRAFFIC_PANEL_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/panels/traffic.html"
));
const PATCH_PANEL_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/panels/patch.html"
));
const RENDER_PANEL_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/panels/render.html"
));
const ADBLOCK_PANEL_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/panels/adblock.html"
));
const CA_CARD_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/partials/ca_card.html"
));
const TEXT_SETTING_ROW_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/partials/text_setting_row.html"
));
const SELECT_SETTING_ROW_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/partials/select_setting_row.html"
));
const SELECT_OPTION_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/web/partials/select_option.html"
));

pub(crate) fn render_index(
    app_name: &str,
    session_id: &str,
    status_panel: &str,
    settings_panel: &str,
    traffic_panel: &str,
    patch_panel: &str,
    render_panel: &str,
    adblock_panel: &str,
) -> String {
    let session_id_json = serde_json::to_string(session_id).unwrap_or_else(|_| "\"\"".to_string());
    let html_lang = lang::text("meta.locale");
    let page_title = html_escape(&format!("{app_name} {}", lang::text("app.title")));
    let app_title_json = json_string(&lang::text("app.title"));
    let app_online_json = json_string(&lang::text("app.online"));
    let app_offline_json = json_string(&lang::text("app.offline"));
    let adblock_rules_none_json = json_string(&lang::text("adblock.rules.none"));
    let adblock_resources_none_json = json_string(&lang::text("adblock.resources.none"));
    let common_bytes_json = json_string(&lang::text("common.bytes"));
    let common_none_json = json_string(&lang::text("common.none"));
    let common_yes_json = json_string(&lang::text("common.yes"));
    let common_no_json = json_string(&lang::text("common.no"));
    let common_enabled_json = json_string(&lang::text("common.enabled"));
    let common_disabled_json = json_string(&lang::text("common.disabled"));
    let traffic_host_none_json = json_string(&lang::text("traffic_page.host.none"));

    render_template(
        INDEX_TEMPLATE,
        &[
            ("__HTML_LANG__", &html_lang),
            ("__PAGE_TITLE__", &page_title),
            ("__APP_TITLE_JSON__", &app_title_json),
            ("__APP_ONLINE_JSON__", &app_online_json),
            ("__APP_OFFLINE_JSON__", &app_offline_json),
            ("__ADBLOCK_RULES_NONE_JSON__", &adblock_rules_none_json),
            (
                "__ADBLOCK_RESOURCES_NONE_JSON__",
                &adblock_resources_none_json,
            ),
            ("__COMMON_BYTES_JSON__", &common_bytes_json),
            ("__COMMON_NONE_JSON__", &common_none_json),
            ("__COMMON_YES_JSON__", &common_yes_json),
            ("__COMMON_NO_JSON__", &common_no_json),
            ("__COMMON_ENABLED_JSON__", &common_enabled_json),
            ("__COMMON_DISABLED_JSON__", &common_disabled_json),
            ("__TRAFFIC_HOST_NONE_JSON__", &traffic_host_none_json),
        ],
    )
    .replace("__APP_NAME__", &html_escape(app_name))
    .replace("__STATUS_PANEL__", status_panel)
    .replace("__SETTINGS_PANEL__", settings_panel)
    .replace("__TRAFFIC_PANEL__", traffic_panel)
    .replace("__PATCH_PANEL__", patch_panel)
    .replace("__RENDER_PANEL__", render_panel)
    .replace("__ADBLOCK_PANEL__", adblock_panel)
    .replace("__SESSION_ID__", &session_id_json)
}

pub(crate) fn render_status_panel() -> String {
    render_template(STATUS_PANEL_TEMPLATE, &[])
}

pub(crate) fn render_settings_panel(config: &RelayGateConfig, mitm: &MitmStatusPayload) -> String {
    render_template(
        SETTINGS_PANEL_TEMPLATE,
        &[
            (
                "__APP_NAME_ROW__",
                &text_setting_row_with_id(
                    &lang::text("settings.app_name.label"),
                    "app.name",
                    &config.app.name,
                    &lang::text("settings.app_name.note"),
                    "settings-app-name-input",
                ),
            ),
            (
                "__PROXY_LISTEN_ROW__",
                &text_setting_row_with_id(
                    &lang::text("settings.proxy.label"),
                    "proxy.listen",
                    &config.proxy.listen,
                    &lang::text("settings.proxy.note"),
                    "settings-proxy-listen-input",
                ),
            ),
            (
                "__WEB_LISTEN_ROW__",
                &text_setting_row_with_id(
                    &lang::text("settings.web.label"),
                    "web.listen",
                    &config.web.listen,
                    &lang::text("settings.web.note"),
                    "settings-web-listen-input",
                ),
            ),
            ("__CA_CARD__", &render_ca_card(mitm)),
        ],
    )
}

pub(crate) fn render_traffic_panel() -> String {
    render_template(TRAFFIC_PANEL_TEMPLATE, &[])
}

pub(crate) fn render_patch_panel() -> String {
    render_template(PATCH_PANEL_TEMPLATE, &[])
}

pub(crate) fn render_render_panel() -> String {
    render_template(RENDER_PANEL_TEMPLATE, &[])
}

pub(crate) fn render_adblock_panel(config: &RelayGateConfig) -> String {
    render_template(
        ADBLOCK_PANEL_TEMPLATE,
        &[(
            "__ADBLOCK_MODE_ROW__",
            &select_setting_row_with_id(
                &lang::text("settings.adblock.label"),
                "proxy.adblock.mode",
                adblock_mode_value(config.proxy.adblock.effective_mode()),
                &[
                    ("disabled", lang::text("adblock.mode.off")),
                    ("standard", lang::text("adblock.mode.std")),
                    ("aggressive", lang::text("adblock.mode.agg")),
                ],
                &lang::text("settings.adblock.note"),
                "adblock-feedback",
                "adblock-mode-select",
            ),
        )],
    )
}

fn render_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let rendered = replacements
        .iter()
        .fold(template.to_string(), |output, (from, to)| {
            output.replace(from, to)
        });
    render_lang_template(&rendered)
}

fn render_ca_card(mitm: &MitmStatusPayload) -> String {
    let none = lang::text("common.none");
    let yes = lang::text("common.yes");
    let no = lang::text("common.no");
    let cert = if mitm.ca_cert_exists {
        html_escape(&mitm.ca_cert_path)
    } else {
        none.clone()
    };
    let key = if mitm.ca_key_exists {
        html_escape(&mitm.ca_key_path)
    } else {
        none
    };
    let trust = match mitm.windows_user_root_trusted {
        Some(true) => yes,
        Some(false) | None => no,
    };

    render_template(
        CA_CARD_TEMPLATE,
        &[
            ("__CA_CERT__", &cert),
            ("__CA_KEY__", &key),
            ("__CA_TRUST__", &trust),
            ("__CA_FEEDBACK__", ""),
        ],
    )
}

fn text_setting_row_with_id(
    label: &str,
    key: &str,
    value: &str,
    note: &str,
    input_id: &str,
) -> String {
    render_template(
        TEXT_SETTING_ROW_TEMPLATE,
        &[
            ("__LABEL__", &html_escape(label)),
            ("__NOTE__", &html_escape(note)),
            ("__KEY__", &html_escape(key)),
            ("__VALUE__", &html_escape(value)),
            ("__INPUT_ID_ATTR__", &optional_id_attr(input_id)),
        ],
    )
}

fn select_setting_row_with_id(
    label: &str,
    key: &str,
    value: &str,
    options: &[(&str, String)],
    note: &str,
    feedback_target: &str,
    select_id: &str,
) -> String {
    let option_html = options
        .iter()
        .map(|(option_value, option_label)| {
            render_template(
                SELECT_OPTION_TEMPLATE,
                &[
                    ("__VALUE__", &html_escape(option_value)),
                    (
                        "__SELECTED_ATTR__",
                        if *option_value == value {
                            "selected"
                        } else {
                            ""
                        },
                    ),
                    ("__LABEL__", &html_escape(option_label)),
                ],
            )
        })
        .collect::<Vec<_>>()
        .join("");

    render_template(
        SELECT_SETTING_ROW_TEMPLATE,
        &[
            ("__LABEL__", &html_escape(label)),
            ("__NOTE__", &html_escape(note)),
            ("__KEY__", &html_escape(key)),
            ("__OPTION_HTML__", &option_html),
            ("__FEEDBACK_TARGET__", &html_escape(feedback_target)),
            ("__SELECT_ID_ATTR__", &optional_id_attr(select_id)),
        ],
    )
}

fn optional_id_attr(id: &str) -> String {
    if id.is_empty() {
        String::new()
    } else {
        format!(r#"id="{}""#, html_escape(id))
    }
}

fn render_lang_template(template: &str) -> String {
    let with_raw = replace_lang_tokens(template, "{{{", "}}}", |key| lang::text(key));
    replace_lang_tokens(&with_raw, "{{", "}}", |key| html_escape(&lang::text(key)))
}

fn replace_lang_tokens(
    template: &str,
    start: &str,
    end: &str,
    mut resolve: impl FnMut(&str) -> String,
) -> String {
    let mut output = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start_index) = remaining.find(start) {
        output.push_str(&remaining[..start_index]);
        let after_start = &remaining[start_index + start.len()..];
        let Some(end_index) = after_start.find(end) else {
            output.push_str(&remaining[start_index..]);
            return output;
        };
        let key = after_start[..end_index].trim();
        output.push_str(&resolve(key));
        remaining = &after_start[end_index + end.len()..];
    }

    output.push_str(remaining);
    output
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn adblock_mode_value(mode: Option<AdblockMode>) -> &'static str {
    match mode {
        None => "disabled",
        Some(AdblockMode::Standard) => "standard",
        Some(AdblockMode::Aggressive) => "aggressive",
    }
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
