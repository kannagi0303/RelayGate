use super::model::{RunAt, UserScriptEntry, UserScriptMetadata};

const STORAGE_PREFIX_BASE: &str = "__RelayGate_UserScript__";

pub(crate) fn build_script_tag(script: &str) -> String {
    // TODO(User Script): handle source text containing `</script>` without changing the
    // original script body semantics.
    format!(r#"<script data-relaygate-user-script="1">{script}</script>"#)
}

pub(crate) fn build_wrapper(
    entry: &UserScriptEntry,
    metadata: &UserScriptMetadata,
    source: &str,
) -> String {
    let run_at = RunAt::from_metadata(metadata.run_at.as_ref());
    let storage_prefix = storage_prefix(entry, metadata);
    let storage_prefix_json =
        serde_json::to_string(&storage_prefix).unwrap_or_else(|_| "\"\"".to_string());
    let filename_json =
        serde_json::to_string(&entry.filename).unwrap_or_else(|_| "\"\"".to_string());
    let body = format!(
        r#"
(() => {{
{runtime_shim}
  const RGGM = createRelayGateUserScriptRuntime({{ storagePrefix: {storage_prefix_json}, filename: {filename_json} }});
  const GM_addStyle = RGGM.addStyle;
  const GM_getValue = RGGM.getValueSync;
  const GM_setValue = RGGM.setValueSync;
  const GM_deleteValue = RGGM.deleteValueSync;
  const GM_listValues = RGGM.listValuesSync;
  const GM_addValueChangeListener = RGGM.addValueChangeListener;
  const GM_removeValueChangeListener = RGGM.removeValueChangeListener;
  const GM_openInTab = RGGM.openInTab;
  const GM_xmlhttpRequest = RGGM.xmlhttpRequest;
  const GM = {{
    addStyle: RGGM.addStyle,
    getValue: RGGM.getValue,
    setValue: RGGM.setValue,
    deleteValue: RGGM.deleteValue,
    listValues: RGGM.listValues,
    openInTab: RGGM.openInTab,
    xmlHttpRequest: RGGM.xmlhttpRequest
  }};
{source}
}})();
"#,
        runtime_shim = runtime_shim_js(),
        storage_prefix_json = storage_prefix_json,
        filename_json = filename_json,
        source = source
    );

    match run_at {
        RunAt::DocumentStart => body,
        RunAt::DocumentEnd => timed_wrapper_js("document-end", &body),
        RunAt::DocumentIdle => timed_wrapper_js("document-idle", &body),
    }
}

fn timed_wrapper_js(run_at: &str, body: &str) -> String {
    format!(
        r#"(function() {{
  const run = function() {{
{body}
  }};
  if ({run_at:?} === "document-end") {{
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run, {{ once: true }});
    else run();
  }} else {{
    const afterReady = function() {{
      if (window.requestIdleCallback) window.requestIdleCallback(run);
      else window.setTimeout(run, 1);
    }};
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", afterReady, {{ once: true }});
    else afterReady();
  }}
}})();"#
    )
}

fn runtime_shim_js() -> &'static str {
    include_str!("runtime_shim.js")
}

fn storage_prefix(entry: &UserScriptEntry, metadata: &UserScriptMetadata) -> String {
    match (&metadata.namespace, &metadata.name) {
        (Some(namespace), Some(name)) if !namespace.is_empty() && !name.is_empty() => {
            format!("{STORAGE_PREFIX_BASE}:{namespace}:{name}:")
        }
        _ => format!("{STORAGE_PREFIX_BASE}:{}:", entry.filename),
    }
}
