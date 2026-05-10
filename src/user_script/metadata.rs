use anyhow::Result;

use super::model::{UserScriptMetadata, UserScriptStatus};

pub(crate) fn parse_metadata_block(block: &str) -> Result<UserScriptMetadata> {
    let mut metadata = UserScriptMetadata::default();

    for line in block.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("//") else {
            continue;
        };
        let rest = rest.trim();
        let Some(rest) = rest.strip_prefix('@') else {
            continue;
        };
        let (key, value) = rest
            .split_once(char::is_whitespace)
            .map(|(key, value)| (key.trim(), value.trim()))
            .unwrap_or((rest.trim(), ""));
        match key {
            "name" => metadata.name = Some(value.to_string()),
            "namespace" => metadata.namespace = Some(value.to_string()),
            "version" => metadata.version = Some(value.to_string()),
            "description" => metadata.description = Some(value.to_string()),
            "match" => metadata.matches.push(value.to_string()),
            "include" => metadata.includes.push(value.to_string()),
            "exclude" => metadata.excludes.push(value.to_string()),
            "run-at" => metadata.run_at = Some(value.to_string()),
            "grant" => metadata.grants.push(value.to_string()),
            "inject-into" => metadata.inject_into = Some(value.to_string()),
            "noframes" => metadata.noframes = true,
            "require" => metadata.requires.push(value.to_string()),
            "connect" => metadata.connects.push(value.to_string()),
            _ => {}
        }
    }

    Ok(metadata)
}

pub(crate) fn classify_metadata(metadata: &UserScriptMetadata) -> UserScriptStatus {
    if metadata.matches.is_empty() && metadata.includes.is_empty() {
        return UserScriptStatus::Unsupported;
    }

    if !metadata.requires.is_empty() || !metadata.connects.is_empty() {
        return UserScriptStatus::Unsupported;
    }

    let partial_grant = metadata.grants.iter().any(|grant| {
        matches!(
            grant.as_str(),
            "GM_getValue"
                | "GM_setValue"
                | "GM_deleteValue"
                | "GM_listValues"
                | "GM_addValueChangeListener"
                | "GM_removeValueChangeListener"
                | "GM_openInTab"
                | "GM_xmlhttpRequest"
                | "GM.xmlHttpRequest"
        )
    }) || matches!(
        metadata.inject_into.as_deref(),
        Some("content") | Some("Content")
    );

    if partial_grant {
        UserScriptStatus::Partial
    } else {
        UserScriptStatus::Supported
    }
}
