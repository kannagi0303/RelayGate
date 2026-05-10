use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserScriptStatus {
    Supported,
    Partial,
    Unsupported,
    Error,
}

impl UserScriptStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Supported => "支援",
            Self::Partial => "部分支援",
            Self::Unsupported => "尚未支援",
            Self::Error => "錯誤",
        }
    }

    pub(crate) fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunAt {
    DocumentStart,
    DocumentEnd,
    DocumentIdle,
}

impl RunAt {
    pub(crate) fn from_metadata(value: Option<&String>) -> Self {
        match value.map(|item| item.trim()) {
            Some("document-start") => Self::DocumentStart,
            Some("document-end") => Self::DocumentEnd,
            _ => Self::DocumentIdle,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UserScriptMetadata {
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub matches: Vec<String>,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub run_at: Option<String>,
    pub grants: Vec<String>,
    pub inject_into: Option<String>,
    pub noframes: bool,
    pub requires: Vec<String>,
    pub connects: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserScriptListItem {
    pub filename: String,
    pub status: UserScriptStatus,
    pub status_label: String,
    pub name: String,
    pub version: String,
    pub match_summary: String,
    pub enabled: bool,
    pub operable: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct UserScriptEntry {
    pub(crate) filename: String,
    pub(crate) path: PathBuf,
    pub(crate) metadata: Option<UserScriptMetadata>,
    pub(crate) status: UserScriptStatus,
    pub(crate) error: Option<String>,
    pub(crate) enabled: bool,
}
