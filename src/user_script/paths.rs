use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};

use crate::path_mode::{app_path_mode, AppPathMode};

const USER_SCRIPT_DIR_NAME: &str = "user_script";
const USER_SCRIPT_STATE_FILE_NAME: &str = "user_script.bin";

pub fn script_dir() -> PathBuf {
    preferred_base_dir()
        .join("data")
        .join("user")
        .join(USER_SCRIPT_DIR_NAME)
}

pub(crate) fn ensure_script_dir_ready() -> Result<PathBuf> {
    let dir = script_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create user script dir: {}", dir.display()))?;
    Ok(dir)
}

pub(crate) fn store_path() -> PathBuf {
    preferred_base_dir()
        .join("data")
        .join("state")
        .join(USER_SCRIPT_STATE_FILE_NAME)
}

fn preferred_base_dir() -> PathBuf {
    match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(".")),
    }
}
