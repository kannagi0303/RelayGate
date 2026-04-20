use std::sync::OnceLock;

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppPathMode {
    Workspace,
    Portable,
}

static APP_PATH_MODE: OnceLock<AppPathMode> = OnceLock::new();

pub fn set_app_path_mode(mode: AppPathMode) -> Result<()> {
    APP_PATH_MODE
        .set(mode)
        .map_err(|_| anyhow::anyhow!("application path mode has already been initialized"))
}

pub fn app_path_mode() -> AppPathMode {
    APP_PATH_MODE
        .get()
        .copied()
        .unwrap_or(AppPathMode::Workspace)
}
