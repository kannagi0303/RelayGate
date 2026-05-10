use std::{
    env,
    path::{Path, PathBuf},
};

use crate::path_mode::{app_path_mode, AppPathMode};

const USER_SCRIPT_DIR_NAME: &str = "user_script";

pub(crate) const ENABLED_FILE_NAME: &str = "enabled.yaml";

pub fn script_dir() -> PathBuf {
    preferred_base_dir().join("data").join(USER_SCRIPT_DIR_NAME)
}

fn preferred_base_dir() -> PathBuf {
    match app_path_mode() {
        AppPathMode::Workspace => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        AppPathMode::Portable => env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from(".")),
    }
}
