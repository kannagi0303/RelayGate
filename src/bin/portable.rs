#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use relaygate::{bootstrap, path_mode::AppPathMode};

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap::run(AppPathMode::Portable).await
}
