use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::runtime::AppRuntime;

use super::{paths::ensure_script_dir_ready, SharedUserScriptRegistry};

const USER_SCRIPT_WATCH_DEBOUNCE: Duration = Duration::from_millis(800);

pub(crate) struct UserScriptWatcher {
    _watcher: RecommendedWatcher,
}

enum WatchMessage {
    Dirty,
    Error(String),
}

pub(crate) fn start_auto_reload_watcher(
    registry: SharedUserScriptRegistry,
    runtime: AppRuntime,
) -> Result<UserScriptWatcher> {
    let dir = ensure_script_dir_ready()?;
    let (tx, rx) = mpsc::unbounded_channel::<WatchMessage>();
    let watched_dir = dir.clone();
    let callback_tx = tx.clone();

    let mut watcher =
        notify::recommended_watcher(move |result: notify::Result<Event>| match result {
            Ok(event) => {
                if event_requires_reload(&watched_dir, &event) {
                    let _ = callback_tx.send(WatchMessage::Dirty);
                } else {
                    debug!(
                        kind = ?event.kind,
                        paths = ?event.paths,
                        "ignored user script watcher event"
                    );
                }
            }
            Err(error) => {
                let _ = callback_tx.send(WatchMessage::Error(error.to_string()));
            }
        })
        .context("failed to create user script file watcher")?;

    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to watch user script dir: {}", dir.display()))?;

    tokio::spawn(run_reload_loop(rx, registry, runtime, dir.clone()));

    info!(dir = %dir.display(), "watching user script dir for changes");
    Ok(UserScriptWatcher { _watcher: watcher })
}

async fn run_reload_loop(
    mut rx: mpsc::UnboundedReceiver<WatchMessage>,
    registry: SharedUserScriptRegistry,
    runtime: AppRuntime,
    dir: PathBuf,
) {
    while let Some(message) = rx.recv().await {
        if let WatchMessage::Error(error) = message {
            warn!(error = %error, "user script watcher error");
            continue;
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(USER_SCRIPT_WATCH_DEBOUNCE) => break,
                next = rx.recv() => match next {
                    Some(WatchMessage::Dirty) => continue,
                    Some(WatchMessage::Error(error)) => {
                        warn!(error = %error, "user script watcher error");
                        continue;
                    }
                    None => return,
                },
            }
        }

        let registry = registry.clone();
        match tokio::task::spawn_blocking(move || super::reload_shared_registry(&registry)).await {
            Ok(Ok(count)) => {
                info!(dir = %dir.display(), scripts = count, "user script changes reloaded");
                runtime.notify_backend_changed(&["status", "user_script"]);
            }
            Ok(Err(error)) => {
                warn!(dir = %dir.display(), error = %error, "failed to reload user script changes");
            }
            Err(error) => {
                warn!(dir = %dir.display(), error = %error, "user script reload task failed");
            }
        }
    }
}

fn event_requires_reload(script_dir: &Path, event: &Event) -> bool {
    if matches!(event.kind, EventKind::Access(_)) {
        return false;
    }

    if event.paths.is_empty() {
        return true;
    }

    event
        .paths
        .iter()
        .any(|path| path_requires_reload(script_dir, path))
}

fn path_requires_reload(script_dir: &Path, path: &Path) -> bool {
    if path == script_dir {
        return true;
    }

    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };

    if file_name.ends_with(".tmp") {
        return false;
    }

    file_name.ends_with(".user.js")
}
