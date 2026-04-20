use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::sync::{watch, Notify};

/// Shared runtime state.
/// Current use:
/// - lets web and tray request shutdown
#[derive(Clone)]
pub struct AppRuntime {
    inner: Arc<RuntimeInner>,
}

#[derive(Clone, Debug)]
pub struct BackendSignal {
    pub version: u64,
    pub changed: Vec<String>,
}

struct RuntimeInner {
    shutdown_notify: Notify,
    session_id: String,
    backend_change_tx: watch::Sender<BackendSignal>,
}

impl AppRuntime {
    pub fn new() -> Self {
        let (backend_change_tx, _backend_change_rx) = watch::channel(BackendSignal {
            version: 0,
            changed: Vec::new(),
        });
        Self {
            inner: Arc::new(RuntimeInner {
                shutdown_notify: Notify::new(),
                session_id: make_session_id(),
                backend_change_tx,
            }),
        }
    }

    pub fn request_shutdown(&self) {
        self.inner.shutdown_notify.notify_waiters();
        self.notify_status_changed();
    }

    pub async fn wait_for_shutdown(&self) {
        self.inner.shutdown_notify.notified().await;
    }

    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn subscribe_backend_changes(&self) -> watch::Receiver<BackendSignal> {
        self.inner.backend_change_tx.subscribe()
    }

    pub fn notify_status_changed(&self) {
        self.notify_backend_changed(&["status"]);
    }

    pub fn notify_adblock_changed(&self) {
        self.notify_backend_changed(&["adblock"]);
    }

    pub fn notify_settings_changed(&self) {
        self.notify_backend_changed(&["settings"]);
    }

    pub fn notify_traffic_changed(&self) {
        self.notify_backend_changed(&["traffic"]);
    }

    pub fn notify_patch_changed(&self) {
        self.notify_backend_changed(&["patch"]);
    }

    pub fn notify_render_changed(&self) {
        self.notify_backend_changed(&["render"]);
    }

    pub fn notify_backend_changed(&self, changed: &[&str]) {
        let current = self.inner.backend_change_tx.borrow().clone();
        let next = BackendSignal {
            version: current.version.wrapping_add(1),
            changed: changed.iter().map(|item| (*item).to_string()).collect(),
        };
        let _ = self.inner.backend_change_tx.send(next);
    }
}

fn make_session_id() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    format!("rg-{}", now.as_millis())
}
