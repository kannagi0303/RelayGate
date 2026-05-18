use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use tracing::{debug, warn};

#[derive(Clone)]
pub(super) struct ControlPanelOpenGuard {
    url: String,
    opening: Arc<AtomicBool>,
    last_started: Arc<Mutex<Option<Instant>>>,
    min_interval: Duration,
}

impl ControlPanelOpenGuard {
    pub(super) fn new(web_listen: String, min_interval: Duration) -> Self {
        Self {
            url: format!("http://{}/", browser_open_address(&web_listen)),
            opening: Arc::new(AtomicBool::new(false)),
            last_started: Arc::new(Mutex::new(None)),
            min_interval,
        }
    }

    pub(super) fn request_open(&self, source: &'static str) {
        if self
            .opening
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            debug!(
                source = source,
                "ignored tray open request while previous request is still running"
            );
            return;
        }

        let now = Instant::now();
        {
            let mut last_started = self
                .last_started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(previous) = *last_started {
                if now.duration_since(previous) < self.min_interval {
                    self.opening.store(false, Ordering::SeqCst);
                    debug!(source = source, "ignored duplicate tray open request");
                    return;
                }
            }
            *last_started = Some(now);
        }

        let url = self.url.clone();
        let opening = self.opening.clone();
        thread::spawn(move || {
            let result = open_control_panel_url(&url);
            opening.store(false, Ordering::SeqCst);
            if let Err(error) = result {
                warn!(source = source, error = %error, "failed to open control panel from tray");
            }
        });
    }
}

fn open_control_panel_url(url: &str) -> Result<()> {
    let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
    let target: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let result = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    };

    if result as isize <= 32 {
        anyhow::bail!("failed to open control panel URL: {url}");
    }

    Ok(())
}

pub(super) fn browser_open_address(listen: &str) -> String {
    if let Some((host, port)) = listen.rsplit_once(':') {
        let browser_host = match host.trim_matches(['[', ']']) {
            "0.0.0.0" | "::" | "::0" => "127.0.0.1",
            other => other,
        };
        format!("{browser_host}:{port}")
    } else {
        listen.to_string()
    }
}
