use std::{
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};

use tokio::sync::{watch, Notify};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::{
        ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::{GetCurrentProcess, GetProcessTimes},
    },
};

/// Shared runtime state.
/// Current use:
/// - lets web and tray request shutdown
/// - exposes low-cost runtime status for the local dashboard
#[derive(Clone)]
pub struct AppRuntime {
    inner: Arc<RuntimeInner>,
}

#[derive(Clone, Debug)]
pub struct BackendSignal {
    pub version: u64,
    pub changed: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ProcessMetrics {
    pub pid: u32,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub sample_interval_secs: u64,
}

struct RuntimeInner {
    shutdown_notify: Notify,
    session_id: String,
    started_at: SystemTime,
    shutdown_requested: AtomicBool,
    process_metrics: Mutex<ProcessMetricsSampler>,
    backend_change_tx: watch::Sender<BackendSignal>,
}

struct ProcessMetricsSampler {
    cached: ProcessMetrics,
    last_sample_at: Option<Instant>,
    last_process_time_100ns: Option<u64>,
}

impl ProcessMetricsSampler {
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

    fn new() -> Self {
        Self {
            cached: ProcessMetrics {
                pid: process::id(),
                cpu_percent: None,
                memory_bytes: process_memory_bytes(),
                sample_interval_secs: Self::SAMPLE_INTERVAL.as_secs(),
            },
            last_sample_at: None,
            last_process_time_100ns: process_time_100ns(),
        }
    }

    fn sample(&mut self) -> ProcessMetrics {
        let now = Instant::now();
        if self
            .last_sample_at
            .is_some_and(|last| now.duration_since(last) < Self::SAMPLE_INTERVAL)
        {
            return self.cached.clone();
        }

        let memory_bytes = process_memory_bytes();
        let process_time = process_time_100ns();
        let cpu_percent = self
            .last_sample_at
            .zip(self.last_process_time_100ns)
            .zip(process_time)
            .and_then(
                |((last_sample_at, last_process_time), current_process_time)| {
                    let wall_100ns =
                        now.duration_since(last_sample_at).as_secs_f64() * 10_000_000.0;
                    if wall_100ns <= 0.0 || current_process_time < last_process_time {
                        return None;
                    }
                    let logical_cpus = std::thread::available_parallelism()
                        .map(|count| count.get())
                        .unwrap_or(1) as f64;
                    let process_delta = (current_process_time - last_process_time) as f64;
                    Some(((process_delta / wall_100ns) / logical_cpus * 100.0).clamp(0.0, 100.0))
                },
            );

        self.cached = ProcessMetrics {
            pid: process::id(),
            cpu_percent,
            memory_bytes,
            sample_interval_secs: Self::SAMPLE_INTERVAL.as_secs(),
        };
        self.last_sample_at = Some(now);
        self.last_process_time_100ns = process_time;
        self.cached.clone()
    }
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
                started_at: SystemTime::now(),
                shutdown_requested: AtomicBool::new(false),
                process_metrics: Mutex::new(ProcessMetricsSampler::new()),
                backend_change_tx,
            }),
        }
    }

    pub fn request_shutdown(&self) {
        self.inner.shutdown_requested.store(true, Ordering::SeqCst);
        self.inner.shutdown_notify.notify_waiters();
        self.notify_status_changed();
    }

    pub async fn wait_for_shutdown(&self) {
        self.inner.shutdown_notify.notified().await;
    }

    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.inner.started_at)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    pub fn shutdown_requested(&self) -> bool {
        self.inner.shutdown_requested.load(Ordering::SeqCst)
    }

    pub fn process_metrics(&self) -> ProcessMetrics {
        self.inner
            .process_metrics
            .lock()
            .map(|mut sampler| sampler.sample())
            .unwrap_or_else(|_| ProcessMetrics {
                pid: process::id(),
                cpu_percent: None,
                memory_bytes: process_memory_bytes(),
                sample_interval_secs: ProcessMetricsSampler::SAMPLE_INTERVAL.as_secs(),
            })
    }

    pub fn backend_signal(&self) -> BackendSignal {
        self.inner.backend_change_tx.borrow().clone()
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

    pub fn notify_resource_replace_changed(&self) {
        self.notify_backend_changed(&["resource_replace"]);
    }

    pub fn notify_user_script_changed(&self) {
        self.notify_backend_changed(&["user_script"]);
    }

    pub fn notify_i18n_changed(&self) {
        self.notify_backend_changed(&["i18n"]);
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

#[cfg(windows)]
fn process_memory_bytes() -> Option<u64> {
    unsafe {
        let mut counters = std::mem::zeroed::<PROCESS_MEMORY_COUNTERS>();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        );
        if ok == 0 {
            None
        } else {
            Some(counters.WorkingSetSize as u64)
        }
    }
}

#[cfg(not(windows))]
fn process_memory_bytes() -> Option<u64> {
    None
}

#[cfg(windows)]
fn process_time_100ns() -> Option<u64> {
    unsafe {
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let ok = GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        );
        if ok == 0 {
            None
        } else {
            Some(filetime_to_u64(kernel).saturating_add(filetime_to_u64(user)))
        }
    }
}

#[cfg(not(windows))]
fn process_time_100ns() -> Option<u64> {
    None
}

#[cfg(windows)]
fn filetime_to_u64(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}
