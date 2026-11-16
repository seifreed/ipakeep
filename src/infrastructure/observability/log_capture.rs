//! Test-only capture writer for `tracing` assertions.
//!
//! Each capture installs a thread-local default subscriber, so it only sees
//! events emitted on the installing thread, and the global lock serializes
//! captures. Captured lines carry no timestamps: their sub-second digits are
//! random text that once made "secret never logged" assertions flaky (a fake
//! DSID `1234` matched `…:37.123425Z`).

use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt::MakeWriter;

static LOG_CAPTURE_LOCK: Mutex<()> = Mutex::new(());

fn pin_global_max_level() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(io::sink)
                .finish(),
        );
    });
}

/// In-memory sink for test log assertions.
#[derive(Clone, Default)]
pub(crate) struct LogCapture {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    /// Install a debug-level subscriber writing into this capture.
    pub(crate) fn install(&self) -> LogCaptureGuard {
        Self::install_subscriber(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .without_time()
                .with_ansi(false)
                .with_writer(self.clone())
                .finish(),
        )
    }

    /// Install a JSON subscriber for structured event assertions.
    pub(crate) fn install_json(&self) -> LogCaptureGuard {
        Self::install_subscriber(
            tracing_subscriber::fmt()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .without_time()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(self.clone())
                .finish(),
        )
    }

    fn install_subscriber<S>(subscriber: S) -> LogCaptureGuard
    where
        S: tracing::Subscriber + Send + Sync + 'static,
    {
        pin_global_max_level();
        let lock = match LOG_CAPTURE_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
        LogCaptureGuard {
            _subscriber: tracing::subscriber::set_default(subscriber),
            _lock: lock,
        }
    }

    /// Return captured logs as UTF-8 text.
    pub(crate) fn contents(&self) -> String {
        String::from_utf8_lossy(&self.lock()).into_owned()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        match self.inner.lock() {
            Ok(buffer) => buffer,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Keeps a test subscriber installed while holding the global capture lock.
pub(crate) struct LogCaptureGuard {
    _subscriber: DefaultGuard,
    _lock: MutexGuard<'static, ()>,
}

impl<'a> MakeWriter<'a> for LogCapture {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter {
            inner: Arc::clone(&self.inner),
        }
    }
}

pub(crate) struct LogWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.lock() {
            Ok(mut inner) => inner.write(buf),
            Err(poisoned) => poisoned.into_inner().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LogCapture;

    #[test]
    fn captures_only_the_installing_thread_without_timestamps() {
        let capture = LogCapture::default();
        let guard = capture.install();
        tracing::info!(event_name = "test.capture.own_thread", "captured");
        std::thread::spawn(|| tracing::info!(event_name = "test.capture.other_thread", "ignored"))
            .join()
            .expect("logging thread");
        drop(guard);
        tracing::info!(event_name = "test.capture.after_guard", "ignored");

        let logs = capture.contents();
        assert!(logs.starts_with(" INFO "), "{logs}");
        assert_eq!(logs.lines().count(), 1, "{logs}");
        assert!(logs.contains("test.capture.own_thread"), "{logs}");
    }

    #[test]
    fn json_capture_has_no_timestamp_field() {
        let capture = LogCapture::default();
        let guard = capture.install_json();
        tracing::info!(event_name = "test.capture.json", "captured");
        drop(guard);

        let event: serde_json::Value =
            serde_json::from_str(capture.contents().trim()).expect("one JSON event");
        assert_eq!(event["event_name"], "test.capture.json");
        assert!(event.get("timestamp").is_none(), "{event}");
    }
}
