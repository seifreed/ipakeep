//! Test-only capture writer for `tracing` assertions.

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
