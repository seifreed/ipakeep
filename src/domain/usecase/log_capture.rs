//! Test helpers for asserting `tracing` output.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt::MakeWriter;

static LOG_CAPTURE_LOCK: Mutex<()> = Mutex::new(());

/// In-memory sink for test log assertions.
#[derive(Clone, Default)]
pub struct LogCapture {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    /// Install a debug-level subscriber writing into this capture.
    pub fn install(&self) -> LogCaptureGuard {
        let lock = match LOG_CAPTURE_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(self.clone())
            .finish();
        LogCaptureGuard {
            _subscriber: tracing::subscriber::set_default(subscriber),
            _lock: lock,
        }
    }

    /// Return captured logs as UTF-8 text.
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.lock()).into_owned()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        match self.inner.lock() {
            Ok(buffer) => buffer,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Keeps a test log subscriber installed while holding the global capture lock.
pub struct LogCaptureGuard {
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

/// Writer that appends formatter output to a shared buffer.
pub struct LogWriter {
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
