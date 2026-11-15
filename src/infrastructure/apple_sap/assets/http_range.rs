//! Random-access reads over HTTP byte ranges.
//!
//! Ported from ipatool `internal/sap/assets/http_range.go`.
//!
//! The restore image is tens of gigabytes, so it is never downloaded: every
//! consumer (ZIP central directory, AEA decryption, APFS, dyld) reads it
//! lazily through the synchronous [`ReadAt`] trait. HTTP is performed by
//! `reqwest` (async-only) on a private current-thread Tokio runtime owned by
//! [`BlockingHttp`]. Each blocking call drives that runtime on a short-lived
//! scoped thread, so it is safe to call from any thread, including a Tokio
//! worker (where it blocks that worker; prefer `spawn_blocking` there).

use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use reqwest::StatusCode;
use reqwest::header::{CONTENT_RANGE, RANGE, USER_AGENT};
use tokio::runtime::{Builder, Runtime};

/// Number of attempts made to complete one HTTP range read.
const REMOTE_READ_ATTEMPTS: usize = 3;
/// User agent required by Apple's restore-image CDN.
const RESTORE_IMAGE_USER_AGENT: &str = "Mozilla/5.0";
/// Reads up to this size, when sequential, earn read-ahead.
const REMOTE_SMALL_READ_SIZE: usize = 32 << 10;
/// Size of one read-ahead transfer and the cache bound.
const REMOTE_READ_AHEAD_SIZE: usize = 256 << 10;
/// The probe range requests exactly one byte; reading one more detects overflow.
const PROBE_READ_LIMIT: usize = 2;

/// Errors produced by blocking HTTP range access.
#[derive(Debug, thiserror::Error)]
pub enum HttpRangeError {
    /// The private Tokio runtime could not be created.
    #[error("create HTTP runtime: {0}")]
    Runtime(#[source] io::Error),
    /// The private runtime has already been shut down.
    #[error("HTTP runtime is no longer available")]
    RuntimeUnavailable,
    /// The thread driving the HTTP runtime panicked.
    #[error("HTTP worker thread panicked")]
    WorkerPanicked,
    /// The HTTP client could not be built.
    #[error("create HTTP client: {0}")]
    Client(#[source] reqwest::Error),
    /// The request failed at the transport level.
    #[error("HTTP request to {url}: {source}")]
    Request {
        /// Requested URL.
        url: String,
        /// Transport error.
        #[source]
        source: reqwest::Error,
    },
    /// The server answered with an unexpected status.
    #[error("{context}: server returned {status}")]
    Status {
        /// What was being requested.
        context: &'static str,
        /// The HTTP status received.
        status: StatusCode,
    },
    /// The `Content-Range` header is missing or malformed.
    #[error("invalid Content-Range {0:?}")]
    InvalidContentRange(String),
    /// The probe returned a range other than `0-0`.
    #[error("open remote image: server returned unexpected byte range {start}-{end}")]
    UnexpectedProbeRange {
        /// First byte returned.
        start: u64,
        /// Last byte returned.
        end: u64,
    },
    /// The probe body did not contain exactly one byte.
    #[error("remote image probe has an invalid length")]
    InvalidProbeLength,
    /// The server returned a different range than requested.
    #[error("read remote image range: server returned bytes {actual}, expected {expected}")]
    RangeMismatch {
        /// Range received, formatted as `start-end/size`.
        actual: String,
        /// Range requested, formatted as `start-end/size`.
        expected: String,
    },
    /// A range could not be completed after all retries.
    #[error("read remote image at offset {offset}: {reason}")]
    Incomplete {
        /// Absolute offset of the first missing byte.
        offset: u64,
        /// Last failure observed.
        reason: String,
    },
    /// A bounded response exceeded its size limit.
    #[error("{context}: response is larger than {limit} bytes")]
    TooLarge {
        /// What was being downloaded.
        context: &'static str,
        /// Maximum accepted size.
        limit: usize,
    },
}

/// Synchronous positional reads, the Rust counterpart of Go's `io.ReaderAt`.
///
/// `read_at` returns fewer bytes than requested only when the read reaches
/// [`ReadAt::size`]; reading at or beyond the end returns `Ok(0)`.
pub trait ReadAt: Send + Sync {
    /// Reads up to `buf.len()` bytes starting at `offset`.
    ///
    /// # Errors
    /// Returns an I/O error when the underlying source fails.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;

    /// Total number of readable bytes.
    fn size(&self) -> u64;

    /// Fills `buf` completely from `offset`.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::UnexpectedEof`] when the source ends early.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let count = self.read_at(buf, offset)?;
        if count == buf.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "short read at offset {offset}: {count} of {} bytes",
                    buf.len()
                ),
            ))
        }
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Arc<T> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        (**self).read_at(buf, offset)
    }

    fn size(&self) -> u64 {
        (**self).size()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        (**self).read_at(buf, offset)
    }

    fn size(&self) -> u64 {
        (**self).size()
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let Ok(start) = usize::try_from(offset) else {
            return Ok(0);
        };
        let available = self.get(start..).unwrap_or_default();
        let count = buf.len().min(available.len());
        buf[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }

    fn size(&self) -> u64 {
        self.len() as u64
    }
}

/// A bounded window of another [`ReadAt`], like Go's `io.SectionReader`.
#[derive(Debug, Clone)]
pub struct SectionReader<R> {
    inner: R,
    offset: u64,
    size: u64,
}

impl<R: ReadAt> SectionReader<R> {
    /// Exposes `size` bytes of `inner` starting at `offset` as offset zero.
    pub fn new(inner: R, offset: u64, size: u64) -> Self {
        Self {
            inner,
            offset,
            size,
        }
    }

    /// Absolute offset of this section inside the wrapped reader.
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

impl<R: ReadAt> ReadAt for SectionReader<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let remaining = self.size.saturating_sub(offset);
        let wanted = clamp_len(buf.len(), remaining);
        if wanted == 0 {
            return Ok(0);
        }
        let absolute = self.offset.checked_add(offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "section offset overflow")
        })?;
        self.inner.read_at(&mut buf[..wanted], absolute)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// Length of a read of `requested` bytes when only `remaining` bytes remain.
pub(crate) fn clamp_len(requested: usize, remaining: u64) -> usize {
    usize::try_from(remaining).map_or(requested, |remaining| requested.min(remaining))
}

/// A blocking facade over an async `reqwest` client and a private runtime.
#[derive(Debug)]
pub struct BlockingHttp {
    runtime: Option<Runtime>,
    client: reqwest::Client,
}

impl BlockingHttp {
    /// Creates the client and its private current-thread runtime.
    ///
    /// # Errors
    /// Returns an error when the runtime or the client cannot be created.
    pub fn new() -> Result<Self, HttpRangeError> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(HttpRangeError::Runtime)?;
        let client = reqwest::Client::builder()
            .build()
            .map_err(HttpRangeError::Client)?;
        Ok(Self {
            runtime: Some(runtime),
            client,
        })
    }

    /// Downloads `url` with a `200 OK` status, refusing bodies over `limit`.
    ///
    /// # Errors
    /// Fails on transport errors, non-200 statuses and oversized bodies.
    pub fn get_limited(
        &self,
        url: &str,
        limit: usize,
        context: &'static str,
    ) -> Result<Vec<u8>, HttpRangeError> {
        self.block_on(async {
            let mut response = self.send(self.client.get(url), url).await?;
            if response.status() != StatusCode::OK {
                return Err(HttpRangeError::Status {
                    context,
                    status: response.status(),
                });
            }
            let body = read_body_limited(&mut response, url, limit.saturating_add(1)).await?;
            if body.len() > limit {
                return Err(HttpRangeError::TooLarge { context, limit });
            }
            Ok(body)
        })?
    }

    fn block_on<F>(&self, future: F) -> Result<F::Output, HttpRangeError>
    where
        F: Future + Send,
        F::Output: Send,
    {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(HttpRangeError::RuntimeUnavailable)?;
        std::thread::scope(|scope| scope.spawn(|| runtime.block_on(future)).join())
            .map_err(|_| HttpRangeError::WorkerPanicked)
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        url: &str,
    ) -> Result<reqwest::Response, HttpRangeError> {
        request
            .send()
            .await
            .map_err(|source| HttpRangeError::Request {
                url: url.to_owned(),
                source,
            })
    }

    async fn send_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
    ) -> Result<reqwest::Response, HttpRangeError> {
        let request = self
            .client
            .get(url)
            .header(USER_AGENT, RESTORE_IMAGE_USER_AGENT)
            .header(RANGE, format!("bytes={start}-{end}"));
        self.send(request, url).await
    }
}

impl Drop for BlockingHttp {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

async fn read_body_limited(
    response: &mut reqwest::Response,
    url: &str,
    limit: usize,
) -> Result<Vec<u8>, HttpRangeError> {
    let mut body = Vec::new();
    while body.len() < limit {
        let chunk = response
            .chunk()
            .await
            .map_err(|source| HttpRangeError::Request {
                url: url.to_owned(),
                source,
            })?;
        let Some(chunk) = chunk else { break };
        let take = chunk.len().min(limit - body.len());
        body.extend_from_slice(&chunk[..take]);
    }
    Ok(body)
}

/// A parsed `Content-Range: bytes start-end/size` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    /// First byte in the response.
    pub start: u64,
    /// Last byte in the response, inclusive.
    pub end: u64,
    /// Complete size of the resource.
    pub size: u64,
}

impl ContentRange {
    /// Parses a complete `Content-Range` value with a known total size.
    ///
    /// # Errors
    /// Rejects unknown totals, empty resources, other units and invalid bounds.
    pub fn parse(value: &str) -> Result<Self, HttpRangeError> {
        let invalid = || HttpRangeError::InvalidContentRange(value.to_owned());
        let (unit_and_range, total) = value.split_once('/').ok_or_else(invalid)?;
        let size: u64 = total.parse().map_err(|_| invalid())?;
        let range = unit_and_range.strip_prefix("bytes ").ok_or_else(invalid)?;
        let (start, end) = range.split_once('-').ok_or_else(invalid)?;
        let start: u64 = start.parse().map_err(|_| invalid())?;
        let end: u64 = end.parse().map_err(|_| invalid())?;
        if size == 0 || end < start || end >= size {
            return Err(invalid());
        }
        Ok(Self { start, end, size })
    }

    fn from_response(response: &reqwest::Response) -> Result<Self, HttpRangeError> {
        let value = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        Self::parse(value)
    }
}

impl std::fmt::Display for ContentRange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}-{}/{}", self.start, self.end, self.size)
    }
}

#[derive(Debug, Default)]
struct ReadCache {
    data: Vec<u8>,
    offset: u64,
    previous: bool,
    last_end: u64,
}

impl ReadCache {
    fn lookup(&self, offset: u64, wanted: usize) -> Option<&[u8]> {
        let start = usize::try_from(offset.checked_sub(self.offset)?).ok()?;
        self.data.get(start..start.checked_add(wanted)?)
    }
}

/// A remote file read lazily through HTTP `Range` requests.
///
/// Sparse reads are fetched exactly; a sequential stream of small reads
/// (at most 32 KiB each) earns 256 KiB read-ahead. Interrupted bodies are
/// resumed up to three times.
#[derive(Debug)]
pub struct RemoteFile {
    http: Arc<BlockingHttp>,
    url: String,
    size: u64,
    cache: Mutex<ReadCache>,
}

impl RemoteFile {
    /// Probes `url` with `bytes=0-0` and learns its size.
    ///
    /// # Errors
    /// Fails when the server lacks byte-range support or answers inconsistently.
    pub fn open(http: Arc<BlockingHttp>, url: &str) -> Result<Self, HttpRangeError> {
        let size = http.block_on(probe_size(&http, url))??;
        Ok(Self {
            http,
            url: url.to_owned(),
            size,
            cache: Mutex::new(ReadCache::default()),
        })
    }

    /// The URL being read.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Shared HTTP client used by this reader.
    pub fn http(&self) -> &Arc<BlockingHttp> {
        &self.http
    }

    fn lock_cache(&self) -> MutexGuard<'_, ReadCache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Serves the read from cache, or reports whether it earns read-ahead.
    fn try_cached(&self, data: &mut [u8], offset: u64) -> Result<(), bool> {
        let mut cache = self.lock_cache();
        let end = offset + data.len() as u64;
        if let Some(cached) = cache.lookup(offset, data.len()) {
            data.copy_from_slice(cached);
            cache.previous = true;
            cache.last_end = end;
            return Ok(());
        }
        let ahead =
            cache.previous && offset == cache.last_end && data.len() <= REMOTE_SMALL_READ_SIZE;
        cache.previous = true;
        cache.last_end = end;
        Err(ahead)
    }

    fn fetch(&self, data: &mut [u8], offset: u64, ahead: bool) -> Result<(), HttpRangeError> {
        let wanted = data.len();
        let fetch_size = if ahead {
            clamp_len(REMOTE_READ_AHEAD_SIZE, self.size - offset).max(wanted)
        } else {
            wanted
        };
        let mut buffer = vec![0; fetch_size];
        self.http
            .block_on(read_range(&self.http, self, &mut buffer, offset))??;
        data.copy_from_slice(&buffer[..wanted]);
        if fetch_size <= REMOTE_READ_AHEAD_SIZE {
            let mut cache = self.lock_cache();
            cache.offset = offset;
            cache.data = buffer;
        }
        Ok(())
    }
}

impl ReadAt for RemoteFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() || offset >= self.size {
            return Ok(0);
        }
        let wanted = clamp_len(buf.len(), self.size - offset);
        let data = &mut buf[..wanted];
        if let Err(ahead) = self.try_cached(data, offset) {
            self.fetch(data, offset, ahead).map_err(io::Error::other)?;
        }
        Ok(wanted)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

async fn probe_size(http: &BlockingHttp, url: &str) -> Result<u64, HttpRangeError> {
    let mut response = http.send_range(url, 0, 0).await?;
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(HttpRangeError::Status {
            context: "open remote image without byte-range support",
            status: response.status(),
        });
    }
    let range = ContentRange::from_response(&response)?;
    if range.start != 0 || range.end != 0 {
        return Err(HttpRangeError::UnexpectedProbeRange {
            start: range.start,
            end: range.end,
        });
    }
    let probe = read_body_limited(&mut response, url, PROBE_READ_LIMIT).await?;
    if probe.len() != 1 {
        return Err(HttpRangeError::InvalidProbeLength);
    }
    Ok(range.size)
}

/// Reads one wire range, resuming interrupted bodies up to the retry limit.
async fn read_range(
    http: &BlockingHttp,
    file: &RemoteFile,
    data: &mut [u8],
    offset: u64,
) -> Result<(), HttpRangeError> {
    let mut total = 0;
    let mut last_error = String::from("unexpected EOF");
    for _ in 0..REMOTE_READ_ATTEMPTS {
        if total == data.len() {
            break;
        }
        match read_range_attempt(http, file, &mut data[total..], offset + total as u64).await {
            Ok((count, None)) => total += count,
            Ok((count, Some(reason))) => {
                total += count;
                last_error = reason;
            }
            Err(error @ (HttpRangeError::Status { .. } | HttpRangeError::RangeMismatch { .. })) => {
                return Err(error);
            }
            Err(error @ HttpRangeError::InvalidContentRange(_)) => return Err(error),
            Err(error) => last_error = error.to_string(),
        }
    }
    if total == data.len() {
        return Ok(());
    }
    Err(HttpRangeError::Incomplete {
        offset: offset + total as u64,
        reason: last_error,
    })
}

/// One request for `data`: returns bytes received and a retryable failure.
async fn read_range_attempt(
    http: &BlockingHttp,
    file: &RemoteFile,
    data: &mut [u8],
    start: u64,
) -> Result<(usize, Option<String>), HttpRangeError> {
    let end = start + data.len() as u64 - 1;
    let mut response = http.send_range(&file.url, start, end).await?;
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(HttpRangeError::Status {
            context: "read remote image range",
            status: response.status(),
        });
    }
    let actual = ContentRange::from_response(&response)?;
    let expected = ContentRange {
        start,
        end,
        size: file.size,
    };
    if actual != expected {
        return Err(HttpRangeError::RangeMismatch {
            actual: actual.to_string(),
            expected: expected.to_string(),
        });
    }
    Ok(fill_from_body(&mut response, data).await)
}

async fn fill_from_body(
    response: &mut reqwest::Response,
    data: &mut [u8],
) -> (usize, Option<String>) {
    let mut filled = 0;
    while filled < data.len() {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(data.len() - filled);
                data[filled..filled + take].copy_from_slice(&chunk[..take]);
                filled += take;
            }
            Ok(None) => return (filled, Some(String::from("unexpected EOF"))),
            Err(error) => return (filled, Some(error.to_string())),
        }
    }
    (filled, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    struct RangeServer {
        content: Vec<u8>,
        ranges: Arc<Mutex<Vec<String>>>,
    }

    impl Respond for RangeServer {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            if request
                .headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                != Some(RESTORE_IMAGE_USER_AGENT)
            {
                return ResponseTemplate::new(403);
            }
            let header = request
                .headers
                .get("range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            self.ranges.lock().unwrap().push(header.clone());
            let (start, end) = header
                .strip_prefix("bytes=")
                .and_then(|r| r.split_once('-'))
                .unwrap();
            let start: usize = start.parse().unwrap();
            let end: usize = end.parse::<usize>().unwrap().min(self.content.len() - 1);
            ResponseTemplate::new(206)
                .insert_header(
                    "content-range",
                    format!("bytes {start}-{end}/{}", self.content.len()),
                )
                .set_body_bytes(self.content[start..=end].to_vec())
        }
    }

    struct Fixture {
        _server: MockServer,
        url: String,
        content: Vec<u8>,
        ranges: Arc<Mutex<Vec<String>>>,
    }

    async fn serve(content: Vec<u8>) -> Fixture {
        let server = MockServer::start().await;
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let responder = RangeServer {
            content: content.clone(),
            ranges: ranges.clone(),
        };
        Mock::given(method("GET"))
            .respond_with(responder)
            .mount(&server)
            .await;
        Fixture {
            url: format!("{}/restore.ipsw", server.uri()),
            _server: server,
            content,
            ranges,
        }
    }

    fn pattern(size: usize) -> Vec<u8> {
        (0..size).map(|n| u8::try_from(n % 251).unwrap()).collect()
    }

    fn open(url: &str) -> RemoteFile {
        RemoteFile::open(Arc::new(BlockingHttp::new().unwrap()), url).unwrap()
    }

    #[test]
    fn parses_complete_content_ranges() {
        let single = ContentRange::parse("bytes 0-0/26637307067").unwrap();
        assert_eq!(
            (single.start, single.end, single.size),
            (0, 0, 26_637_307_067)
        );
        let middle = ContentRange::parse("bytes 100-199/1000").unwrap();
        assert_eq!((middle.start, middle.end, middle.size), (100, 199, 1000));
    }

    #[test]
    fn rejects_incomplete_content_ranges() {
        for value in [
            "bytes 0-0/*",
            "bytes 0-0",
            "bytes 0-0/0",
            "items 0-0/1",
            "bytes 0-1/1",
            "bytes 2-1/3",
        ] {
            assert!(ContentRange::parse(value).is_err(), "{value}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_calls_are_safe_inside_async_runtime() {
        let http = BlockingHttp::new().unwrap();
        let result = http.get_limited("http://127.0.0.1:1/", 1, "test");
        assert!(matches!(result, Err(HttpRangeError::Request { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reads_ranges_with_browser_user_agent() {
        let fixture = serve(b"restore image".to_vec()).await;
        tokio::task::spawn_blocking(move || {
            let remote = open(&fixture.url);
            assert_eq!(remote.size(), fixture.content.len() as u64);
            let mut data = vec![0; fixture.content.len() - 1];
            assert_eq!(remote.read_at(&mut data, 1).unwrap(), data.len());
            assert_eq!(data, fixture.content[1..]);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_sequential_stream_in_bounded_transfers() {
        let fixture = serve(pattern(1 << 20)).await;
        tokio::task::spawn_blocking(move || {
            let remote = open(&fixture.url);
            let mut output = vec![0; fixture.content.len()];
            for chunk in output.chunks_mut(4096).enumerate() {
                let (index, chunk) = chunk;
                assert_eq!(remote.read_at(chunk, (index * 4096) as u64).unwrap(), 4096);
            }
            assert_eq!(output, fixture.content);
            assert_eq!(fixture.ranges.lock().unwrap().len(), 1 + 5);
            assert!(remote.lock_cache().data.len() <= REMOTE_READ_AHEAD_SIZE);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keeps_sparse_requests_exact_and_reports_eof() {
        let fixture = serve(pattern(1 << 20)).await;
        tokio::task::spawn_blocking(move || {
            let remote = open(&fixture.url);
            for offset in [0_usize, 500_000, 900_000] {
                let mut output = [0; 8];
                remote.read_at(&mut output, offset as u64).unwrap();
                assert_eq!(output, fixture.content[offset..offset + 8]);
            }
            let ranges = fixture.ranges.lock().unwrap().clone();
            assert_eq!(
                ranges[1..],
                ["bytes=0-7", "bytes=500000-500007", "bytes=900000-900007"]
            );
            let mut tail = [0; 32];
            let len = fixture.content.len();
            assert_eq!(remote.read_at(&mut tail, (len - 16) as u64).unwrap(), 16);
            assert_eq!(tail[..16], fixture.content[len - 16..]);
            assert_eq!(remote.read_at(&mut tail, len as u64).unwrap(), 0);
        })
        .await
        .unwrap();
    }

    #[test]
    fn section_reader_bounds_reads() {
        let section = SectionReader::new(pattern(100), 10, 20);
        let mut data = [0; 32];
        assert_eq!(section.read_at(&mut data, 5).unwrap(), 15);
        assert_eq!(data[..15], pattern(100)[15..30]);
        assert_eq!(section.read_at(&mut data, 20).unwrap(), 0);
        assert!(section.read_exact_at(&mut data, 0).is_err());
    }
}
