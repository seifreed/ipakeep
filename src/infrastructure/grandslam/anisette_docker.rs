//! Auto-managed anisette server via Docker (non-macOS platforms).
//!
//! `AOSKit` is only available on macOS, so Windows and Linux cannot generate
//! valid Anisette OTP tokens locally. Instead we run an anisette server in a
//! Docker container and fetch the tokens over HTTP. This module detects whether
//! the server is already running and, if not, launches the container.

use crate::domain::error::AppStoreError;
use std::time::Duration;
use tokio::process::Command;

/// Local endpoint the anisette container is published on.
const ANISETTE_URL: &str = "http://127.0.0.1:6969";
/// Name of the managed container.
const CONTAINER_NAME: &str = "ipakeep-anisette";
/// Default image (auto-built locally; overridable via `IPAKEEP_ANISETTE_IMAGE`).
const DEFAULT_IMAGE: &str = "ipakeep-anisette:bundled";
/// Upstream anisette server our default image is built on top of.
const BASE_IMAGE: &str = "dadoum/anisette-v3-server:latest";
/// Named volume that persists the server's device provisioning state.
const VOLUME: &str = "ipakeep-anisette-data";
/// In-container path holding the provisioning state.
const SERVER_LIB_PATH: &str = "/home/Alcoholic/.config/anisette-v3/lib/";
/// Seconds to wait for the server to finish provisioning and answer requests.
const READINESS_TIMEOUT_SECS: u64 = 120;
/// Per-probe HTTP timeout.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Apple Root CA bundled into the image so the server trusts `gsa.apple.com`
/// during provisioning (Debian's default store does not include it).
const APPLE_ROOT_CA: &[u8] = include_bytes!("../http/apple_root_ca.pem");

/// Dockerfile for the auto-built image: the upstream server plus the Apple Root
/// CA so its provisioning TLS to `gsa.apple.com` validates (the base Debian
/// image does not trust Apple's root). The server downloads its own Apple
/// provisioning library at runtime — that remains upstream's responsibility.
const BUNDLED_DOCKERFILE: &str = "FROM dadoum/anisette-v3-server:latest\n\
     USER root\n\
     COPY apple_root_ca.pem /usr/local/share/ca-certificates/apple-root-ca.crt\n\
     RUN update-ca-certificates\n\
     USER Alcoholic\n";

/// Ensure a local anisette server is reachable, launching the container if
/// necessary, and return its base URL.
///
/// # Errors
///
/// Returns an error if Docker is unavailable, the container fails to launch, or
/// the server does not become ready within the configured readiness timeout.
pub async fn ensure_local_server(client: &reqwest::Client) -> Result<String, AppStoreError> {
    if probe(client).await {
        return Ok(ANISETTE_URL.to_string());
    }

    ensure_docker_available().await?;
    start_container().await?;
    wait_until_ready(client).await?;

    Ok(ANISETTE_URL.to_string())
}

/// Return `true` if the anisette server answers a successful HTTP response.
async fn probe(client: &reqwest::Client) -> bool {
    matches!(
        client.get(ANISETTE_URL).timeout(PROBE_TIMEOUT).send().await,
        Ok(response) if response.status().is_success()
    )
}

/// Verify the Docker CLI is installed and the daemon is reachable.
async fn ensure_docker_available() -> Result<(), AppStoreError> {
    let available = Command::new("docker")
        .arg("version")
        .output()
        .await
        .is_ok_and(|output| output.status.success());

    if available {
        return Ok(());
    }

    Err(AppStoreError::NetworkError(
        "Docker is required to run the anisette server on this platform. Install and start \
         Docker, or set IPAKEEP_ANISETTE_URL to point at an existing anisette server."
            .into(),
    ))
}

/// Start the anisette container, reusing an existing one only when it was
/// created from the requested image.
async fn start_container() -> Result<(), AppStoreError> {
    let image =
        std::env::var("IPAKEEP_ANISETTE_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string());

    ensure_image(&image).await?;

    let reusable = existing_container_image().await.as_deref() == Some(image.as_str());
    if reusable && start_existing_container().await {
        return Ok(());
    }

    // A missing, stopped-but-unstartable, or stale-image container would
    // otherwise make `docker run --name` fail with "name already in use".
    // Removing first frees the name and the 6969 port; the named volume keeps
    // the device provisioning state, so recreation is cheap.
    remove_container().await;
    run_new_container(&image).await
}

/// Ensure the requested image is available.
///
/// The default `ipakeep-anisette` image is built locally from the upstream
/// server plus the Apple Root CA (the upstream image fails provisioning because
/// Debian does not trust Apple's root). Custom images named via
/// `IPAKEEP_ANISETTE_IMAGE` are the caller's responsibility and are left to
/// `docker run` to pull.
async fn ensure_image(image: &str) -> Result<(), AppStoreError> {
    if image != DEFAULT_IMAGE || image_exists(image).await {
        return Ok(());
    }
    build_bundled_image(image).await
}

/// Return `true` if a local image with this name/tag exists.
async fn image_exists(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

/// Build the bundled anisette image (upstream + Apple Root CA) from a temporary
/// build context derived from the cert embedded in this binary.
async fn build_bundled_image(image: &str) -> Result<(), AppStoreError> {
    let context = std::env::temp_dir().join("ipakeep-anisette-build");
    let io_err = |e: std::io::Error| {
        AppStoreError::NetworkError(format!("failed to prepare anisette build context: {e}"))
    };

    tokio::fs::create_dir_all(&context).await.map_err(io_err)?;
    tokio::fs::write(context.join("Dockerfile"), BUNDLED_DOCKERFILE)
        .await
        .map_err(io_err)?;
    tokio::fs::write(context.join("apple_root_ca.pem"), APPLE_ROOT_CA)
        .await
        .map_err(io_err)?;

    let context = context.to_string_lossy().to_string();
    let output = Command::new("docker")
        .args(["build", "--pull", "-t", image, &context])
        .output()
        .await
        .map_err(|e| {
            AppStoreError::NetworkError(format!("failed to build the anisette image: {e}"))
        })?;

    if output.status.success() {
        return Ok(());
    }

    Err(AppStoreError::NetworkError(format!(
        "failed to build the anisette image from {BASE_IMAGE}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Launch a fresh detached anisette container from `image`.
async fn run_new_container(image: &str) -> Result<(), AppStoreError> {
    let volume_mount = format!("{VOLUME}:{SERVER_LIB_PATH}");

    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            CONTAINER_NAME,
            "--restart",
            "unless-stopped",
            "-p",
            "6969:6969",
            "-v",
            &volume_mount,
            image,
        ])
        .output()
        .await
        .map_err(|e| {
            AppStoreError::NetworkError(format!("failed to launch the anisette container: {e}"))
        })?;

    if output.status.success() {
        return Ok(());
    }

    Err(AppStoreError::NetworkError(format!(
        "failed to launch the anisette container: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Image the managed container was created from, or `None` if it does not exist.
async fn existing_container_image() -> Option<String> {
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{.Config.Image}}", CONTAINER_NAME])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let image = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!image.is_empty()).then_some(image)
}

/// Force-remove the managed container, ignoring "no such container".
async fn remove_container() {
    let _ = Command::new("docker")
        .args(["rm", "-f", CONTAINER_NAME])
        .output()
        .await;
}

/// Try to start a previously-created container; returns `true` on success.
async fn start_existing_container() -> bool {
    Command::new("docker")
        .args(["start", CONTAINER_NAME])
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

/// Poll the server until it answers or the readiness timeout elapses.
///
/// Uses a wall-clock deadline rather than a fixed iteration count: each `probe`
/// can itself block for up to [`PROBE_TIMEOUT`], so a plain
/// `0..READINESS_TIMEOUT_SECS` loop would wait far longer than the advertised
/// budget when the server is unreachable.
async fn wait_until_ready(client: &reqwest::Client) -> Result<(), AppStoreError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(READINESS_TIMEOUT_SECS);

    while tokio::time::Instant::now() < deadline {
        if probe(client).await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Err(AppStoreError::NetworkError(format!(
        "anisette server did not become ready within {READINESS_TIMEOUT_SECS}s"
    )))
}
