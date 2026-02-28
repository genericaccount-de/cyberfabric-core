//! CPU profiling server with pprof-compatible endpoints.
//!
//! Spawns a separate HTTP server exposing:
//! - `GET /debug/pprof/profile` — CPU profile in pprof protobuf format
//! - `GET /debug/pprof/flamegraph` — CPU profile as flamegraph SVG
//!
//! Query parameters (both endpoints):
//! - `seconds` — profiling duration (default: 30, max: 300)
//! - `frequency` — sampling frequency in Hz (default: 99, max: 999)
//!
//! The server binds to a configurable address/port (default `127.0.0.1:6060`)
//! and optionally requires a bearer token for authentication.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Router, middleware, routing::get};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use super::config::ProfilingConfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_SECONDS: u64 = 30;
const MAX_SECONDS: u64 = 300;
const DEFAULT_FREQUENCY: i32 = 99;
const MAX_FREQUENCY: i32 = 999;

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ProfileParams {
    seconds: Option<u64>,
    frequency: Option<i32>,
}

impl ProfileParams {
    fn seconds(&self) -> u64 {
        self.seconds
            .unwrap_or(DEFAULT_SECONDS)
            .clamp(1, MAX_SECONDS)
    }

    fn frequency(&self) -> i32 {
        self.frequency
            .unwrap_or(DEFAULT_FREQUENCY)
            .clamp(1, MAX_FREQUENCY)
    }
}

// ---------------------------------------------------------------------------
// ${ENV_VAR} expansion for auth_token
// ---------------------------------------------------------------------------

fn expand_env_vars(input: &str) -> Result<String> {
    let mut result = input.to_owned();
    // Match ${VAR_NAME} patterns
    while let Some(start) = result.find("${") {
        let Some(end) = result[start..].find('}') else {
            break;
        };
        let var_name = &result[start + 2..start + end];
        let value = std::env::var(var_name)
            .with_context(|| format!("Environment variable '{var_name}' not found"))?;
        result.replace_range(start..=start + end, &value);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    axum::extract::State(expected_token): axum::extract::State<String>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let authorized = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| token == expected_token);

    if authorized {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_profile(Query(params): Query<ProfileParams>) -> Response {
    let seconds = params.seconds();
    let frequency = params.frequency();

    tracing::info!(seconds, frequency, "Starting CPU profile collection");

    match collect_profile(seconds, frequency).await {
        Ok(data) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            data,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to collect CPU profile");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to collect profile: {e}"),
            )
                .into_response()
        }
    }
}

async fn handle_flamegraph(Query(params): Query<ProfileParams>) -> Response {
    let seconds = params.seconds();
    let frequency = params.frequency();

    tracing::info!(seconds, frequency, "Starting flamegraph collection");

    match collect_flamegraph(seconds, frequency).await {
        Ok(svg) => (StatusCode::OK, [("content-type", "image/svg+xml")], svg).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate flamegraph");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate flamegraph: {e}"),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Profile collection
// ---------------------------------------------------------------------------

async fn collect_profile(seconds: u64, frequency: i32) -> Result<Vec<u8>> {
    emit_platform_warning();

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(frequency)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .context("Failed to build profiler guard")?;

    tokio::time::sleep(Duration::from_secs(seconds)).await;

    let report = guard.report().build().context("Failed to build report")?;
    let profile = report.pprof().context("Failed to generate pprof profile")?;

    let mut buf = Vec::new();
    pprof::protos::Message::encode(&profile, &mut buf)
        .context("Failed to encode pprof protobuf")?;

    tracing::info!(
        bytes = buf.len(),
        seconds,
        frequency,
        "CPU profile collected"
    );
    Ok(buf)
}

async fn collect_flamegraph(seconds: u64, frequency: i32) -> Result<Vec<u8>> {
    emit_platform_warning();

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(frequency)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .context("Failed to build profiler guard")?;

    tokio::time::sleep(Duration::from_secs(seconds)).await;

    let report = guard.report().build().context("Failed to build report")?;

    let mut svg = Vec::new();
    report
        .flamegraph(&mut svg)
        .context("Failed to generate flamegraph SVG")?;

    tracing::info!(
        bytes = svg.len(),
        seconds,
        frequency,
        "Flamegraph SVG generated"
    );
    Ok(svg)
}

fn emit_platform_warning() {
    #[cfg(not(target_os = "linux"))]
    tracing::warn!(
        "CPU profiling has limited fidelity on non-Linux platforms. \
         Signal-based sampling works best on Linux."
    );
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the profiling HTTP server in a background task.
///
/// The server binds to `{config.address}:{config.port}` **before returning**,
/// so any bind failure (port in use, permission denied, etc.) is propagated
/// to the caller. The actual serve loop runs in a spawned background task
/// that shuts down gracefully when the provided `CancellationToken` is
/// cancelled.
///
/// # Errors
///
/// Returns an error if address parsing fails, `auth_token` environment
/// variable expansion fails, or the TCP listener cannot bind.
pub async fn start_profiling_server(
    config: &ProfilingConfig,
    cancel: CancellationToken,
) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.address, config.port)
        .parse()
        .with_context(|| {
            format!(
                "Invalid profiling bind address: {}:{}",
                config.address, config.port
            )
        })?;

    let resolved_token = config
        .auth_token
        .as_deref()
        .map(expand_env_vars)
        .transpose()
        .context("Failed to expand profiling auth_token")?;

    let router = build_router(resolved_token);

    tracing::info!(
        %addr,
        auth = config.auth_token.is_some(),
        "Starting profiling server"
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind profiling server on {addr}"))?;

    tracing::info!(%addr, "Profiling server listening");

    tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async move {
            cancel.cancelled().await;
            tracing::info!("Profiling server shutting down");
        });

        if let Err(e) = server.await {
            tracing::error!(error = %e, "Profiling server error");
        }
    });

    Ok(())
}

fn build_router(auth_token: Option<String>) -> Router {
    let routes = Router::new()
        .route("/debug/pprof/profile", get(handle_profile))
        .route("/debug/pprof/flamegraph", get(handle_flamegraph));

    if let Some(token) = auth_token {
        routes.layer(middleware::from_fn_with_state(token, auth_middleware))
    } else {
        routes
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_profile_params_defaults() {
        let params = ProfileParams {
            seconds: None,
            frequency: None,
        };
        assert_eq!(params.seconds(), DEFAULT_SECONDS);
        assert_eq!(params.frequency(), DEFAULT_FREQUENCY);
    }

    #[test]
    fn test_profile_params_clamping() {
        let params = ProfileParams {
            seconds: Some(999),
            frequency: Some(9999),
        };
        assert_eq!(params.seconds(), MAX_SECONDS);
        assert_eq!(params.frequency(), MAX_FREQUENCY);
    }

    #[test]
    fn test_profile_params_min_clamping() {
        let params = ProfileParams {
            seconds: Some(0),
            frequency: Some(0),
        };
        assert_eq!(params.seconds(), 1);
        assert_eq!(params.frequency(), 1);
    }

    #[test]
    fn test_expand_env_vars_no_vars() {
        let result = expand_env_vars("plain-token").expect("should succeed");
        assert_eq!(result, "plain-token");
    }

    #[test]
    fn test_expand_env_vars_with_env() {
        let var_name = "TEST_PROFILING_TOKEN_EXPAND_8273";
        temp_env::with_var(var_name, Some("secret123"), || {
            let input = format!("${{{var_name}}}");
            let result = expand_env_vars(&input).expect("should expand");
            assert_eq!(result, "secret123");
        });
    }

    #[test]
    fn test_expand_env_vars_missing() {
        let result = expand_env_vars("${NONEXISTENT_PROFILING_VAR_12345}");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_profiling_config() {
        let config = ProfilingConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.port, 6060);
        assert!(config.auth_token.is_none());
    }

    #[test]
    fn test_build_router_no_auth() {
        let router = build_router(None);
        // Smoke test: router should build without panicking
        drop(router);
    }

    #[test]
    fn test_build_router_with_auth() {
        let router = build_router(Some("test-token".to_owned()));
        drop(router);
    }
}
