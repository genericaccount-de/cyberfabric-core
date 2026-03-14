//! Profiling HTTP server: routes, auth middleware, and graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio_util::sync::CancellationToken;

use crate::bootstrap::config::ProfilingConfig;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Spawn the profiling HTTP server as a background tokio task.
///
/// The server binds to `config.bind_addr` and shuts down gracefully when
/// `cancel` is triggered.
pub fn start_profiling_server(config: ProfilingConfig, cancel: CancellationToken) {
    tokio::spawn(async move {
        if let Err(e) = run_server(config, cancel).await {
            tracing::error!(error = %e, "profiling server failed");
        }
    });
}

async fn run_server(config: ProfilingConfig, cancel: CancellationToken) -> anyhow::Result<()> {
    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid profiling bind_addr '{}': {e}", config.bind_addr))?;

    let state = Arc::new(ProfileState {
        config: config.clone(),
    });

    let mut app = Router::new()
        .route("/debug/pprof/", get(index_handler))
        .route("/debug/pprof/profile", get(cpu_profile_handler))
        .route("/debug/pprof/heap", get(heap_handler))
        .with_state(Arc::clone(&state));

    // Optional bearer-token auth middleware
    if config.auth_token.is_some() {
        app = app.layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth_middleware,
        ));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "profiling server started");

    let shutdown = {
        let cancel = cancel.clone();
        async move {
            cancel.cancelled().await;
            tracing::info!("profiling server shutting down");
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| anyhow::anyhow!(e))
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct ProfileState {
    config: ProfilingConfig,
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<Arc<ProfileState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if let Some(ref expected) = state.config.auth_token {
        let provided = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));

        match provided {
            Some(token) if token == expected.as_str() => {}
            _ => {
                return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token")
                    .into_response();
            }
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct CpuProfileParams {
    /// Duration in seconds (clamped to `cpu_sample_duration_secs`).
    #[serde(default = "default_seconds")]
    seconds: u64,
    /// Output format: `protobuf` (default) or `flamegraph`.
    #[serde(default)]
    format: OutputFormat,
}

fn default_seconds() -> u64 {
    30
}

#[derive(Default, serde::Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub(in crate::bootstrap::host::profiling) enum OutputFormat {
    #[default]
    Protobuf,
    Flamegraph,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn index_handler() -> impl IntoResponse {
    let platform = if cfg!(unix) {
        "unix (pprof-rs, signal-based)"
    } else if cfg!(windows) {
        "windows (SuspendThread sampler)"
    } else {
        "unsupported"
    };

    let body = format!(
        "pprof profiling endpoint\n\n\
         Platform: {platform}\n\n\
         Available profiles:\n\
         - /debug/pprof/profile?seconds=30&format=protobuf  CPU profile\n\
         - /debug/pprof/profile?seconds=10&format=flamegraph CPU flamegraph SVG\n\
         - /debug/pprof/heap                                 Heap / process memory stats\n"
    );

    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], body)
}

async fn cpu_profile_handler(
    State(state): State<Arc<ProfileState>>,
    Query(params): Query<CpuProfileParams>,
) -> Response {
    let seconds = params.seconds.min(state.config.cpu_sample_duration_secs);
    if seconds == 0 {
        return (StatusCode::BAD_REQUEST, "seconds must be > 0").into_response();
    }
    let frequency = state.config.cpu_sample_frequency_hz;

    #[cfg(unix)]
    {
        super::sampler_unix::capture(seconds, frequency, params.format).await
    }

    #[cfg(windows)]
    {
        super::sampler_win::capture(seconds, frequency, params.format).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (seconds, frequency);
        (
            StatusCode::NOT_IMPLEMENTED,
            "CPU profiling is not supported on this platform",
        )
            .into_response()
    }
}

async fn heap_handler() -> impl IntoResponse {
    let info = gather_memory_info();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string_pretty(&info).unwrap_or_else(|_| "{}".to_owned()),
    )
}

// ---------------------------------------------------------------------------
// Memory info (cross-platform)
// ---------------------------------------------------------------------------

fn gather_memory_info() -> serde_json::Value {
    // Use /proc/self/status on Linux, basic process info elsewhere.
    #[cfg(target_os = "linux")]
    {
        gather_linux_memory()
    }

    #[cfg(not(target_os = "linux"))]
    {
        serde_json::json!({
            "note": "detailed memory stats are only available on Linux; consider /proc/self/status",
            "platform": std::env::consts::OS,
        })
    }
}

#[cfg(target_os = "linux")]
fn gather_linux_memory() -> serde_json::Value {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(contents) => {
            let mut info = serde_json::Map::new();
            for line in contents.lines() {
                if let Some((key, val)) = line.split_once(':') {
                    let key = key.trim();
                    let val = val.trim();
                    if key.starts_with("Vm") || key.starts_with("Rss") || key == "Threads" {
                        info.insert(key.to_owned(), serde_json::Value::String(val.to_owned()));
                    }
                }
            }
            serde_json::Value::Object(info)
        }
        Err(e) => serde_json::json!({ "error": e.to_string() }),
    }
}

// Re-export OutputFormat so samplers can use it.
pub(super) use self::OutputFormat as ProfOutputFormat;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_config(auth_token: Option<&str>) -> ProfilingConfig {
        ProfilingConfig {
            enabled: true,
            bind_addr: "127.0.0.1:0".to_owned(),
            cpu_sample_duration_secs: 5,
            cpu_sample_frequency_hz: 100,
            auth_token: auth_token.map(ToOwned::to_owned),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn build_app(config: ProfilingConfig) -> Router {
        let state = Arc::new(ProfileState {
            config: config.clone(),
        });

        let mut app = Router::new()
            .route("/debug/pprof/", get(index_handler))
            .route("/debug/pprof/profile", get(cpu_profile_handler))
            .route("/debug/pprof/heap", get(heap_handler))
            .with_state(Arc::clone(&state));

        if config.auth_token.is_some() {
            app = app.layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                auth_middleware,
            ));
        }
        app
    }

    #[tokio::test]
    async fn index_returns_200_and_text() {
        let app = build_app(test_config(None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("pprof profiling endpoint"));
        assert!(text.contains("/debug/pprof/profile"));
        assert!(text.contains("/debug/pprof/heap"));
    }

    #[tokio::test]
    async fn heap_returns_200_json() {
        let app = build_app(test_config(None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/heap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("application/json"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // Must be valid JSON.
        let _: serde_json::Value = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn auth_rejects_missing_token() {
        let app = build_app(test_config(Some("secret")));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_rejects_wrong_token() {
        let app = build_app(test_config(Some("secret")));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/")
                    .header(header::AUTHORIZATION, "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_accepts_valid_token() {
        let app = build_app(test_config(Some("secret")));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn no_auth_config_passes_through() {
        let app = build_app(test_config(None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cpu_profile_rejects_zero_seconds() {
        let app = build_app(test_config(None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/profile?seconds=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let app = build_app(test_config(None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/debug/pprof/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
