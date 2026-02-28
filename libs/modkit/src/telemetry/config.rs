//! Telemetry configuration types
//!
//! These types define the configuration structure for OpenTelemetry distributed tracing
//! and CPU profiling.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tracing configuration for OpenTelemetry distributed tracing
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TracingConfig {
    pub enabled: bool,
    pub service_name: Option<String>,
    pub exporter: Option<Exporter>,
    pub sampler: Option<Sampler>,
    pub propagation: Option<Propagation>,
    pub resource: Option<HashMap<String, String>>,
    pub http: Option<HttpOpts>,
    pub logs_correlation: Option<LogsCorrelation>,
    /// CPU profiling configuration (separate HTTP server).
    #[serde(default)]
    pub profiling: ProfilingConfig,
}

/// CPU profiling configuration.
///
/// When enabled, a separate HTTP server is spawned exposing pprof-compatible
/// endpoints for on-demand CPU profiling. Requires the `profiling` Cargo feature.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfilingConfig {
    /// Enable the profiling HTTP server at runtime.
    #[serde(default)]
    pub enabled: bool,
    /// Bind address for the profiling server.
    #[serde(default = "default_profiling_address")]
    pub address: String,
    /// Bind port for the profiling server.
    #[serde(default = "default_profiling_port")]
    pub port: u16,
    /// Optional bearer token for endpoint authentication.
    /// Supports `${ENV_VAR}` expansion.
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: default_profiling_address(),
            port: default_profiling_port(),
            auth_token: None,
        }
    }
}

fn default_profiling_address() -> String {
    "127.0.0.1".to_owned()
}

const fn default_profiling_port() -> u16 {
    6060
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ExporterKind {
    #[default]
    OtlpGrpc,
    OtlpHttp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Exporter {
    pub kind: ExporterKind,
    pub endpoint: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Sampler {
    ParentBasedAlwaysOn {},
    ParentBasedRatio {
        #[serde(skip_serializing_if = "Option::is_none")]
        ratio: Option<f64>,
    },
    AlwaysOn {},
    AlwaysOff {},
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Propagation {
    pub w3c_trace_context: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpOpts {
    pub inject_request_id_header: Option<String>,
    pub record_headers: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogsCorrelation {
    pub inject_trace_ids_into_logs: Option<bool>,
}
