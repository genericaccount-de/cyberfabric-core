//! Telemetry utilities for OpenTelemetry integration and CPU profiling
//!
//! This module provides utilities for setting up and configuring
//! OpenTelemetry tracing layers for distributed tracing, and
//! on-demand CPU profiling via pprof-compatible endpoints.

pub mod config;
pub mod init;
pub mod throttled_log;

pub use config::{
    Exporter, HttpOpts, LogsCorrelation, ProfilingConfig, Propagation, Sampler, TracingConfig,
};

#[cfg(all(unix, feature = "profiling"))]
pub mod profiling;
pub use init::{init_tracing, shutdown_tracing};
pub use throttled_log::ThrottledLog;
