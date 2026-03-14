//! On-demand CPU and memory profiling endpoint (pprof-compatible).
//!
//! When enabled via [`ProfilingConfig`], a **separate** HTTP server is started
//! on a configurable address (default `127.0.0.1:6060`) exposing:
//!
//! - `GET /debug/pprof/profile` — CPU profile (pprof protobuf or flamegraph SVG)
//! - `GET /debug/pprof/heap`    — Heap / allocator statistics (JSON)
//! - `GET /debug/pprof/`        — Index page listing available profiles
//!
//! ## Platform support
//!
//! - **Linux / macOS**: CPU profiling via `pprof-rs` (signal-based sampling).
//! - **Windows**: CPU profiling via a custom sampler thread
//!   (`SuspendThread` / `GetThreadContext` / `ResumeThread`).

mod server;

#[cfg(unix)]
mod sampler_unix;

#[cfg(windows)]
mod sampler_win;

mod pprof_proto;

pub use server::start_profiling_server;
