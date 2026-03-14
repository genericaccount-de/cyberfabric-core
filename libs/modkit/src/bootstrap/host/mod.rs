//! Host/in-process bootstrap module
//!
//! This module provides logging initialization, signal handling,
//! and path utilities for host processes.
//!
//! Configuration types are now in the top-level `config` module.

pub mod logging;
pub mod metrics_provider;
pub mod panic;
pub mod paths;
pub mod signals;

pub use logging::*;
pub use metrics_provider::*;
pub use panic::*;
pub use paths::{HomeDirError, expand_tilde, normalize_path};
pub use signals::*;

#[cfg(feature = "profiling")]
pub mod profiling;
