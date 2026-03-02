use std::fmt;

use serde::{Deserialize, Serialize};

/// Configuration for the OAGW module.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OagwConfig {
    #[serde(default = "default_proxy_timeout_secs")]
    pub proxy_timeout_secs: u64,
    #[serde(default = "default_max_body_size_bytes")]
    pub max_body_size_bytes: usize,
    #[serde(default)]
    pub allow_http_upstream: bool,
}

impl Default for OagwConfig {
    fn default() -> Self {
        Self {
            proxy_timeout_secs: default_proxy_timeout_secs(),
            max_body_size_bytes: default_max_body_size_bytes(),
            allow_http_upstream: false,
        }
    }
}

fn default_proxy_timeout_secs() -> u64 {
    30
}

fn default_max_body_size_bytes() -> usize {
    10 * 1024 * 1024 // 10 MB
}

/// Read-only runtime configuration exposed to handlers via `AppState`.
///
/// Derived from [`OagwConfig`] at init time.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub max_body_size_bytes: usize,
}

impl From<&OagwConfig> for RuntimeConfig {
    fn from(cfg: &OagwConfig) -> Self {
        Self {
            max_body_size_bytes: cfg.max_body_size_bytes,
        }
    }
}

impl fmt::Debug for OagwConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OagwConfig")
            .field("proxy_timeout_secs", &self.proxy_timeout_secs)
            .field("max_body_size_bytes", &self.max_body_size_bytes)
            .field("allow_http_upstream", &self.allow_http_upstream)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_timeout_and_body_size() {
        let config = OagwConfig::default();
        let debug_output = format!("{config:?}");
        assert!(debug_output.contains("proxy_timeout_secs"));
        assert!(debug_output.contains("max_body_size_bytes"));
    }
}
