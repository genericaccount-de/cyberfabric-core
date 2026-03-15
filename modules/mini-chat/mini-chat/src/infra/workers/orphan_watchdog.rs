//! Orphan watchdog — detects and finalizes turns abandoned by crashed pods.
//!
//! Requires leader election: exactly one active watchdog instance per environment.
//!
//! **P1 stub**: runs the periodic loop, logs each tick, but performs no actual
//! scan or finalization. Real logic will be added when domain services and
//! repository access are wired in.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::OrphanWatchdogConfig;
use crate::infra::leader::{LeaderElector, work_fn};

/// Run the orphan watchdog under leader election.
///
/// Returns when `cancel` fires (module shutdown) or on unrecoverable error.
pub async fn run(
    elector: Arc<dyn LeaderElector>,
    config: OrphanWatchdogConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    if !config.enabled {
        info!("orphan_watchdog: disabled, skipping");
        return Ok(());
    }

    info!(
        scan_interval_secs = config.scan_interval_secs,
        timeout_secs = config.timeout_secs,
        "orphan_watchdog: starting",
    );

    let interval = Duration::from_secs(config.scan_interval_secs);

    elector
        .run_role(
            "orphan-watchdog",
            cancel,
            work_fn(move |cancel| {
                let interval = interval;
                async move {
                    let mut ticker = tokio::time::interval(interval);
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                    loop {
                        tokio::select! {
                            _ = ticker.tick() => {
                                info!("orphan_watchdog: tick (stub -- no scan yet)");
                            }
                            () = cancel.cancelled() => {
                                info!("orphan_watchdog: shutting down");
                                return Ok(());
                            }
                        }
                    }
                }
            }),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_returns_immediately() {
        let elector = crate::infra::leader::noop();
        let cancel = CancellationToken::new();
        let config = OrphanWatchdogConfig {
            enabled: false,
            ..Default::default()
        };
        let result = run(elector, config, cancel).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn shutdown_on_cancel() {
        let elector = crate::infra::leader::noop();
        let cancel = CancellationToken::new();
        let config = OrphanWatchdogConfig::default();

        let c = cancel.clone();
        let handle = tokio::spawn(async move { run(elector, config, c).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(matches!(result, Ok(Ok(Ok(())))));
    }
}
