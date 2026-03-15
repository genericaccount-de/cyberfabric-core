//! Cleanup outbox handler — removes provider resources for soft-deleted chats.
//!
//! Runs as part of the outbox pipeline (decoupled strategy). All replicas
//! process events in parallel, partitioned by `tenant_id`. No leader election needed.
//!
//! **P1 stub**: logs each message but performs no actual provider cleanup.
//! Returns `Retry` so events accumulate safely in the outbox until the
//! handler is fully implemented.

use async_trait::async_trait;
use modkit_db::outbox::{HandlerResult, MessageHandler, OutboxMessage};
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Stub handler for attachment cleanup events.
///
/// Returns `Retry` for every message — events accumulate safely in the outbox
/// until the cleanup worker ships. This ensures the queue is registered and
/// partitioned from day one.
pub struct AttachmentCleanupHandler;

#[async_trait]
impl MessageHandler for AttachmentCleanupHandler {
    async fn handle(&self, msg: &OutboxMessage, _cancel: CancellationToken) -> HandlerResult {
        warn!(
            partition_id = msg.partition_id,
            seq = msg.seq,
            "attachment cleanup handler not yet implemented - retrying"
        );
        HandlerResult::Retry {
            reason: "cleanup handler not yet implemented".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg() -> OutboxMessage {
        OutboxMessage {
            partition_id: 1,
            seq: 1,
            payload: b"{}".to_vec(),
            payload_type: "application/json".to_owned(),
            created_at: chrono::Utc::now(),
            attempts: 0i16,
        }
    }

    #[tokio::test]
    async fn stub_returns_retry() {
        let handler = AttachmentCleanupHandler;
        let msg = make_msg();
        let result = handler.handle(&msg, CancellationToken::new()).await;
        assert!(matches!(result, HandlerResult::Retry { .. }));
    }
}
