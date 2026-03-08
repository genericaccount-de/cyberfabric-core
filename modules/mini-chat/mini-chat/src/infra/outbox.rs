use async_trait::async_trait;
use mini_chat_sdk::UsageEvent;
use tracing::warn;

use crate::domain::error::DomainError;
use crate::domain::repos::OutboxEnqueuer;

const USAGE_QUEUE: &str = "mini-chat.usage_snapshot";
const NUM_PARTITIONS: u32 = 4;

/// Infrastructure implementation of [`OutboxEnqueuer`].
///
/// Serializes `UsageEvent` to JSON and inserts into the outbox table
/// within the caller's transaction via `modkit_db::outbox::Outbox::enqueue()`.
///
/// TODO: replace stub with real implementation once `modkit_db::outbox`
/// is merged from the `transactional-outbox` branch. The implementation should:
/// - Hold `Arc<modkit_db::outbox::Outbox>`
/// - Call `outbox.enqueue(runner, queue_name, partition, payload).await`
pub struct InfraOutboxEnqueuer;

impl InfraOutboxEnqueuer {
    pub(crate) fn new() -> Self {
        Self
    }

    fn partition_for(tenant_id: uuid::Uuid) -> u32 {
        let hash = tenant_id.as_u128();
        #[allow(clippy::cast_possible_truncation)]
        {
            (hash % u128::from(NUM_PARTITIONS)) as u32
        }
    }
}

#[async_trait]
impl OutboxEnqueuer for InfraOutboxEnqueuer {
    async fn enqueue_usage_event(
        &self,
        _runner: &(dyn modkit_db::secure::DBRunner + Sync),
        event: UsageEvent,
    ) -> Result<(), DomainError> {
        let partition = Self::partition_for(event.tenant_id);
        let payload = serde_json::to_vec(&event)
            .map_err(|e| DomainError::internal(format!("serialize UsageEvent: {e}")))?;
        let payload_json = String::from_utf8_lossy(&payload);

        warn!(
            queue = USAGE_QUEUE,
            partition = partition,
            payload = %payload_json,
            "outbox enqueue stub - event NOT persisted (modkit_db::outbox not yet wired)"
        );

        // TODO: replace with real outbox.enqueue(runner, queue_name, partition, payload)
        Ok(())
    }
}
