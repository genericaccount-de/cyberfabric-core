use std::sync::Arc;

use mini_chat_sdk::{MiniChatAuditPluginClientV1, MiniChatAuditPluginSpecV1};
use modkit::client_hub::{ClientHub, ClientScope};
use modkit::plugins::{ChoosePluginError, GtsPluginSelector, choose_plugin_instance};
use tracing::warn;
use types_registry_sdk::{ListQuery, TypesRegistryClient};

/// Resolves and dispatches to the registered audit plugin instance.
///
/// Follows the same lazy-resolution pattern as `ModelPolicyGateway`:
/// the plugin instance is discovered via GTS types-registry on first use.
/// Used exclusively by `AuditEventHandler` in the outbox layer.
pub struct AuditGateway {
    hub: Arc<ClientHub>,
    vendor: String,
    selector: GtsPluginSelector,
}

impl AuditGateway {
    pub(crate) fn new(hub: Arc<ClientHub>, vendor: String) -> Self {
        Self {
            hub,
            vendor,
            selector: GtsPluginSelector::new(),
        }
    }

    /// Create a no-op gateway for tests.
    ///
    /// The selector is pre-warmed with the empty-string sentinel so
    /// `get_plugin()` immediately returns `Ok(None)` and audit events
    /// are silently dropped without hitting the types-registry.
    #[cfg(test)]
    pub(crate) fn noop() -> Arc<Self> {
        Self::new_preconfigured(
            Arc::new(ClientHub::new()),
            String::new(),
            GtsPluginSelector::pre_cached(String::new()),
        )
    }

    /// Create a gateway pre-loaded with a concrete plugin instance — for unit tests.
    ///
    /// The supplied plugin is registered in a fresh `ClientHub` under a
    /// fixed synthetic instance ID.  The selector is pre-cached so
    /// `get_plugin()` returns the plugin immediately without any
    /// types-registry round-trip.
    #[cfg(test)]
    pub(crate) fn from_plugin(plugin: Arc<dyn MiniChatAuditPluginClientV1>) -> Arc<Self> {
        const MOCK_INSTANCE_ID: &str = "test.audit.plugin.v1~test._.mock.v1";
        let hub = Arc::new(ClientHub::new());
        hub.register_scoped::<dyn MiniChatAuditPluginClientV1>(
            ClientScope::gts_id(MOCK_INSTANCE_ID),
            plugin,
        );
        Self::new_preconfigured(
            hub,
            String::new(),
            GtsPluginSelector::pre_cached(MOCK_INSTANCE_ID.to_owned()),
        )
    }

    /// Create a gateway with explicit fields — for tests that pre-warm the
    /// selector and register the plugin directly in the hub.
    #[cfg(test)]
    pub(crate) fn new_preconfigured(
        hub: Arc<ClientHub>,
        vendor: String,
        selector: GtsPluginSelector,
    ) -> Arc<Self> {
        Arc::new(Self {
            hub,
            vendor,
            selector,
        })
    }

    /// Lazily resolve the audit plugin from `ClientHub`.
    ///
    /// - `Ok(Some(plugin))` — plugin resolved and ready.
    /// - `Ok(None)` — no audit plugin is registered; audit is optional, caller should skip.
    /// - `Err(e)` — transient resolution failure; caller should retry.
    pub(crate) async fn get_plugin(
        &self,
    ) -> Result<Option<Arc<dyn MiniChatAuditPluginClientV1>>, anyhow::Error> {
        let instance_id = self
            .selector
            .get_or_init(|| self.resolve_audit_plugin())
            .await?;

        // Empty string is the sentinel written by `resolve_audit_plugin` when no
        // plugin instance is registered.  The selector caches it so we don't
        // hammer the types-registry on every delivery attempt.
        if instance_id.is_empty() {
            return Ok(None);
        }

        let scope = ClientScope::gts_id(instance_id.as_ref());
        let client = self
            .hub
            .try_get_scoped::<dyn MiniChatAuditPluginClientV1>(&scope);

        if client.is_none() {
            warn!(instance_id = %instance_id, "audit plugin client not registered in ClientHub");
        }

        Ok(client)
    }

    async fn resolve_audit_plugin(&self) -> Result<String, anyhow::Error> {
        let registry = self.hub.get::<dyn TypesRegistryClient>()?;
        let plugin_type_id = MiniChatAuditPluginSpecV1::gts_schema_id().clone();
        let instances = registry
            .list(
                ListQuery::new()
                    .with_pattern(format!("{plugin_type_id}*"))
                    .with_is_type(false),
            )
            .await?;

        match choose_plugin_instance::<MiniChatAuditPluginSpecV1>(
            &self.vendor,
            instances.iter().map(|e| (e.gts_id.as_str(), &e.content)),
        ) {
            Ok(gts_id) => Ok(gts_id),
            // No matching instances — audit is optional; cache a sentinel so we
            // don't re-query the registry on every delivery attempt.
            Err(ChoosePluginError::PluginNotFound { .. }) => Ok(String::new()),
            Err(e) => Err(anyhow::Error::new(e)),
        }
    }
}
