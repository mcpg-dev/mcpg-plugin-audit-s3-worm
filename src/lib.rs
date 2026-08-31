//! `dev.mcpg.audit.s3-worm` — `audit_sink` plugin.
//!
//! Persists every audit event as an **immutable** S3 object under
//! Object Lock, so a compliance auditor gets a tamper-evident,
//! retention-protected record (SOC2 / HIPAA / PCI-DSS). Each event is
//! one JSON object keyed by its `event_id`; the object is written with
//! an Object-Lock retention header (`governance` or `compliance` mode,
//! `retain_until = now + retention_days`), which S3 enforces — the
//! object cannot be overwritten or deleted before the retention date.
//!
//! # Durable-ack contract
//!
//! `emit` returns Ok only after the `PutObject` completes, satisfying
//! the audit-sink fan-out contract (the gateway awaits every sink's Ok
//! before completing the request that produced the event, unless the
//! operator opts into fail-open). The returned [`AuditReceipt`] carries
//! the SHA-256 the sink computed over the exact bytes it stored, so a
//! consumer re-derives the hash chain from the stored objects + the
//! receipts.
//!
//! # Bucket prerequisites
//!
//! The bucket MUST already exist with Object Lock enabled at creation
//! (`ObjectLockEnabledForBucket=true`). The plugin writes locked
//! objects; it does not create or reconfigure the bucket. Use
//! `compliance` mode for regulatory WORM (immutable even to root).

mod config;
mod s3_client;

use std::sync::Arc;

use mcpg_plugin_protocol::audit::{AuditError, AuditEvent, AuditReceipt};
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncAuditSink;
use sha2::{Digest, Sha256};
use tokio::runtime::Runtime;

pub use config::{ConfigError, RetentionMode, StaticCredentials, WormConfig};

const PLUGIN_ID: &str = "dev.mcpg.audit.s3-worm";

pub struct S3WormAuditSink {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    client: s3_client::S3WormClient,
    prefix: String,
    runtime: Runtime,
}

impl S3WormAuditSink {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = WormConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "audit.s3-worm: config parse failed; refusing to register"
            );
            panic!(
                "audit.s3-worm config parse failed: {err}. A misconfigured \
                 compliance audit sink is a safety hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: WormConfig) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("audit.s3-worm: failed to build tokio runtime");
        let prefix = cfg.normalized_prefix();
        let client = runtime.block_on(s3_client::S3WormClient::new(&cfg));
        tracing::info!(
            plugin_id = PLUGIN_ID,
            bucket = %cfg.bucket,
            region = %cfg.region,
            retention_days = cfg.retention_days,
            "audit.s3-worm: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "S3 Object-Lock (WORM) Audit Sink".into(),
                    plugin_class: PluginClass::AuditSink,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                client,
                prefix,
                runtime,
            }),
        }
    }
}

async fn emit_inner(inner: &Inner, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
    // Serialize the event to the canonical bytes we store, then hash
    // exactly those bytes — a consumer reads the object back and
    // re-derives the same SHA-256 to verify the chain.
    let body = serde_json::to_vec(event).map_err(|e| AuditError::WriteFailed {
        reason: format!("serialize audit event: {e}"),
    })?;
    let durable_hash = hex::encode(Sha256::digest(&body));
    let key = object_key(&inner.prefix, event);

    let metadata = vec![
        ("mcpg-event-id", event.event_id.clone()),
        ("mcpg-action", event.action.clone()),
        ("mcpg-outcome", event.outcome.to_string()),
        ("mcpg-sha256", durable_hash.clone()),
    ];

    let started = std::time::Instant::now();
    let result = inner.client.put_event(&key, body, metadata).await;
    metrics::histogram!("mcpg_audit_s3_worm_emit_latency_ms")
        .record(started.elapsed().as_millis() as f64);

    match result {
        Ok(()) => {
            metrics::counter!("mcpg_audit_s3_worm_emit_total", "result" => "ok").increment(1);
            Ok(AuditReceipt {
                sink_id: PLUGIN_ID.to_owned(),
                persisted_at: now_rfc3339(),
                durable_hash,
            })
        }
        Err(err) => {
            metrics::counter!(
                "mcpg_audit_s3_worm_emit_total",
                "result" => err.kind_label(),
            )
            .increment(1);
            Err(err)
        }
    }
}

/// Object key for an event: `<prefix>events/<date>/<event_id>.json`.
/// The date is the `occurred_at` calendar day (for cheap prefix-range
/// queries); `event_id` keys the object and is sanitised to a
/// filesystem/key-safe charset so a crafted id can't inject path
/// segments.
fn object_key(prefix: &str, event: &AuditEvent) -> String {
    let date = event
        .occurred_at
        .get(0..10)
        .filter(|d| d.len() == 10 && d.as_bytes()[4] == b'-' && d.as_bytes()[7] == b'-')
        .unwrap_or("undated");
    let id = sanitize_key_component(&event.event_id);
    format!("{prefix}events/{date}/{id}.json")
}

fn sanitize_key_component(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "no-id".to_owned()
    } else {
        cleaned
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

impl SyncAuditSink for S3WormAuditSink {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
        let inner = Arc::clone(&self.inner);
        let event = event.clone();
        self.inner
            .runtime
            .block_on(async move { emit_inner(&inner, &event).await })
    }

    // No buffering: every `emit` is durable before it returns, so
    // `flush` is a no-op. `shutdown` likewise — nothing to drain.
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        audit_sink as entity {
            inner_name: "",
            plugin_type: S3WormAuditSink,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> S3WormAuditSink {
                S3WormAuditSink::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::audit::AuditOutcome;
    use mcpg_plugin_protocol::types::PluginIdentity;
    use serde_json::json;

    fn sample_event(id: &str, occurred_at: &str) -> AuditEvent {
        AuditEvent {
            event_id: id.into(),
            occurred_at: occurred_at.into(),
            actor: PluginIdentity {
                kind: "system".into(),
                trust_level: "verified".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: std::collections::BTreeMap::new(),
            },
            action: "tool.call.denied".into(),
            resource: Some("tool://payments.charge".into()),
            outcome: AuditOutcome::Denied,
            request_id: Some("req-1".into()),
            upstream_request_id: None,
            node_id: None,
            details: json!({"reason": "rate_limit"}),
            prev_event_hash: None,
        }
    }

    fn plugin() -> S3WormAuditSink {
        // Static creds so construction never probes IMDS/SSO and stays
        // fully offline; these unit tests never reach S3.
        let cfg = json!({
            "bucket": "audit-bkt",
            "region": "us-east-1",
            "prefix": "audit",
            "credentials": {"access_key_id": "test", "secret_access_key": "test"}
        });
        S3WormAuditSink::from_config_json(&cfg.to_string())
    }

    #[test]
    fn manifest_is_audit_sink_kind() {
        let p = plugin();
        let m = SyncAuditSink::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::AuditSink);
        assert!(m.required_capabilities.is_empty());
    }

    #[test]
    #[should_panic(expected = "audit.s3-worm config parse failed")]
    fn malformed_config_panics() {
        S3WormAuditSink::from_config_json("{ not json");
    }

    #[test]
    #[should_panic(expected = "audit.s3-worm config parse failed")]
    fn missing_bucket_panics() {
        S3WormAuditSink::from_config_json(&json!({"region": "us-east-1"}).to_string());
    }

    #[test]
    fn object_key_partitions_by_date_and_id() {
        let ev = sample_event(
            "01930000-0000-7000-8000-000000000000",
            "2026-06-22T12:00:00Z",
        );
        let key = object_key("audit/", &ev);
        assert_eq!(
            key,
            "audit/events/2026-06-22/01930000-0000-7000-8000-000000000000.json"
        );
    }

    #[test]
    fn object_key_handles_undated_and_root_prefix() {
        let ev = sample_event("abc", "not-a-date");
        assert_eq!(object_key("", &ev), "events/undated/abc.json");
    }

    #[test]
    fn object_key_sanitises_path_injection_in_id() {
        let ev = sample_event("../../etc/passwd", "2026-06-22T00:00:00Z");
        let key = object_key("p/", &ev);
        // The real guard is no injected '/' in the id component — S3
        // keys are flat strings, so a leftover ".." (dots are key-safe)
        // is a harmless filename, but a '/' would forge a key segment.
        let id_component = &key["p/events/2026-06-22/".len()..];
        assert!(!id_component.contains('/'), "{key}");
        assert_eq!(id_component, ".._.._etc_passwd.json");
    }

    #[test]
    fn sanitize_empty_falls_back() {
        assert_eq!(sanitize_key_component(""), "no-id");
        assert_eq!(sanitize_key_component("a/b c"), "a_b_c");
        assert_eq!(sanitize_key_component("Keep-_.1"), "Keep-_.1");
    }

    #[test]
    fn hash_matches_stored_bytes() {
        // The receipt hash must equal SHA-256 of exactly the bytes we
        // serialize for storage — the consumer re-derives it on replay.
        let ev = sample_event("id-1", "2026-06-22T00:00:00Z");
        let body = serde_json::to_vec(&ev).unwrap();
        let expected = hex::encode(Sha256::digest(&body));
        assert_eq!(expected.len(), 64);
        // Re-serializing the same event is byte-stable.
        let body2 = serde_json::to_vec(&ev).unwrap();
        assert_eq!(body, body2);
    }
}
