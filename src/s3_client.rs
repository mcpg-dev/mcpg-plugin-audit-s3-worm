//! Thin async wrapper over S3 `PutObject` with Object Lock.
//!
//! One `PutObject` per audit event, written with an Object-Lock
//! retention header so the object is immutable for the configured
//! window. The cdylib FFI boundary is sync, so the plugin bundles a
//! private tokio runtime and `block_on`s `put_event`.

use std::time::Duration;

use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Builder as S3ConfigBuilder;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_s3::primitives::{ByteStream, DateTime};
use aws_sdk_s3::types::ObjectLockMode;
use mcpg_plugin_protocol::audit::AuditError;

use crate::config::{RetentionMode, WormConfig};

const SECS_PER_DAY: i64 = 86_400;

pub(crate) struct S3WormClient {
    client: Client,
    bucket: String,
    retention_mode: ObjectLockMode,
    retention_days: i64,
    request_timeout: Duration,
}

impl S3WormClient {
    pub(crate) async fn new(cfg: &WormConfig) -> Self {
        let mut builder = S3ConfigBuilder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(cfg.region.clone()))
            .force_path_style(cfg.force_path_style);

        if let Some(endpoint) = &cfg.endpoint_url {
            builder = builder.endpoint_url(endpoint.clone());
        }

        if let Some(creds) = &cfg.credentials {
            builder = builder.credentials_provider(Credentials::new(
                creds.access_key_id.clone(),
                creds.secret_access_key.clone(),
                creds.session_token.clone(),
                None,
                "mcpg-worm-static",
            ));
        } else {
            // Default chain (IRSA / instance role / env / profile).
            // Loading it is async; materialise the provider once here.
            let defaults = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(cfg.region.clone()))
                .load()
                .await;
            if let Some(provider) = defaults.credentials_provider() {
                builder = builder.credentials_provider(provider);
            }
        }

        Self {
            client: Client::from_conf(builder.build()),
            bucket: cfg.bucket.clone(),
            retention_mode: match cfg.retention_mode {
                RetentionMode::Governance => ObjectLockMode::Governance,
                RetentionMode::Compliance => ObjectLockMode::Compliance,
            },
            retention_days: cfg.retention_days as i64,
            request_timeout: Duration::from_millis(cfg.request_timeout_ms),
        }
    }

    /// Write one event as an immutable, Object-Lock-retained object.
    /// Returns Ok only after `PutObject` durably completes — the
    /// audit-sink contract.
    pub(crate) async fn put_event(
        &self,
        key: &str,
        body: Vec<u8>,
        metadata: Vec<(&'static str, String)>,
    ) -> Result<(), AuditError> {
        let retain_until = DateTime::from_secs(
            chrono::Utc::now().timestamp() + self.retention_days * SECS_PER_DAY,
        );

        let mut put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type("application/json")
            .object_lock_mode(self.retention_mode.clone())
            .object_lock_retain_until_date(retain_until);
        for (k, v) in metadata {
            put = put.metadata(k, v);
        }

        match tokio::time::timeout(self.request_timeout, put.send()).await {
            Err(_elapsed) => Err(AuditError::Timeout),
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(classify_put_error(err)),
        }
    }
}

/// Map an S3 `PutObject` SDK error onto the audit-sink error taxonomy.
fn classify_put_error(err: SdkError<PutObjectError>) -> AuditError {
    if matches!(&err, SdkError::TimeoutError(_)) {
        return AuditError::Timeout;
    }
    let svc = err.as_service_error();
    let code = svc.and_then(|e| e.code()).unwrap_or_default();
    let reason = svc
        .and_then(|e| e.message())
        .map(str::to_owned)
        .unwrap_or_else(|| err.to_string());
    match code {
        "Throttling" | "ThrottlingException" | "RequestLimitExceeded" | "SlowDown" => {
            AuditError::Throttled
        }
        _ => AuditError::WriteFailed {
            reason: if code.is_empty() {
                reason
            } else {
                format!("S3 PutObject [{code}]: {reason}")
            },
        },
    }
}
