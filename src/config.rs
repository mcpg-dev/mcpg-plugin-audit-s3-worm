//! Operator-supplied configuration schema for
//! `dev.mcpg.audit.s3-worm`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WormConfig {
    /// Target bucket. MUST already exist with S3 Object Lock enabled
    /// (`ObjectLockEnabledForBucket` at create time) — the plugin
    /// writes locked objects but does not create / configure the
    /// bucket.
    pub bucket: String,

    /// AWS region the S3 client targets.
    pub region: String,

    /// Optional key prefix, e.g. `audit/`. A trailing slash is added
    /// if missing. Empty = bucket root.
    #[serde(default)]
    pub prefix: String,

    /// Custom endpoint URL for S3-compatible providers (LocalStack,
    /// MinIO). Must be `http(s)://`. `None` = AWS default resolver.
    #[serde(default)]
    pub endpoint_url: Option<String>,

    /// Path-style addressing. Required by MinIO + LocalStack. AWS
    /// prefers virtual-hosted style (the default when `false`).
    #[serde(default)]
    pub force_path_style: bool,

    /// Static credentials. `None` = default AWS chain (IRSA / instance
    /// role / env / profile).
    #[serde(default)]
    pub credentials: Option<StaticCredentials>,

    /// Object Lock retention mode. `governance` (default) lets an IAM
    /// principal with the bypass permission delete early; `compliance`
    /// is immutable to everyone — including root — for the retention
    /// window. Use `compliance` for regulatory WORM.
    #[serde(default)]
    pub retention_mode: RetentionMode,

    /// Retention window in days. `retain_until = now + retention_days`.
    /// Bounded 1..=36_500 (100 years, the S3 ceiling).
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    /// Per-`PutObject` deadline in milliseconds. The audit contract is
    /// synchronous-durable, so a hung write surfaces as
    /// `AuditError::Timeout` rather than blocking the request forever.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StaticCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    /// Deletable only by a principal holding
    /// `s3:BypassGovernanceRetention`. Default.
    #[default]
    Governance,
    /// Immutable for everyone (including the account root) until the
    /// retention date passes.
    Compliance,
}

const MAX_RETENTION_DAYS: u32 = 36_500;

fn default_retention_days() -> u32 {
    365
}
fn default_request_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid audit.s3-worm config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("audit.s3-worm: bucket is empty")]
    EmptyBucket,
    #[error("audit.s3-worm: region is empty")]
    EmptyRegion,
    #[error("audit.s3-worm: endpoint_url must start with http:// or https://")]
    InvalidEndpointScheme,
    #[error("audit.s3-worm: credentials.access_key_id is empty")]
    EmptyAccessKeyId,
    #[error("audit.s3-worm: credentials.secret_access_key is empty")]
    EmptySecretAccessKey,
    #[error("audit.s3-worm: retention_days={0} out of range (must be 1..=36_500)")]
    InvalidRetentionDays(u32),
    #[error("audit.s3-worm: request_timeout_ms must be >= 1")]
    InvalidRequestTimeout,
}

impl WormConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.bucket.trim().is_empty() {
            return Err(ConfigError::EmptyBucket);
        }
        if self.region.trim().is_empty() {
            return Err(ConfigError::EmptyRegion);
        }
        if let Some(ep) = &self.endpoint_url
            && !ep.starts_with("http://")
            && !ep.starts_with("https://")
        {
            return Err(ConfigError::InvalidEndpointScheme);
        }
        if let Some(creds) = &self.credentials {
            if creds.access_key_id.trim().is_empty() {
                return Err(ConfigError::EmptyAccessKeyId);
            }
            if creds.secret_access_key.is_empty() {
                return Err(ConfigError::EmptySecretAccessKey);
            }
        }
        if self.retention_days == 0 || self.retention_days > MAX_RETENTION_DAYS {
            return Err(ConfigError::InvalidRetentionDays(self.retention_days));
        }
        if self.request_timeout_ms == 0 {
            return Err(ConfigError::InvalidRequestTimeout);
        }
        Ok(())
    }

    /// Prefix with a guaranteed trailing slash (empty stays empty).
    pub fn normalized_prefix(&self) -> String {
        if self.prefix.is_empty() || self.prefix.ends_with('/') {
            self.prefix.clone()
        } else {
            format!("{}/", self.prefix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> serde_json::Value {
        json!({ "bucket": "audit-bkt", "region": "us-east-1" })
    }

    #[test]
    fn parses_minimal_with_defaults() {
        let cfg = WormConfig::parse(&minimal().to_string()).unwrap();
        assert_eq!(cfg.bucket, "audit-bkt");
        assert_eq!(cfg.retention_mode, RetentionMode::Governance);
        assert_eq!(cfg.retention_days, 365);
        assert_eq!(cfg.request_timeout_ms, 10_000);
        assert_eq!(cfg.normalized_prefix(), "");
    }

    #[test]
    fn normalizes_prefix_trailing_slash() {
        let mut v = minimal();
        v["prefix"] = json!("audit");
        let cfg = WormConfig::parse(&v.to_string()).unwrap();
        assert_eq!(cfg.normalized_prefix(), "audit/");
    }

    #[test]
    fn rejects_unknown_field() {
        let mut v = minimal();
        v["bogus"] = json!(1);
        assert!(matches!(
            WormConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidJson(_)
        ));
    }

    #[test]
    fn rejects_empty_bucket() {
        let mut v = minimal();
        v["bucket"] = json!("  ");
        assert!(matches!(
            WormConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyBucket
        ));
    }

    #[test]
    fn rejects_bad_endpoint_scheme() {
        let mut v = minimal();
        v["endpoint_url"] = json!("ftp://s3.local");
        assert!(matches!(
            WormConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidEndpointScheme
        ));
    }

    #[test]
    fn rejects_zero_retention_days() {
        let mut v = minimal();
        v["retention_days"] = json!(0);
        assert!(matches!(
            WormConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidRetentionDays(0)
        ));
    }

    #[test]
    fn rejects_oversized_retention_days() {
        let mut v = minimal();
        v["retention_days"] = json!(36_501);
        assert!(matches!(
            WormConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidRetentionDays(_)
        ));
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut v = minimal();
        v["request_timeout_ms"] = json!(0);
        assert!(matches!(
            WormConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidRequestTimeout
        ));
    }

    #[test]
    fn compliance_mode_parses() {
        let mut v = minimal();
        v["retention_mode"] = json!("compliance");
        let cfg = WormConfig::parse(&v.to_string()).unwrap();
        assert_eq!(cfg.retention_mode, RetentionMode::Compliance);
    }

    #[test]
    fn rejects_empty_access_key() {
        let mut v = minimal();
        v["credentials"] = json!({"access_key_id": "", "secret_access_key": "x"});
        assert!(matches!(
            WormConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyAccessKeyId
        ));
    }
}
