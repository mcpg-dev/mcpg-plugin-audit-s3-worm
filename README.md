# S3 Object-Lock (WORM) Audit Sink (`dev.mcpg.audit.s3-worm`)

An **audit_sink** plugin that persists every audit event as an
**immutable** S3 object under [Object Lock][objlock] — write-once-
read-many compliance storage for SOC2 / HIPAA / PCI-DSS.

Each event is one JSON object keyed by its `event_id`, written with an
Object-Lock retention header (`governance` or `compliance` mode,
`retain_until = now + retention_days`). S3 enforces it: the object
**cannot be overwritten or deleted** before the retention date.

## Durable-ack contract

`emit` returns Ok **only after** the `PutObject` durably completes — the
audit-sink fan-out contract (the gateway awaits every sink's Ok before
completing the request that produced the event, unless the operator
opts into fail-open). The returned `AuditReceipt` carries the SHA-256
the sink computed over the **exact bytes it stored**, so a consumer
re-derives the hash chain from the stored objects + the receipts.

## Bucket prerequisites

The bucket **must already exist with Object Lock enabled at creation**
(`ObjectLockEnabledForBucket=true` — it cannot be turned on after the
fact). The plugin writes locked objects; it does not create or
reconfigure the bucket. Grant the gateway's principal `s3:PutObject` +
`s3:PutObjectRetention` on the prefix.

```bash
aws s3api create-bucket --bucket my-audit-wormbucket \
    --object-lock-enabled-for-bucket --region us-east-1
```

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `bucket` | string | *(required)* | Object-Lock-enabled bucket. |
| `region` | string | *(required)* | AWS region. |
| `prefix` | string | `""` | Key prefix; trailing slash added if missing. |
| `endpoint_url` | string | *(none)* | S3 endpoint override (LocalStack / MinIO / VPC). |
| `force_path_style` | bool | `false` | Path-style addressing (MinIO / LocalStack need `true`). |
| `credentials` | object | *(none → default chain)* | `{ access_key_id, secret_access_key, session_token? }`. Production should omit + run as an IAM principal. |
| `retention_mode` | `governance` \| `compliance` | `governance` | `compliance` is immutable to everyone incl. root; `governance` allows early delete by a principal with `s3:BypassGovernanceRetention`. Use `compliance` for regulatory WORM. |
| `retention_days` | int | `365` | Retention window; `retain_until = now + retention_days`. `1..=36500`. |
| `request_timeout_ms` | int | `10000` | Per-`PutObject` deadline; a hung write surfaces as `AuditError::Timeout`. |

## Object layout

```
<prefix>events/<YYYY-MM-DD>/<event_id>.json
```

The date is the event's `occurred_at` calendar day (cheap prefix-range
queries); `event_id` keys the object (sanitised to a key-safe charset).
Each object also carries `x-amz-meta-mcpg-{event-id,action,outcome,sha256}`.

## Example

```yaml
# Top-level `plugins:` is a flat list of plugin entries. An audit_sink
# registers globally (no per-binding wiring) — every audit event fans out
# to it once loaded.
plugins:
  - id: dev.mcpg.audit.s3-worm
    class: audit_sink
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/audit-s3-worm:protocol-1" }
    config:
      bucket: acme-mcpg-audit-worm
      region: us-east-1
      prefix: gateway-prod
      retention_mode: compliance
      retention_days: 2555   # 7 years
```

## Testing

Unit tests (`cargo test -p mcpg-plugin-audit-s3-worm --lib`) cover
config validation, object-key derivation + path-injection sanitising,
and hash stability — all offline. A LocalStack-backed integration suite
creates an Object-Lock bucket, emits an event, and asserts the stored
bytes hash to the receipt + the object carries a retention header:

```bash
cargo test -p mcpg-plugin-audit-s3-worm --features integration-tests --test integration
```

(needs Docker; runs in the `--config=integration` CI lane.)

## Notes

- Pure-Rust, rustls-only: the AWS SDK uses the modern
  `default-https-client` (aws-lc-rs / rustls 0.23) — **not** the legacy
  `rustls` feature.
- `network_outbound` capability (reaches the S3 endpoint).
- No buffering — every `emit` is durable before it returns, so `flush`
  and `shutdown` are no-ops.
- Works against any S3-API service that supports Object Lock (AWS S3,
  MinIO with object locking enabled).

[objlock]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
