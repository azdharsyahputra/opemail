# MailOpen Operations Runbook: Monitoring & Observability

## 1. Prometheus Metrics Endpoints
MailOpen exposes standard metrics on `/metrics`:

| Metric Name | Type | Description |
|---|---|---|
| `mailopen_smtp_connections_total` | Counter | Total inbound SMTP TCP connections |
| `mailopen_smtp_auth_success_total` | Counter | Total successful SASL authentications |
| `mailopen_smtp_auth_failure_total` | Counter | Total rejected authentications |
| `mailopen_messages_received_total` | Counter | Total accepted inbound messages |
| `mailopen_messages_delivered_total`| Counter | Total delivered to local Maildir |
| `mailopen_messages_deferred_total` | Counter | Total messages routed to deferred queue |
| `mailopen_messages_bounced_total`  | Counter | Total permanent bounce notifications |
| `mailopen_spam_detected_total`     | Counter | Total spam messages tagged/quarantined |
| `mailopen_malware_detected_total`  | Counter | Total malware detections rejected |

## 2. Health Probes Semantics
- **`/health/live`**: Returns `200 OK` as long as the process is alive (used by Kubernetes liveness probes).
- **`/health/ready`**: Returns `200 OK` only when PostgreSQL database and critical spool directories are reachable.
- **`/health/deep`**: Comprehensive check verifying write/read on storage, Postfix queue count, and certificate keystores.
