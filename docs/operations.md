# Operations Runbook

Operational procedures for running, securing, backing up, and recovering the Ethos-Protocol backend and smart-contract infrastructure. This runbook satisfies **ISO 27001 A.12.1 (Operational Procedures and Responsibilities)**.

## Table of Contents

- [Key Rotation Procedures](#key-rotation-procedures)
- [Backup Schedules](#backup-schedules)
- [Restore Drills](#restore-drills)
- [On-Call Contacts & Escalation](#on-call-contacts--escalation)
- [Related Documentation](#related-documentation)

---

## Key Rotation Procedures

All long-lived secrets follow the intervals and grace periods defined in the [Secret Rotation Policy](secret-rotation-policy.md).

### Rotation Schedule Summary

| Secret Type | Environment / Scope | Rotation Interval | Grace Period |
|---|---|---|---|
| `api_key` | `ADMIN_API_KEY` | 90 days | 24 hours |
| `database_password` | Database credentials | 30 days | 2 hours |
| `encryption_key` | Vault AES-GCM encryption keys | 365 days | 48 hours |
| `jwt_secret` | Session / JWT signing secret | 30 days | 192 hours |
| `webhook_secret` | Webhook HMAC signing secret | 90 days | 24 hours |
| `reminders_api_key` | `REMINDER_EMAIL_API_KEY`, `REMINDER_SMS_API_KEY` | 90 days | 24 hours |

### Standard (Planned) Rotation

1. **Generate new secret material** using a CSPRNG (e.g., `openssl rand -hex 32`) outside the application and store it in your secrets manager.
2. **Stage the new secret** in all runtime environments and CI/CD secret stores while keeping the previous secret active during the grace period.
3. **Record the rotation and start the grace period** via the admin API:
   ```bash
   curl -X POST https://<host>/api/secret-rotation/<secret_type>/rotate \
     -H "Authorization: Bearer $ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"notes": "Scheduled rotation"}'
   ```
4. **Verify service health** (`GET /health`) and confirm no authentication errors appear in structured logs.
5. **Decommission the old secret** once the grace period recorded in `secret_rotation_logs` has elapsed.

### Emergency Rotation (Suspected Compromise)

1. Immediately generate replacement secret material and deploy it to all production instances.
2. Trigger the rotation endpoint with an incident reference in `notes`.
3. Revoke the compromised secret at the upstream provider (email, SMS, database, or secrets manager) without waiting for the standard grace period.
4. Audit recent requests via `GET /api/audit-logs` for unauthorized activity and follow the escalation path in [On-Call Contacts & Escalation](#on-call-contacts--escalation).

---

## Backup Schedules

Ethos-Protocol maintains backups across three layers:

| Asset | Frequency | Retention | Storage & Encryption | Verification |
|---|---|---|---|---|
| **Backend SQLite Database** | Daily at 02:00 UTC (plus pre-migration snapshots) | 30 daily, 12 monthly | Off-host encrypted object storage (AES-256 / KMS) | Automated hourly check via `POST /admin/validate-backup` |
| **Encrypted Vault Backups** | On every vault state change | Per-vault lifecycle policy | AES-GCM encrypted prior to storage | Checksum & decryption check during restore drills |
| **Smart Contract State** | Daily & before any contract upgrade | 90 days | Versioned off-host snapshots | See [Contract State Backup](contract-state-backup.md) |

### Manual Backup Snapshot

Before running database migrations or high-risk deployments:

1. Create a consistent SQLite snapshot (e.g., `sqlite3 <db_path> ".backup '<snapshot_path>'"`).
2. Upload the snapshot to the encrypted backup bucket with a UTC timestamped filename (e.g., `ethos-db-YYYY-MM-DDTHH-MM-SSZ.sqlite`).
3. Validate the snapshot using the backup validation endpoint (see [Backup Validation](backup-validation.md)):
   ```bash
   curl -X POST https://<host>/admin/validate-backup \
     -H "Authorization: Bearer $ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"backup_id\": \"manual-$(date -u +%Y-%m-%d)\", \"data_base64\": \"$(base64 -w0 <snapshot_path>)\"}"
   ```
4. Confirm the response returns `"valid": true`, `"integrity_ok": true`, and `"restore_test_ok": true`.

---

## Restore Drills

Regular restore drills verify that backups are usable and that operators can meet recovery objectives.

### Cadence & Recovery Objectives

- **Drill cadence:** Monthly (first Tuesday of each month) and after any major schema or infrastructure change.
- **Target RPO (Recovery Point Objective):** ≤ 24 hours.
- **Target RTO (Recovery Time Objective):** ≤ 1 hour.

### Drill Procedure

1. **Provision an isolated staging environment** (never run restore drills against production).
2. **Fetch the latest production backup** from encrypted off-host storage and record the start timestamp.
3. **Validate backup integrity** via `POST /admin/validate-backup` and verify the SQLite integrity check:
   ```bash
   sqlite3 restored.sqlite "PRAGMA integrity_check;"
   ```
4. **Restore and start the backend** pointed at the restored database file.
5. **Run smoke checks:**
   - `GET /health` returns `200 OK`.
   - `GET /admin/compliance-report` returns `200 OK` with expected check counts.
   - Sample read queries against vaults and audit logs succeed without errors.
6. **Record drill results** (date, operator, backup ID, elapsed restore time vs. RTO, pass/fail, and any follow-up actions) in the operations log and tear down the temporary staging environment.

---

## On-Call Contacts & Escalation

### Escalation Tiers

| Tier | Role | Responsibilities | Initial Response Target |
|---|---|---|---|
| **Tier 1** | Primary On-Call Engineer | Alert triage, service restarts, initial mitigation, backup/restore execution | 15 minutes (SEV-1) / 1 hour (SEV-2) |
| **Tier 2** | Backend / Smart Contract Maintainer | Code-level debugging, emergency key rotation, contract pause/upgrade | 30 minutes (SEV-1) / 4 hours (SEV-2) |
| **Tier 3** | Security & Engineering Lead | Security incident coordination, external disclosure, compliance reporting | 1 hour (SEV-1) |

### Contact Channels

- **Primary On-Call Rotation:** Configured in the team's paging/alerting tool (see [Alert Runbook](runbook-alerts.md)).
- **Security Incidents & Vulnerability Disclosure:** Follow [SECURITY.md](../SECURITY.md).
- **Escalation Rule:** If a SEV-1 incident is not acknowledged within 15 minutes or mitigated within 60 minutes, automatically escalate to the next tier.

---

## Related Documentation

- [Compliance Audit Reports](compliance-audit-reports.md)
- [Secret Rotation Policy](secret-rotation-policy.md)
- [Backup Validation](backup-validation.md)
- [Contract State Backup](contract-state-backup.md)
- [Alert Runbook](runbook-alerts.md)
- [Security Policy](../SECURITY.md)
