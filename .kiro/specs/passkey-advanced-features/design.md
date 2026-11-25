# Design Document: Passkey Advanced Features

## Overview

This document specifies the technical design for four advanced passkey capabilities in the Ethos-Protocol vault system (issues #557–#560), building on the existing Soroban `ttl_vault` contract (`VaultPasskeys`, `PasskeyExpiry`, `PasskeyUsage`) and the Rust backend `NotificationService`.

1. **Passkey Delegation (#557)**: Time-bounded check-in delegation for a specific passkey from a vault owner to a designated delegate address.
2. **Passkey Audit Trail (#558)**: Append-only on-chain audit log recording every passkey lifecycle operation (`add`, `remove`, `use`, and `rotate` as `remove` + `add`) with actor, hash, and timestamp.
3. **Passkey Escrow (#559)**: Locking a passkey in escrow under a designated recovery contact who can release it for emergency vault access, while preventing normal check-ins while escrowed.
4. **Passkey Expiry Notifications (#560)**: On-chain expiry warning events (`ping_expiry`) and backend push notifications (`PasskeyExpiringSoon` and `PasskeyExpired`) via `NotificationService`.

---

## Architecture

### System Components

- **Smart Contract (`contracts/ttl_vault`)**:
  - `src/types.rs`: `DataKey` variants (`PasskeyDelegation`, `PasskeyEscrow`, `PasskeyAuditLog`) and contract data types (`PasskeyDelegation`, `PasskeyEscrowRecord`, `PasskeyAuditEntry`).
  - `src/contract_impls/passkeys_and_recovery.rs`: Core passkey delegation, audit trail logging, and escrow state transitions and queries.
  - `src/contract_impls/withdrawals.rs`: `ping_expiry` emission of `pk_exp_warn` events when passkey remaining TTL falls below `EXPIRY_WARNING_THRESHOLD`.
  - `src/errors.rs`: Error variants (`PasskeyNotFound`, `InvalidInterval`, `InvalidBeneficiary`, `AlreadyInEscrow`, `NotRecoveryContact`, `VaultNotFound`).
- **Backend Notification Service (`backend/src/notifications.rs`)**:
  - `NotificationType::PasskeyExpiringSoon` and `NotificationType::PasskeyExpired`.
  - `NotificationPreferences::expiry_warning_enabled` preference gate.
  - `NotificationService::schedule_passkey_expiry_check` and `check_passkey_expiry` for deduplicated expiry notification scheduling.

---

## Data Models & Storage Layout

### On-Chain Storage Keys (`DataKey`)

| Storage Key | Value Type | Persistence | Description |
| :--- | :--- | :--- | :--- |
| `DataKey::PasskeyDelegation(u64, BytesN<32>)` | `PasskeyDelegation` | Persistent | Active delegation for `(vault_id, passkey_hash)` |
| `DataKey::PasskeyEscrow(u64, BytesN<32>)` | `PasskeyEscrowRecord` | Persistent | Active escrow record for `(vault_id, passkey_hash)` |
| `DataKey::PasskeyAuditLog(u64)` | `Vec<PasskeyAuditEntry>` | Persistent | Append-only audit log for `vault_id` (bounded by `MAX_PASSKEY_AUDIT_ENTRIES`) |

### On-Chain Structs

```rust
#[contracttype]
#[derive(Clone)]
pub struct PasskeyDelegation {
    pub delegate: Address,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct PasskeyEscrowRecord {
    pub recovery_contact: Address,
    pub escrowed_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct PasskeyAuditEntry {
    pub operation: Symbol, // "add", "remove", "use"
    pub actor: Address,
    pub passkey_hash: BytesN<32>,
    pub timestamp: u64,
}
```

---

## Feature Designs

### 1. Passkey Delegation (#557)

- **`delegate_passkey(env, vault_id, passkey_hash, delegate, expires_at)`**:
  - Requires `owner.require_auth()`.
  - Verifies `passkey_hash` exists in `VaultPasskeys(vault_id)` (`ContractError::PasskeyNotFound`).
  - Verifies `expires_at > env.ledger().timestamp()` (`ContractError::InvalidInterval`).
  - Verifies `delegate != owner` (`ContractError::InvalidBeneficiary`).
  - Stores `PasskeyDelegation { delegate, expires_at }` under `DataKey::PasskeyDelegation(vault_id, passkey_hash)`.
  - Emits event `pk_del` with `(vault_id, passkey_hash, delegate, expires_at)`.
- **`revoke_passkey_delegation(env, vault_id, passkey_hash)`**:
  - Requires `owner.require_auth()`.
  - Removes `DataKey::PasskeyDelegation(vault_id, passkey_hash)` and emits `pk_del_rev` with `(vault_id, passkey_hash, delegate)`.
- **`get_passkey_delegation(env, vault_id, passkey_hash) -> Option<PasskeyDelegation>`**:
  - Returns the active delegation if present and not expired, otherwise `None`.
- **Check-in Authorization**:
  - During `check_in`, if the caller is not the vault owner, the contract checks `DataKey::PasskeyDelegation(vault_id, passkey_hash)`. If a matching delegate exists and `env.ledger().timestamp() < delegation.expires_at`, the check-in is authorized.

### 2. Passkey Audit Trail (#558)

- **Append-Only Logging**:
  - Internal helper appends a `PasskeyAuditEntry` to `DataKey::PasskeyAuditLog(vault_id)` with TTL extended to at least the vault's check-in interval TTL, and emits `pk_audit` with `(vault_id, operation, actor, passkey_hash, timestamp)`.
  - `add_passkey` logs `"add"`.
  - `remove_passkey` logs `"remove"`.
  - `rotate_passkey` logs `"remove"` (old hash) followed by `"add"` (new hash).
  - `check_in` using a passkey logs `"use"`.
  - No mutation or deletion entry points are exposed.
- **`get_passkey_audit_log(env, vault_id) -> Result<Vec<PasskeyAuditEntry>, ContractError>`**:
  - Returns `ContractError::VaultNotFound` if the vault does not exist; otherwise returns the stored `Vec<PasskeyAuditEntry>`.

### 3. Passkey Escrow (#559)

- **`escrow_passkey(env, vault_id, passkey_hash, recovery_contact)`**:
  - Requires `owner.require_auth()`.
  - Verifies `passkey_hash` exists in `VaultPasskeys(vault_id)` (`ContractError::PasskeyNotFound`).
  - Verifies `recovery_contact != owner` (`ContractError::InvalidBeneficiary`).
  - Verifies no existing escrow record (`ContractError::AlreadyInEscrow`).
  - Stores `PasskeyEscrowRecord { recovery_contact, escrowed_at: now }` under `DataKey::PasskeyEscrow(vault_id, passkey_hash)`.
  - Emits event `pk_esc` with `(vault_id, passkey_hash, recovery_contact)`.
- **Check-in Restriction**:
  - While `DataKey::PasskeyEscrow(vault_id, passkey_hash)` exists, check-in attempts using that passkey are rejected.
- **`release_escrow_passkey(env, vault_id, passkey_hash)`**:
  - Loads `PasskeyEscrowRecord`, verifies caller is `record.recovery_contact` (`ContractError::NotRecoveryContact`), and calls `record.recovery_contact.require_auth()`.
  - Removes `DataKey::PasskeyEscrow(vault_id, passkey_hash)` and emits `pk_esc_rel` with `(vault_id, passkey_hash, recovery_contact)`.
- **`cancel_passkey_escrow(env, vault_id, passkey_hash)`**:
  - Requires `owner.require_auth()`.
  - Removes `DataKey::PasskeyEscrow(vault_id, passkey_hash)` and emits `pk_esc_can` with `(vault_id, passkey_hash)`.
- **`get_passkey_escrow(env, vault_id, passkey_hash) -> Option<PasskeyEscrowRecord>`**:
  - Returns the active `PasskeyEscrowRecord` if present, or `None`.

### 4. Passkey Expiry Notifications (#560)

- **On-Chain Warning (`ping_expiry`)**:
  - Iterates `VaultPasskeys(vault_id)` and checks each passkey's `DataKey::PasskeyExpiry(vault_id, hash)`.
  - When `0 < seconds_remaining <= EXPIRY_WARNING_THRESHOLD`, emits `pk_exp_warn` with `(vault_id, passkey_hash, seconds_remaining)`.
- **Backend Notification Service (`backend/src/notifications.rs`)**:
  - Adds `NotificationType::PasskeyExpiringSoon` and `NotificationType::PasskeyExpired`.
  - Respects `NotificationPreferences::expiry_warning_enabled` before scheduling `PasskeyExpiringSoon`.
  - Deduplicates pending `PasskeyExpiringSoon` notifications per `(vault_id, passkey_hash)` so at most one warning is delivered per expiry cycle.
  - Formats notification body with `vault_id`, the first 8 hex characters of `passkey_hash`, and approximate hours remaining.
  - Exposes `schedule_passkey_expiry_check` and `check_passkey_expiry` for the backend scheduler.

---

## Testing Strategy

- **Contract Unit & Cap Tests (`contracts/ttl_vault`)**:
  - Delegation lifecycle: grant, delegated check-in, expiry rejection, revocation, invalid inputs, and emitted events (`pk_del`, `pk_del_rev`).
  - Audit trail: verify entry counts and payloads across `add`, `remove`, `rotate`, and `use`, `VaultNotFound` handling, `pk_audit` events, and storage cap behavior (`passkey_cap_tests.rs`).
  - Escrow lifecycle: escrow creation, blocked check-in while escrowed, release by recovery contact, unauthorized release rejection, owner cancellation, duplicate escrow rejection, and events (`pk_esc`, `pk_esc_rel`, `pk_esc_can`).
  - Expiry warnings: `ping_expiry` emission of `pk_exp_warn` within threshold.
- **Backend Unit Tests (`backend/src/notifications.rs`)**:
  - `PasskeyExpiringSoon` scheduling within `EXPIRY_WARNING_THRESHOLD` and `PasskeyExpired` scheduling when already expired.
  - Preference opt-out (`expiry_warning_enabled = false`).
  - Deduplication preventing duplicate pending `PasskeyExpiringSoon` notifications for the same `(vault_id, passkey_hash)`.
  - Notification body formatting (vault ID, 8-char hex hash prefix, hours remaining).
