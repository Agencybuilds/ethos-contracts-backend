# Implementation Plan: Passkey Advanced Features

## Overview

This task list tracks the implementation of the four advanced passkey features defined in `requirements.md` and `design.md` (issues #557–#560) across `contracts/ttl_vault` and `backend/src/notifications.rs`.

---

## Tasks

- [x] 1. Passkey Delegation (Issue #557)
  - [x] 1.1 Add `DataKey::PasskeyDelegation(u64, BytesN<32>)` and `PasskeyDelegation` struct in `contracts/ttl_vault/src/types.rs`
  - [x] 1.2 Implement `delegate_passkey`, `revoke_passkey_delegation`, and `get_passkey_delegation` in `contracts/ttl_vault/src/contract_impls/passkeys_and_recovery.rs`
  - [x] 1.3 Enforce owner auth, passkey existence (`PasskeyNotFound`), future `expires_at` (`InvalidInterval`), and non-owner delegate (`InvalidBeneficiary`)
  - [x] 1.4 Allow active, non-expired delegates to perform `check_in` and emit `pk_del` / `pk_del_rev` events
  - [x] 1.5 Add unit tests covering delegation creation, check-in authorization, expiration, revocation, and error cases

- [x] 2. Passkey Audit Trail (Issue #558)
  - [x] 2.1 Add `DataKey::PasskeyAuditLog(u64)` and `PasskeyAuditEntry` struct in `contracts/ttl_vault/src/types.rs`
  - [x] 2.2 Implement append-only audit logging on `add_passkey`, `remove_passkey`, `rotate_passkey`, and passkey `check_in` in `contracts/ttl_vault/src/contract_impls/passkeys_and_recovery.rs`
  - [x] 2.3 Implement `get_passkey_audit_log` query returning `VaultNotFound` for missing vaults and emit `pk_audit` events on each append
  - [x] 2.4 Add unit and storage-cap tests in `contracts/ttl_vault/src/passkey_cap_tests.rs`

- [x] 3. Passkey Escrow (Issue #559)
  - [x] 3.1 Add `DataKey::PasskeyEscrow(u64, BytesN<32>)` and `PasskeyEscrowRecord` struct in `contracts/ttl_vault/src/types.rs`
  - [x] 3.2 Implement `escrow_passkey`, `release_escrow_passkey`, `cancel_passkey_escrow`, and `get_passkey_escrow` in `contracts/ttl_vault/src/contract_impls/passkeys_and_recovery.rs`
  - [x] 3.3 Block check-ins using escrowed passkeys and enforce `AlreadyInEscrow`, `InvalidBeneficiary`, `PasskeyNotFound`, and `NotRecoveryContact`
  - [x] 3.4 Emit `pk_esc`, `pk_esc_rel`, and `pk_esc_can` events and add unit tests for the full escrow lifecycle

- [x] 4. Passkey Expiry Notifications (Issue #560)
  - [x] 4.1 Emit `pk_exp_warn` events in `ping_expiry` (`contracts/ttl_vault/src/contract_impls/withdrawals.rs`) when remaining TTL is below `EXPIRY_WARNING_THRESHOLD`
  - [x] 4.2 Add `NotificationType::PasskeyExpiringSoon` and `NotificationType::PasskeyExpired` in `backend/src/notifications.rs`
  - [x] 4.3 Implement `schedule_passkey_expiry_check` and `check_passkey_expiry` with preference gating, deduplication per `(vault_id, passkey_hash)`, and truncated hash formatting
  - [x] 4.4 Add unit tests in `backend/src/notifications.rs` verifying warning/expired scheduling, preference opt-out, deduplication, and message formatting
