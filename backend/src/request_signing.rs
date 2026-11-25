//! Request signing and verification for API endpoints (#529).
//!
//! Clients sign API requests with a private key to prevent tampering.
//! The backend verifies signatures using the corresponding public key.
//!
//! # Signature Scheme
//!
//! Each request includes:
//! - `X-Signature`: HMAC-SHA256 hex digest of the request body
//! - `X-Timestamp`: Unix seconds when the request was signed
//! - `X-Nonce`: Unique request identifier to prevent replay attacks
//!
//! # Algorithm Support
//!
//! - SHA256 (default)
//! - SHA512
//! - ED25519
//!
//! # Nonce Storage (#866)
//!
//! Nonces are stored with their timestamp in a shared `NonceStore` backed by
//! either Redis (multi-instance) or an in-process map (single-process / tests).
//!
//! Each entry expires automatically after `MAX_TIMESTAMP_DRIFT_SECS * 2`
//! seconds, which is the outer bound for a valid nonce. The in-process store
//! prunes stale entries on every `check_and_insert` call so memory is bounded
//! even when Redis is unavailable.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Signature algorithms ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgorithm {
    Sha256,
    Sha512,
    Ed25519,
}

impl Default for SigningAlgorithm {
    fn default() -> Self {
        SigningAlgorithm::Sha256
    }
}

// ── Request signature ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSignature {
    pub algorithm: SigningAlgorithm,
    pub signature: String,
    pub timestamp: i64,
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct SignedRequest {
    pub body: String,
    pub signature: String,
    pub timestamp: String,
    pub nonce: String,
    pub algorithm: Option<String>,
}

// ── Nonce store ───────────────────────────────────────────────────────────────

/// TTL applied to every stored nonce.
///
/// A nonce is valid only within the `MAX_TIMESTAMP_DRIFT_SECS` window on each
/// side of now, so doubling that drift gives a safe outer bound: even a nonce
/// signed at the very edge of the allowed window cannot arrive after this TTL.
pub const NONCE_TTL_SECS: i64 = MAX_TIMESTAMP_DRIFT_SECS * 2;

/// Abstraction over nonce persistence so the verifier works in tests (in-process)
/// and in production (Redis).
pub trait NonceStore: Send + Sync {
    /// Return `true` and record the nonce when it has not been seen before;
    /// return `false` when it is already present (replay detected).
    fn check_and_insert(&self, nonce: &str, now_secs: i64) -> bool;
}

// ── In-process nonce store (single-instance / tests) ─────────────────────────

/// Maps nonce → unix-second timestamp at which it was first seen.
///
/// Stale entries (older than `NONCE_TTL_SECS`) are pruned on every call so
/// memory stays bounded at roughly `request_rate × NONCE_TTL_SECS` entries.
pub struct InProcessNonceStore {
    entries: Mutex<HashMap<String, i64>>,
}

impl InProcessNonceStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InProcessNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore for InProcessNonceStore {
    fn check_and_insert(&self, nonce: &str, now_secs: i64) -> bool {
        let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());

        // Prune expired entries before every check to keep the map bounded.
        map.retain(|_, &mut recorded_at| now_secs - recorded_at < NONCE_TTL_SECS);

        if map.contains_key(nonce) {
            return false;
        }
        map.insert(nonce.to_owned(), now_secs);
        true
    }
}

// ── Redis nonce store (multi-instance) ───────────────────────────────────────

/// Stores nonces in Redis with a per-key TTL so they expire automatically and
/// any number of backend instances share the same replay-protection state.
///
/// The key format is `nonce:<nonce>`.  `SET NX PX` is atomic, so concurrent
/// instances cannot both accept the same nonce.
pub struct RedisNonceStore {
    client: redis::Client,
}

impl RedisNonceStore {
    /// Create a store from a Redis connection URL, e.g. `redis://127.0.0.1/`.
    pub fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }
}

impl NonceStore for RedisNonceStore {
    fn check_and_insert(&self, nonce: &str, _now_secs: i64) -> bool {
        use redis::Commands;
        let mut conn = match self.client.get_connection() {
            Ok(c) => c,
            // If Redis is unreachable, fail closed (reject the request) to
            // avoid inadvertently accepting replays during an outage.
            Err(_) => return false,
        };

        let key = format!("nonce:{nonce}");
        let ttl_ms = (NONCE_TTL_SECS * 1000) as u64;

        // SET key 1 NX PX ttl_ms — returns Some("OK") on first use, None when key exists.
        let result: Option<String> = match conn.set_options(
            &key,
            "1",
            redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::PX(ttl_ms)),
        ) {
            Ok(v) => v,
            Err(_) => return false,
        };

        result.is_some()
    }
}

// ── Signature verifier ────────────────────────────────────────────────────────

pub struct SignatureVerifier {
    public_keys: Arc<Mutex<Vec<String>>>,
    nonce_store: Arc<dyn NonceStore>,
}

impl SignatureVerifier {
    /// Create a verifier backed by an in-process nonce store.
    pub fn new() -> Self {
        Self {
            public_keys: Arc::new(Mutex::new(Vec::new())),
            nonce_store: Arc::new(InProcessNonceStore::new()),
        }
    }

    /// Create a verifier backed by an arbitrary `NonceStore` (e.g. Redis).
    pub fn with_nonce_store(store: Arc<dyn NonceStore>) -> Self {
        Self {
            public_keys: Arc::new(Mutex::new(Vec::new())),
            nonce_store: store,
        }
    }

    pub fn add_public_key(&self, key: String) {
        let mut keys = self.public_keys.lock().unwrap_or_else(|p| p.into_inner());
        keys.push(key);
    }

    pub fn verify(&self, req: &SignedRequest, secret: &str) -> VerificationResult {
        // 1. Validate timestamp
        let ts = match validate_timestamp(&req.timestamp) {
            Ok(ts) => ts,
            Err(e) => return VerificationResult { valid: false, reason: Some(e) },
        };

        // 2. Check nonce hasn't been used (shared across all instances)
        if !self.nonce_store.check_and_insert(&req.nonce, ts) {
            return VerificationResult {
                valid: false,
                reason: Some("nonce already used (replay attack detected)".to_string()),
            };
        }

        // Ed25519 is not implemented yet, so reject it explicitly instead of
        // failing every signature (#894).
        if req.algorithm.as_deref() == Some("ed25519") {
            return VerificationResult {
                valid: false,
                reason: Some("ed25519 signing is not supported yet".to_string()),
            };
        }

        // 3. Verify signature
        let algorithm = parse_algorithm(&req.algorithm);
        let expected_sig = match sign_request(&req.body, secret, algorithm) {
            Ok(sig) => sig,
            Err(e) => return VerificationResult { valid: false, reason: Some(e) },
        };

        let valid = constant_time_eq(req.signature.as_bytes(), expected_sig.as_bytes());

        // If the signature turned out to be invalid the nonce was already
        // recorded, which is intentional: an attacker replaying a request with
        // a bad signature should not get a second attempt with the same nonce.

        VerificationResult {
            valid,
            reason: if valid {
                None
            } else {
                Some("signature verification failed".to_string())
            },
        }
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub reason: Option<String>,
}

// ── Signature computation ─────────────────────────────────────────────────────

pub fn sign_request(
    body: &str,
    secret: &str,
    algorithm: SigningAlgorithm,
) -> Result<String, String> {
    match algorithm {
        SigningAlgorithm::Sha256 => {
            type H = Hmac<Sha256>;
            let mut mac = H::new_from_slice(secret.as_bytes())
                .map_err(|_| "invalid HMAC key".to_string())?;
            mac.update(body.as_bytes());
            Ok(mac
                .finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect())
        }
        SigningAlgorithm::Sha512 => {
            type H = Hmac<Sha512>;
            let mut mac = H::new_from_slice(secret.as_bytes())
                .map_err(|_| "invalid HMAC key".to_string())?;
            mac.update(body.as_bytes());
            Ok(mac
                .finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect())
        }
        SigningAlgorithm::Ed25519 => {
            // For Ed25519, we'd use ed25519_dalek in production
            // For now, return a placeholder
            Ok(format!("ed25519_{}", uuid::Uuid::new_v4()))
        }
    }
}

fn parse_algorithm(algo_str: &Option<String>) -> SigningAlgorithm {
    match algo_str.as_deref() {
        Some("sha512") => SigningAlgorithm::Sha512,
        Some("ed25519") => SigningAlgorithm::Ed25519,
        _ => SigningAlgorithm::Sha256,
    }
}

// ── Timestamp validation ──────────────────────────────────────────────────────

pub const MAX_TIMESTAMP_DRIFT_SECS: i64 = 300;

/// Validate the timestamp and return its parsed value on success.
pub fn validate_timestamp(timestamp_str: &str) -> Result<i64, String> {
    let ts: i64 = timestamp_str
        .parse()
        .map_err(|_| format!("invalid timestamp: {timestamp_str}"))?;

    let now = Utc::now().timestamp();
    let drift = (now - ts).abs();

    if drift > MAX_TIMESTAMP_DRIFT_SECS {
        return Err(format!(
            "timestamp drift too large: {drift}s > {MAX_TIMESTAMP_DRIFT_SECS}s"
        ));
    }

    Ok(ts)
}

// ── Constant-time comparison ──────────────────────────────────────────────────

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn current_timestamp_str() -> String {
        Utc::now().timestamp().to_string()
    }

    #[test]
    fn sign_and_verify_sha256() {
        let body = r#"{"action":"transfer","amount":100}"#;
        let secret = "test-secret-key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig.clone(),
            timestamp: current_timestamp_str(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: Some("sha256".to_string()),
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(result.valid, "signature should verify: {:?}", result.reason);
    }

    #[test]
    fn sign_and_verify_sha512() {
        let body = r#"{"action":"withdraw","amount":500}"#;
        let secret = "another-secret-key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha512).expect("signing should succeed");

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig.clone(),
            timestamp: current_timestamp_str(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: Some("sha512".to_string()),
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(result.valid, "signature should verify: {:?}", result.reason);
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let body = r#"{"action":"transfer"}"#;
        let secret_a = "secret-a";
        let secret_b = "secret-b";
        let sig = sign_request(body, secret_a, SigningAlgorithm::Sha256).expect("signing should succeed");

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: current_timestamp_str(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: None,
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret_b);
        assert!(!result.valid, "signature should not verify with wrong secret");
        assert!(
            result
                .reason
                .as_ref()
                .expect("reason should be present")
                .contains("failed"),
            "error reason should indicate verification failure"
        );
    }

    #[test]
    fn tampered_body_fails_verification() {
        let original_body = r#"{"amount":100}"#;
        let tampered_body = r#"{"amount":999}"#;
        let secret = "key";
        let sig = sign_request(original_body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");

        let req = SignedRequest {
            body: tampered_body.to_string(),
            signature: sig,
            timestamp: current_timestamp_str(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: None,
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(!result.valid, "tampering should be detected");
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let body = r#"{"action":"test"}"#;
        let secret = "key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");

        // 10 minutes in the past
        let old_timestamp = (Utc::now().timestamp() - 600).to_string();

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: old_timestamp,
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: None,
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(!result.valid, "stale timestamp should be rejected");
        assert!(
            result
                .reason
                .as_ref()
                .expect("reason should be present")
                .contains("drift"),
            "error should mention timestamp drift"
        );
    }

    #[test]
    fn replay_attack_is_prevented() {
        let body = r#"{"action":"transfer"}"#;
        let secret = "key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");
        let nonce = uuid::Uuid::new_v4().to_string();

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: current_timestamp_str(),
            nonce: nonce.clone(),
            algorithm: None,
        };

        let verifier = SignatureVerifier::new();
        // First verification should succeed
        let result1 = verifier.verify(&req, secret);
        assert!(result1.valid, "first verification should succeed");

        // Second verification with same nonce should fail
        let req2 = SignedRequest {
            body: body.to_string(),
            signature: sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed"),
            timestamp: current_timestamp_str(),
            nonce: nonce.clone(),
            algorithm: None,
        };
        let result2 = verifier.verify(&req2, secret);
        assert!(!result2.valid, "replay attack should be detected");
        assert!(
            result2
                .reason
                .as_ref()
                .expect("reason should be present")
                .contains("replay"),
            "error should mention replay attack"
        );
    }

    #[test]
    fn multiple_different_nonces_are_accepted() {
        let body = r#"{"action":"test"}"#;
        let secret = "key";
        let verifier = SignatureVerifier::new();

        for i in 0..5 {
            let sig = sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");
            let req = SignedRequest {
                body: body.to_string(),
                signature: sig,
                timestamp: current_timestamp_str(),
                nonce: format!("nonce-{i}"),
                algorithm: None,
            };

            let result = verifier.verify(&req, secret);
            assert!(
                result.valid,
                "verification should succeed for unique nonce: {i}"
            );
        }
    }

    #[test]
    fn future_timestamp_within_tolerance_is_accepted() {
        let body = r#"{"action":"test"}"#;
        let secret = "key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");

        // 1 minute in the future (within tolerance)
        let future_timestamp = (Utc::now().timestamp() + 60).to_string();

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: future_timestamp,
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: None,
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(result.valid, "future timestamp within tolerance should be accepted");
    }

    #[test]
    fn invalid_timestamp_format_is_rejected() {
        let body = r#"{"action":"test"}"#;
        let secret = "key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: "not-a-number".to_string(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: None,
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(!result.valid, "invalid timestamp should be rejected");
        assert!(
            result
                .reason
                .as_ref()
                .expect("reason should be present")
                .contains("invalid"),
            "error should indicate invalid timestamp"
        );
    }

    #[test]
    fn empty_body_can_be_signed() {
        let body = "";
        let secret = "key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha256).expect("signing should succeed");

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: current_timestamp_str(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: None,
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(result.valid, "empty body should be signable");
    }

    #[test]
    fn large_body_is_signed_correctly() {
        let body = &"x".repeat(100_000); // 100KB body
        let secret = "key";
        let sig = sign_request(body, secret, SigningAlgorithm::Sha512).expect("signing should succeed");

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: current_timestamp_str(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: Some("sha512".to_string()),
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(result.valid, "large body should be signed correctly");
    }

    #[test]
    fn default_algorithm_is_sha256() {
        let body = r#"{"test":true}"#;
        let secret = "key";

        // Sign without specifying algorithm (defaults to SHA256)
        let sig = sign_request(body, secret, SigningAlgorithm::default()).expect("signing should succeed");

        let req = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp: current_timestamp_str(),
            nonce: uuid::Uuid::new_v4().to_string(),
            algorithm: None, // No algorithm specified
        };

        let verifier = SignatureVerifier::new();
        let result = verifier.verify(&req, secret);
        assert!(result.valid, "default algorithm should be SHA256");
    }

    #[test]
    fn public_key_management() {
        let verifier = SignatureVerifier::new();
        verifier.add_public_key("key-1".to_string());
        verifier.add_public_key("key-2".to_string());

        let keys = verifier.public_keys.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(keys.len(), 2, "should have 2 public keys");
        assert!(keys.contains(&"key-1".to_string()));
        assert!(keys.contains(&"key-2".to_string()));
    }

    // ── Nonce pruning ─────────────────────────────────────────────────────────

    #[test]
    fn expired_nonces_are_pruned_and_reusable() {
        // Insert a nonce as if it arrived NONCE_TTL_SECS ago (i.e. just expired).
        let store = InProcessNonceStore::new();
        let now = Utc::now().timestamp();
        let nonce = "prunable-nonce";

        // Directly seed an expired entry.
        {
            let mut map = store.entries.lock().unwrap();
            map.insert(nonce.to_owned(), now - NONCE_TTL_SECS);
        }

        // check_and_insert should prune the stale entry and accept the nonce.
        assert!(
            store.check_and_insert(nonce, now),
            "expired nonce should be pruned and accepted"
        );
    }

    #[test]
    fn nonce_within_ttl_is_rejected_as_replay() {
        let store = InProcessNonceStore::new();
        let now = Utc::now().timestamp();
        let nonce = "live-nonce";

        // Insert a nonce that is still within the TTL window.
        {
            let mut map = store.entries.lock().unwrap();
            map.insert(nonce.to_owned(), now - (NONCE_TTL_SECS / 2));
        }

        assert!(
            !store.check_and_insert(nonce, now),
            "nonce within TTL should be rejected as replay"
        );
    }

    #[test]
    fn in_process_store_memory_stays_bounded() {
        // Insert many entries that all expired, then add one live entry.
        // After the call the map should contain only the live entry.
        let store = InProcessNonceStore::new();
        let now = Utc::now().timestamp();

        {
            let mut map = store.entries.lock().unwrap();
            for i in 0..1000 {
                map.insert(format!("old-{i}"), now - NONCE_TTL_SECS - 1);
            }
        }

        store.check_and_insert("new-nonce", now);

        let map = store.entries.lock().unwrap();
        assert_eq!(map.len(), 1, "only the live nonce should remain after pruning");
    }

    // ── Multi-instance replay test ────────────────────────────────────────────

    /// Two `SignatureVerifier` instances share the same `InProcessNonceStore`
    /// (simulating a shared backing store).  A request accepted by instance A
    /// must be rejected as a replay by instance B.
    #[test]
    fn shared_store_prevents_cross_instance_replay() {
        let shared_store: Arc<dyn NonceStore> = Arc::new(InProcessNonceStore::new());

        let instance_a = SignatureVerifier::with_nonce_store(Arc::clone(&shared_store));
        let instance_b = SignatureVerifier::with_nonce_store(Arc::clone(&shared_store));

        let body = r#"{"action":"cross-instance-transfer","amount":250}"#;
        let secret = "shared-secret";
        let nonce = uuid::Uuid::new_v4().to_string();
        let timestamp = current_timestamp_str();

        let sig = sign_request(body, secret, SigningAlgorithm::Sha256)
            .expect("signing should succeed");

        let req_a = SignedRequest {
            body: body.to_string(),
            signature: sig.clone(),
            timestamp: timestamp.clone(),
            nonce: nonce.clone(),
            algorithm: Some("sha256".to_string()),
        };

        // Instance A processes the request first — must succeed.
        let result_a = instance_a.verify(&req_a, secret);
        assert!(
            result_a.valid,
            "instance A should accept the original request: {:?}",
            result_a.reason
        );

        // Instance B sees the same nonce — must be rejected as a replay.
        let req_b = SignedRequest {
            body: body.to_string(),
            signature: sig,
            timestamp,
            nonce,
            algorithm: Some("sha256".to_string()),
        };
        let result_b = instance_b.verify(&req_b, secret);
        assert!(
            !result_b.valid,
            "instance B should reject the replayed request"
        );
        assert!(
            result_b
                .reason
                .as_ref()
                .expect("reason should be present")
                .contains("replay"),
            "rejection reason should mention replay"
        );
    }

    /// Two independent `SignatureVerifier` instances backed by *separate*
    /// in-process stores (the old, broken behaviour) each accept the same
    /// nonce.  This test documents the bug that `shared_store_prevents_cross_instance_replay`
    /// fixes.
    #[test]
    fn independent_stores_do_not_share_nonce_state() {
        let instance_a = SignatureVerifier::new(); // own store
        let instance_b = SignatureVerifier::new(); // own store — isolated

        let body = r#"{"action":"test"}"#;
        let secret = "key";
        let nonce = uuid::Uuid::new_v4().to_string();
        let timestamp = current_timestamp_str();

        let sig = sign_request(body, secret, SigningAlgorithm::Sha256)
            .expect("signing should succeed");

        let make_req = || SignedRequest {
            body: body.to_string(),
            signature: sig.clone(),
            timestamp: timestamp.clone(),
            nonce: nonce.clone(),
            algorithm: Some("sha256".to_string()),
        };

        let result_a = instance_a.verify(&make_req(), secret);
        let result_b = instance_b.verify(&make_req(), secret);

        // Both accept — this is the known limitation of per-process storage.
        assert!(result_a.valid, "instance A should accept");
        assert!(
            result_b.valid,
            "instance B also accepts (isolated store — expected without shared backing)"
        );
    }
}
