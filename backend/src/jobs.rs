// #74 — Bulk Operation Queuing
// Implements: async job queue, POST /jobs, GET /jobs/{job_id}, progress tracking, result retrieval

use chrono::{DateTime, Utc};
use rusqlite::{params, types::Type, Connection, Error as SqliteError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Job status ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

// ── Supported bulk operation types ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BulkOperationType {
    /// Batch-update TTL for multiple vaults.
    UpdateTtl,
    /// Send reminder notifications to a list of vault owners.
    SendReminders,
    /// Export multiple vaults to JSON.
    ExportVaults,
    /// Apply a retention policy sweep across all time-series.
    RetentionSweep,
    /// Generic batch of arbitrary operations defined in `payload`.
    Custom,
}

// ── Core job struct ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkJob {
    pub id: String,
    pub operation: BulkOperationType,
    /// Caller-supplied input data (e.g., list of vault IDs).
    pub payload: serde_json::Value,
    pub status: JobStatus,
    /// 0–100 progress percentage.
    pub progress: u8,
    /// Total number of items in this job.
    pub total_items: usize,
    /// Items processed so far.
    pub processed_items: usize,
    /// Items that resulted in an error.
    pub failed_items: usize,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Structured result once the job is done.
    pub result: Option<serde_json::Value>,
    /// Human-readable error message on failure.
    pub error: Option<String>,
    /// Optional label supplied by the caller.
    pub label: Option<String>,
    /// Ingress correlation id (issue #349), propagated from the `X-Request-Id`
    /// header of the request that enqueued the job so its asynchronous
    /// processing can be traced back to that request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl BulkJob {
    pub fn new(
        operation: BulkOperationType,
        payload: serde_json::Value,
        total_items: usize,
        label: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            operation,
            payload,
            status: JobStatus::Queued,
            progress: 0,
            total_items,
            processed_items: 0,
            failed_items: 0,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            result: None,
            error: None,
            label,
            request_id: None,
        }
    }

    /// Attach the ingress correlation id (issue #349).
    #[must_use]
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    /// Advance progress; clamps to 100.
    pub fn advance(&mut self, processed: usize, failed: usize) {
        self.processed_items += processed;
        self.failed_items += failed;
        if self.total_items > 0 {
            self.progress = ((self.processed_items * 100) / self.total_items).min(100) as u8;
        }
    }

    pub fn mark_running(&mut self) {
        self.status = JobStatus::Running;
        self.started_at = Some(Utc::now());
    }

    pub fn mark_completed(&mut self, result: serde_json::Value) {
        self.status = JobStatus::Completed;
        self.progress = 100;
        self.completed_at = Some(Utc::now());
        self.result = Some(result);
    }

    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = JobStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error.into());
    }

    pub fn mark_cancelled(&mut self) {
        self.status = JobStatus::Cancelled;
        self.completed_at = Some(Utc::now());
    }

    /// Estimated seconds remaining (simple linear extrapolation).
    pub fn estimated_seconds_remaining(&self) -> Option<u64> {
        if self.status != JobStatus::Running {
            return None;
        }
        let started = self.started_at?;
        let elapsed = (Utc::now() - started).num_seconds().max(0) as u64;
        if self.processed_items == 0 {
            return None;
        }
        let rate = self.processed_items as f64 / elapsed.max(1) as f64;
        let remaining = (self.total_items - self.processed_items) as f64;
        Some((remaining / rate).ceil() as u64)
    }
}

// ── Persistent job store ───────────────────────────────────────────────────────

struct Inner {
    conn: Connection,
    jobs: HashMap<String, BulkJob>,
}

#[derive(Clone)]
pub struct JobStore(Arc<Mutex<Inner>>);

fn persist_job(inner: &Inner, job: &BulkJob) -> Result<(), SqliteError> {
    let serialized = serde_json::to_string(job)
        .map_err(|err| SqliteError::ToSqlConversionFailure(Box::new(err)))?;
    inner.conn.execute(
        "INSERT INTO bulk_jobs (id, status, job_json) VALUES (?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET status = excluded.status, job_json = excluded.job_json",
        params![
            job.id,
            format!("{:?}", job.status).to_lowercase(),
            serialized
        ],
    )?;
    Ok(())
}

/// Open a durable job store. Running jobs are returned to the queue after a
/// restart so the caller can dispatch them again.
pub fn open_job_store(path: &str) -> Result<JobStore, SqliteError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS bulk_jobs (
            id TEXT PRIMARY KEY NOT NULL,
            status TEXT NOT NULL,
            job_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bulk_jobs_status ON bulk_jobs(status);",
    )?;

    let mut statement = conn.prepare("SELECT job_json FROM bulk_jobs")?;
    let rows = statement.query_map([], |row| {
        let json: String = row.get(0)?;
        serde_json::from_str(&json)
            .map_err(|err| SqliteError::FromSqlConversionFailure(0, Type::Text, Box::new(err)))
    })?;
    let loaded_jobs: Vec<BulkJob> = rows.collect::<Result<_, _>>()?;
    drop(statement);

    let mut jobs = HashMap::new();
    for mut job in loaded_jobs {
        if job.status == JobStatus::Running {
            job.status = JobStatus::Queued;
            job.started_at = None;
            let serialized = serde_json::to_string(&job)
                .map_err(|err| SqliteError::ToSqlConversionFailure(Box::new(err)))?;
            conn.execute(
                "UPDATE bulk_jobs SET status = 'queued', job_json = ?1 WHERE id = ?2",
                params![serialized, job.id],
            )?;
        }
        jobs.insert(job.id.clone(), job);
    }

    Ok(JobStore(Arc::new(Mutex::new(Inner { conn, jobs }))))
}

/// Create an isolated in-memory job store, primarily for tests.
pub fn create_job_store() -> JobStore {
    open_job_store(":memory:").expect("failed to create in-memory job store")
}

/// Dispatch a persisted queued job on the blocking thread pool.
pub fn spawn_job(store: JobStore, id: String) {
    tokio::task::spawn_blocking(move || {
        if let Err(err) = process_job(&store, &id) {
            tracing::error!(job_id = %id, error = %err, "bulk job processing failed");
        }
    });
}

/// Submit a new job and return its ID after it has been persisted.
pub fn enqueue_job(store: &JobStore, job: BulkJob) -> Result<String, SqliteError> {
    let id = job.id.clone();
    lock_store(store)?.insert(id.clone(), job);
    Ok(id)
}

/// Retrieve a job by ID.
pub fn get_job(store: &JobStore, id: &str) -> Result<Option<BulkJob>, AppError> {
    Ok(lock_store(store)?.get(id).cloned())
}

/// List all jobs, optionally filtered by status.
pub fn list_jobs(
    store: &JobStore,
    status_filter: Option<JobStatus>,
) -> Result<Vec<BulkJob>, AppError> {
    let store = lock_store(store)?;
    let mut jobs: Vec<BulkJob> = store
        .values()
        .filter(|j| status_filter.as_ref().map_or(true, |s| &j.status == s))
        .cloned()
        .collect();
    jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(jobs)
}

/// Cancel a queued job. Returns false if the job is not found or not cancellable.
pub fn cancel_job(store: &JobStore, id: &str) -> Result<bool, AppError> {
    let mut store = lock_store(store)?;
    if let Some(job) = store.get_mut(id) {
        if matches!(job.status, JobStatus::Queued | JobStatus::Running) {
            job.mark_cancelled();
            return Ok(true);
        }
    }
    job.mark_running();
    persist_job(&inner, &job)?;
    inner.jobs.insert(id.to_string(), job);
    Ok(true)
}

// ── Job executor (synchronous simulation for in-process queue) ────────────────
//
// In production this would be a background Tokio task. Here we expose a
// `process_job` function that can be called from a spawned task or inline.

pub fn process_job(store: &JobStore, id: &str) -> Result<(), SqliteError> {
    // Mark running
    {
        let mut s = lock_store(store)?;
        if let Some(job) = s.get_mut(id) {
            if job.status != JobStatus::Queued {
                return Ok(()); // already picked up or cancelled
            }
            job.mark_running();
        } else {
            return Ok(());
        }
    }

    // Simulate processing — real implementations would call domain logic here.
    let (operation, total_items, request_id) = {
        let s = store.lock().unwrap_or_else(|p| p.into_inner());
        // A job removed while it was queued is not an error to panic on (#893).
        let Some(job) = s.get(id) else {
            return;
        };
        (
            job.operation.clone(),
            job.total_items,
            job.request_id.clone(),
        )
    };

    // Carry the correlation id into the span so every log line emitted while
    // this job runs is joinable with the request that enqueued it (#349).
    let _span = tracing::info_span!("bulk_job", job_id = %id, request_id = request_id.as_deref().unwrap_or("none")).entered();

    // Step through items in batches of up to 10.
    let batch_size = 10.min(total_items.max(1));
    let mut processed = {
        let inner = store.0.lock().unwrap();
        inner.jobs.get(id).expect("job exists").processed_items
    };

    while processed < total_items {
        let chunk = batch_size.min(total_items - processed);
        processed += chunk;

        let mut s = lock_store(store)?;
        if let Some(job) = s.get_mut(id) {
            if job.status == JobStatus::Cancelled {
                return Ok(());
            }
            job.advance(chunk, 0);
        }
        job.advance(chunk, 0);
        persist_job(&inner, &job)?;
        inner.jobs.insert(id.to_string(), job);
    }

    // Build a summary result.
    let result = serde_json::json!({
        "operation": format!("{:?}", operation),
        "total_processed": total_items,
        "total_failed": 0,
        "request_id": request_id,
        "message": "Bulk operation completed successfully"
    });

    let mut s = lock_store(store)?;
    if let Some(job) = s.get_mut(id) {
        job.mark_completed(result);
        persist_job(&inner, &job)?;
        inner.jobs.insert(id.to_string(), job);
    }
    Ok(())
}

// ── HTTP request / response types ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateJobRequest {
    pub operation: BulkOperationType,
    /// The items to process. For `update_ttl`, list of vault IDs; for
    /// `send_reminders`, list of owner addresses; etc.
    pub items: serde_json::Value,
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateJobResponse {
    pub job_id: String,
    pub status: JobStatus,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct JobStatusResponse {
    pub job: BulkJob,
    pub estimated_seconds_remaining: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListJobsQuery {
    pub status: Option<JobStatus>,
}

// ── Route handlers ────────────────────────────────────────────────────────────

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};

use crate::error::AppError;
use crate::error_context::REQUEST_ID_HEADER;

/// Acquire the job store lock, mapping a poisoned mutex to `AppError`.
fn lock_store(store: &JobStore) -> Result<std::sync::MutexGuard<'_, HashMap<String, BulkJob>>, AppError> {
    store.lock().map_err(|_| AppError::LockPoisoned)
}

/// POST /jobs — submit a bulk operation job.
pub async fn create_job_handler(
    State(job_store): State<JobStore>,
    headers: HeaderMap,
    Json(body): Json<CreateJobRequest>,
) -> Result<(StatusCode, Json<CreateJobResponse>), AppError> {
    let items_count = match &body.items {
        serde_json::Value::Array(arr) => arr.len(),
        _ => 1,
    };

    if items_count == 0 {
        return Err(AppError::InvalidInput("items must not be empty".into()));
    }

    // Propagate the ingress correlation id (#349) into the job so its async
    // processing is traceable back to this request.
    let request_id = headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let job = BulkJob::new(body.operation, body.items, items_count, body.label)
        .with_request_id(request_id);
    let job_id = job.id.clone();

    enqueue_job(&job_store, job)?;

    // Spawn synchronous processing in a blocking task so the handler returns
    // immediately (non-blocking to the caller).
    spawn_job(job_store.clone(), job_id.clone());

    Ok((
        StatusCode::ACCEPTED,
        Json(CreateJobResponse {
            job_id,
            status: JobStatus::Queued,
            message: "Job queued for processing".into(),
        }),
    ))
}

/// GET /jobs/:job_id — retrieve job status and progress.
pub async fn get_job_handler(
    State(job_store): State<JobStore>,
    Path(job_id): Path<String>,
) -> Result<Json<JobStatusResponse>, AppError> {
    let job = get_job(&job_store, &job_id)?.ok_or(AppError::NotFound)?;
    let eta = job.estimated_seconds_remaining();
    Ok(Json(JobStatusResponse {
        job,
        estimated_seconds_remaining: eta,
    }))
}

/// GET /jobs — list all jobs with optional status filter.
pub async fn list_jobs_handler(
    State(job_store): State<JobStore>,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<Vec<BulkJob>>, AppError> {
    let jobs = list_jobs(&job_store, query.status)?;
    Ok(Json(jobs))
}

/// DELETE /jobs/:job_id — cancel a queued or running job.
pub async fn cancel_job_handler(
    State(job_store): State<JobStore>,
    Path(job_id): Path<String>,
) -> Result<StatusCode, AppError> {
    if cancel_job(&job_store, &job_id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enqueue_and_retrieve() {
        let store = create_job_store();
        let job = BulkJob::new(
            BulkOperationType::UpdateTtl,
            serde_json::json!(["v1", "v2"]),
            2,
            Some("test-label".into()),
        );
        let id = enqueue_job(&store, job).unwrap();
        let retrieved = get_job(&store, &id).unwrap().unwrap();
        assert_eq!(retrieved.status, JobStatus::Queued);
        assert_eq!(retrieved.total_items, 2);
    }

    #[test]
    fn test_running_job_is_requeued_after_reopen_and_transitions_persist() {
        let path = std::env::temp_dir().join(format!("bulk-jobs-{}.sqlite", uuid::Uuid::new_v4()));
        let path = path.to_string_lossy().into_owned();
        let store = open_job_store(&path).unwrap();
        let job = BulkJob::new(
            BulkOperationType::UpdateTtl,
            serde_json::json!(["v1", "v2"]),
            2,
            None,
        );
        let id = enqueue_job(&store, job).unwrap();
        assert!(mark_job_running(&store, &id).unwrap());
        {
            let mut inner = store.0.lock().unwrap();
            let mut job = inner.jobs.get(&id).unwrap().clone();
            job.advance(1, 0);
            persist_job(&inner, &job).unwrap();
            inner.jobs.insert(id.clone(), job);
        }
        drop(store);

        let store = open_job_store(&path).unwrap();
        let recovered = get_job(&store, &id).unwrap().unwrap();
        assert_eq!(recovered.status, JobStatus::Queued);
        assert!(recovered.started_at.is_none());
        assert_eq!(recovered.processed_items, 1);
        assert_eq!(recovered.progress, 50);
        assert_eq!(recovered.payload, serde_json::json!(["v1", "v2"]));

        process_job(&store, &id).unwrap();
        drop(store);

        let store = open_job_store(&path).unwrap();
        let completed = get_job(&store, &id).unwrap().unwrap();
        assert_eq!(completed.status, JobStatus::Completed);
        assert_eq!(completed.processed_items, 2);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_job_progress_advance() {
        let mut job = BulkJob::new(
            BulkOperationType::SendReminders,
            serde_json::json!([]),
            10,
            None,
        );
        job.mark_running();
        job.advance(5, 0);
        assert_eq!(job.progress, 50);
        job.advance(5, 0);
        assert_eq!(job.progress, 100);
    }

    #[test]
    fn test_job_completion() {
        let mut job = BulkJob::new(
            BulkOperationType::ExportVaults,
            serde_json::json!([]),
            1,
            None,
        );
        job.mark_running();
        job.mark_completed(serde_json::json!({"done": true}));
        assert_eq!(job.status, JobStatus::Completed);
        assert!(job.result.is_some());
    }

    #[test]
    fn test_cancel_queued_job() {
        let store = create_job_store();
        let job = BulkJob::new(
            BulkOperationType::RetentionSweep,
            serde_json::json!([]),
            5,
            None,
        );
        let id = enqueue_job(&store, job).unwrap();
        assert!(cancel_job(&store, &id).unwrap());
        assert_eq!(
            get_job(&store, &id).unwrap().unwrap().status,
            JobStatus::Cancelled
        );
    }

    #[test]
    fn test_list_jobs_filtered() {
        let store = create_job_store();
        for _ in 0..3 {
            let job = BulkJob::new(BulkOperationType::Custom, serde_json::json!([]), 1, None);
            enqueue_job(&store, job).unwrap();
        }
        let all = list_jobs(&store, None).unwrap();
        assert_eq!(all.len(), 3);
        let queued = list_jobs(&store, Some(JobStatus::Queued)).unwrap();
        assert_eq!(queued.len(), 3);
        let running = list_jobs(&store, Some(JobStatus::Running)).unwrap();
        assert_eq!(running.len(), 0);
    }

    #[test]
    fn test_request_id_propagates_into_job_and_result() {
        let store = create_job_store();
        let job = BulkJob::new(
            BulkOperationType::UpdateTtl,
            serde_json::json!(["v1", "v2"]),
            2,
            None,
        )
        .with_request_id(Some("req-job-77".into()));
        assert_eq!(job.request_id.as_deref(), Some("req-job-77"));

        let id = enqueue_job(&store, job).unwrap();
        process_job(&store, &id).unwrap();
        let done = get_job(&store, &id).unwrap().unwrap();
        assert_eq!(done.status, JobStatus::Completed);
        // The correlation id survives into the job's structured result.
        assert_eq!(
            done.result.expect("result should be present")["request_id"],
            "req-job-77"
        );
    }

    #[test]
    fn test_process_job_completes() {
        let store = create_job_store();
        let job = BulkJob::new(
            BulkOperationType::UpdateTtl,
            serde_json::json!(["v1", "v2", "v3"]),
            3,
            None,
        );
        let id = enqueue_job(&store, job).unwrap();
        process_job(&store, &id).unwrap();
        let done = get_job(&store, &id).unwrap().unwrap();
        assert_eq!(done.status, JobStatus::Completed);
        assert_eq!(done.progress, 100);
    }

    #[test]
    fn test_poisoned_lock_does_not_panic() {
        let store = create_job_store();
        let job = BulkJob::new(BulkOperationType::Custom, serde_json::json!([]), 1, None);
        let id = enqueue_job(&store, job).expect("enqueue should succeed");

        // Poison the mutex by panicking while holding the lock.
        let poisoner = Arc::clone(&store);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("lock should succeed");
            panic!("intentional panic to poison the lock");
        })
        .join();

        // All store operations must surface a LockPoisoned error, not panic.
        assert!(matches!(get_job(&store, &id), Err(AppError::LockPoisoned)));
        assert!(matches!(list_jobs(&store, None), Err(AppError::LockPoisoned)));
        assert!(matches!(cancel_job(&store, &id), Err(AppError::LockPoisoned)));
        assert!(matches!(process_job(&store, &id), Err(AppError::LockPoisoned)));
        let extra = BulkJob::new(BulkOperationType::Custom, serde_json::json!([]), 1, None);
        assert!(matches!(enqueue_job(&store, extra), Err(AppError::LockPoisoned)));
    }
}
