//! Causal event depth scoped to one scheduled workflow future.

tokio::task_local! {
    static CASCADE_DEPTH: u64;
}

/// Current scheduled event depth; interactive work starts at zero.
#[must_use]
pub fn current_cascade_depth() -> u64 {
    // An unset task-local denotes an interactive or timer root, which has no parent event.
    CASCADE_DEPTH.try_with(|depth| *depth).unwrap_or(0)
}

/// Restore causal depth while awaiting a workflow or a spawned service task.
pub async fn with_cascade_depth<F: std::future::Future>(depth: u64, future: F) -> F::Output {
    CASCADE_DEPTH.scope(depth, future).await
}
