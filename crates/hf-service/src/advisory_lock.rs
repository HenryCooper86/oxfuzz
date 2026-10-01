//! Shared advisory-lock teardown for service-owned leases.

use std::fs::File;

pub(crate) fn unlock_advisory_file(file: &File) {
    if let Err(error) = file.unlock() {
        // A destructor cannot return this error. The file still closes before
        // the process guard releases, retaining OS cleanup as a fallback.
        tracing::warn!(%error, "explicit advisory file unlock failed; falling back to close");
    }
}
