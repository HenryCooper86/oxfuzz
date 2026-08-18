//! Overflow store for oversized tool and engine output.
//!
//! oxfuzz produces some of the largest tool output in the business: `ASan`
//! stack traces, AFL++ `fuzzer_stats` and plot data, `llvm-cov` reports, corpus
//! listings, syzkaller logs. Against a 4,000-token prompt budget
//! (`docs/design/agent-prompt-security-design.md` section 4) these either blow
//! the budget or get truncated with the interesting part thrown away.
//!
//! Spilling writes the artifact to disk and replaces it in the conversation
//! with a head/tail preview plus a locator. The full output survives as
//! retained evidence, and the model can be told where to look.
//!
//! Two properties are the actual craft, and both are tested:
//!
//! - The replacement is sized so that **preview plus notice stays within the
//!   cap**. A preview sized at the cap with a notice appended would make the
//!   result bigger than the input, which is the one thing this must never do.
//! - The store is hostile-input safe: a private root, a digest-keyed
//!   subdirectory, a random filename component, a sanitized suggested name, and
//!   exclusive owner-only creation so a planted symlink cannot redirect the
//!   write. This is `docs/standards/DEFENSIVE_PATTERNS.md` rule 6's spill
//!   clause, implemented rather than described.
//!
//! Callers treat a save failure as "keep the inline result": spilling is an
//! optimization, and turning a successful tool call into an error because its
//! transcript could not be written would be failing worse than not spilling.
//!
//! See `docs/design/deepseek-harness-study.md` item 1.3.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Why an artifact could not be spilled.
#[derive(Debug, Error)]
pub enum SpillError {
    /// The store could not be created or written.
    #[error("spill store io: {0}")]
    Io(#[from] io::Error),
}

/// A successfully spilled artifact.
#[derive(Debug, Clone)]
pub struct Spilled {
    /// Where the full artifact lives.
    pub locator: PathBuf,
    /// Size of the artifact in bytes.
    pub bytes: usize,
    /// Human-readable pointer, suitable for embedding in a notice.
    pub retrieval_hint: String,
}

/// A private on-disk store for spilled artifacts.
pub struct SpillStore {
    root: PathBuf,
}

impl SpillStore {
    /// Create (or adopt) a store rooted at `root`.
    ///
    /// # Errors
    /// Returns [`SpillError::Io`] if the root cannot be created.
    pub fn new(root: PathBuf) -> Result<Self, SpillError> {
        create_private_dir(&root)?;
        Ok(Self { root })
    }

    /// The store's root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write `content` to the store and return where it landed.
    ///
    /// `owner` scopes the artifact (a session or run id); it is hashed rather
    /// than spelled out, because the path may reach a log and the identifier
    /// may not be something to leak there. `suggested_name` is advisory: it is
    /// sanitized to a single path-free component, and a random prefix keeps two
    /// saves of the same name from colliding.
    ///
    /// # Errors
    /// Returns [`SpillError::Io`] if the artifact cannot be written.
    pub fn save_text(
        &self,
        owner: &str,
        suggested_name: &str,
        content: &str,
    ) -> Result<Spilled, SpillError> {
        let dir = self.root.join(format!("session-{}", digest_of(owner)));
        create_private_dir(&dir)?;

        let path = dir.join(format!(
            "{}-{}",
            Uuid::new_v4().simple(),
            safe_name(suggested_name)
        ));
        write_private_new(&path, content.as_bytes())?;

        Ok(Spilled {
            bytes: content.len(),
            retrieval_hint: format!("at {}", path.display()),
            locator: path,
        })
    }
}

/// The replacement for `content` when it exceeds `max_bytes`, or `None` when it
/// fits and should be left exactly as it is.
///
/// The result is guaranteed to be at most `max_bytes` long. That is the whole
/// contract: a caller replaces an oversized result with this and can be sure
/// the substitution did not cost more than the thing it replaced.
#[must_use]
pub fn preview_replacing(content: &str, max_bytes: usize, retrieval_hint: &str) -> Option<String> {
    if content.len() <= max_bytes {
        return None;
    }

    // The omitted count is bounded above by the whole input, so sizing the
    // notice with that figure can only over-reserve, never overflow.
    let notice = format!(
        "\n[... {} bytes omitted; full output {retrieval_hint} ...]\n",
        content.len()
    );

    // A budget too small to hold the notice cannot describe itself; truncate
    // rather than return something longer than asked for.
    let Some(budget) = max_bytes.checked_sub(notice.len()) else {
        return Some(head_within(content, max_bytes).to_owned());
    };

    let head = head_within(content, budget / 2);
    let tail = tail_within(content, budget - budget / 2);
    Some(format!("{head}{notice}{tail}"))
}

/// The longest prefix of `s` that fits `max` bytes without splitting a
/// character.
fn head_within(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The longest suffix of `s` that fits `max` bytes without splitting a
/// character.
fn tail_within(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// A short stable digest of `owner`, safe to use as a directory name.
fn digest_of(owner: &str) -> String {
    let digest = Sha256::digest(owner.as_bytes());
    digest.iter().take(8).fold(String::new(), |mut acc, byte| {
        use std::fmt::Write;
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

/// `suggested_name` reduced to one harmless path component.
///
/// Separators, parent references, and anything outside a conservative set are
/// dropped rather than escaped, because the name is advisory: it exists to make
/// a directory listing readable, not to round-trip.
fn safe_name(suggested_name: &str) -> String {
    let cleaned: String = suggested_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A name of dots would still be a parent reference after cleaning.
    let cleaned = cleaned.trim_matches('.').to_owned();
    if cleaned.is_empty() {
        "artifact".to_owned()
    } else {
        head_within(&cleaned, 64).to_owned()
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if path.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

/// Create `path` exclusively and write `bytes`.
///
/// `create_new` is the point: it fails if anything already exists at the path,
/// including a symbolic link, so a planted link cannot redirect the write
/// somewhere else.
#[cfg(unix)]
fn write_private_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, SpillStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SpillStore::new(dir.path().join("spill")).expect("store");
        (dir, store)
    }

    #[test]
    fn a_saved_artifact_is_readable_at_its_locator() {
        let (_dir, store) = store();
        let saved = store
            .save_text("session-1", "asan.txt", "boom")
            .expect("save");
        assert_eq!(std::fs::read_to_string(&saved.locator).unwrap(), "boom");
        assert_eq!(saved.bytes, 4);
    }

    #[test]
    fn two_saves_of_the_same_name_do_not_collide() {
        let (_dir, store) = store();
        let first = store.save_text("s", "fuzzer_stats", "a").expect("save");
        let second = store.save_text("s", "fuzzer_stats", "b").expect("save");
        assert_ne!(first.locator, second.locator);
        assert_eq!(std::fs::read_to_string(&first.locator).unwrap(), "a");
        assert_eq!(std::fs::read_to_string(&second.locator).unwrap(), "b");
    }

    #[test]
    fn an_owner_is_not_spelled_out_in_the_path() {
        // The session id is a secret-ish identifier and the path may appear in
        // logs, so the directory is keyed by its digest, not its text.
        let (_dir, store) = store();
        let saved = store
            .save_text("project-alpha-secret-id", "out.txt", "x")
            .expect("save");
        assert!(!saved
            .locator
            .to_string_lossy()
            .contains("project-alpha-secret-id"));
    }

    #[test]
    fn a_hostile_suggested_name_cannot_escape_the_store() {
        let (_dir, store) = store();
        let saved = store
            .save_text("s", "../../../../etc/passwd", "x")
            .expect("save");
        assert!(
            saved.locator.starts_with(store.root()),
            "spilled artifact escaped the store root: {:?}",
            saved.locator
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_root_and_the_artifact_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = store();
        let saved = store.save_text("s", "out.txt", "x").expect("save");
        let root_mode = std::fs::metadata(store.root())
            .unwrap()
            .permissions()
            .mode();
        let file_mode = std::fs::metadata(&saved.locator)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(root_mode & 0o777, 0o700, "spill root must be private");
        assert_eq!(file_mode & 0o777, 0o600, "spilled artifact must be private");
    }

    // -- preview sizing ----------------------------------------------------

    #[test]
    fn a_small_result_is_left_alone() {
        assert_eq!(preview_replacing("short", 100, "at /tmp/x"), None);
    }

    #[test]
    fn the_replacement_never_exceeds_the_cap() {
        // The whole point: spilling must not be able to *add* bytes. A notice
        // appended to a preview sized at the cap would do exactly that.
        let content = "x".repeat(10_000);
        for cap in [200_usize, 500, 1_000, 4_000] {
            let replacement =
                preview_replacing(&content, cap, "at /tmp/spill/abc").expect("capped");
            assert!(
                replacement.len() <= cap,
                "cap {cap} exceeded: replacement was {} bytes",
                replacement.len()
            );
        }
    }

    #[test]
    fn the_replacement_keeps_a_head_and_a_tail_and_names_the_locator() {
        let content = format!("HEAD{}TAIL", "x".repeat(5_000));
        let replacement = preview_replacing(&content, 400, "at /tmp/spill/abc").expect("capped");
        assert!(replacement.starts_with("HEAD"));
        assert!(replacement.trim_end().ends_with("TAIL"));
        assert!(replacement.contains("/tmp/spill/abc"));
    }

    #[test]
    fn a_cap_too_small_for_a_notice_still_respects_the_cap() {
        // Degenerate but reachable if a caller passes a tiny budget; it must
        // truncate rather than overflow or panic.
        let content = "x".repeat(1_000);
        let replacement = preview_replacing(&content, 20, "at /tmp/x").expect("capped");
        assert!(replacement.len() <= 20);
    }

    #[test]
    fn a_multibyte_result_is_previewed_on_character_boundaries() {
        let content = "\u{65e5}".repeat(5_000);
        let replacement = preview_replacing(&content, 300, "at /tmp/x").expect("capped");
        assert!(replacement.len() <= 300);
    }
}
