//! Complete, bounded file capture for campaign execution and replay.

use std::path::{Path, PathBuf};

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_FILES: usize = 100_000;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
const MANIFEST: &str = "execution-inputs.json";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: PathBuf,
    directory: bool,
    mode: u32,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    image: String,
    config: serde_json::Value,
    argv: Vec<String>,
    entries: Vec<Entry>,
}

fn invalid(error: impl std::fmt::Display) -> ClassifiedError {
    ClassifiedError::Validation(format!("retained execution inputs: {error}"))
}

fn mode(metadata: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        u32::from(metadata.permissions().readonly())
    }
}

fn entries(root: &Path, skipped: &[&str]) -> Result<Vec<Entry>, ClassifiedError> {
    let mut result = Vec::new();
    let mut remaining = MAX_BYTES;
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        walk(
            root,
            &directory,
            skipped,
            &mut remaining,
            &mut result,
            &mut pending,
        )?;
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

fn walk(
    root: &Path,
    directory: &Path,
    skipped: &[&str],
    remaining: &mut u64,
    result: &mut Vec<Entry>,
    pending: &mut Vec<PathBuf>,
) -> Result<(), ClassifiedError> {
    use std::io::Read as _;

    if !std::fs::symlink_metadata(directory)
        .map_err(invalid)?
        .is_dir()
    {
        return Err(invalid("input directory is missing or is a symlink"));
    }
    let mut children = std::fs::read_dir(directory)
        .map_err(invalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let relative = path.strip_prefix(root).map_err(invalid)?.to_owned();
        if directory == root
            && relative
                .to_str()
                .is_some_and(|name| skipped.contains(&name))
        {
            continue;
        }
        if result.len() >= MAX_FILES {
            return Err(invalid("input file count exceeds 100000"));
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(invalid)?;
        let kind = metadata.file_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err(invalid(format!(
                "unsupported input file {}",
                relative.display()
            )));
        }
        let (bytes, sha256) = if kind.is_file() {
            if metadata.len() > *remaining {
                return Err(invalid("input files exceed 16 GiB"));
            }
            let file = std::fs::File::open(&path).map_err(invalid)?;
            let mut reader = file.take(*remaining + 1);
            let mut digest = Sha256::new();
            let mut bytes = 0;
            let mut buffer = [0_u8; 65536];
            loop {
                let count = reader.read(&mut buffer).map_err(invalid)?;
                if count == 0 {
                    break;
                }
                bytes += u64::try_from(count).map_err(invalid)?;
                if bytes > *remaining {
                    return Err(invalid("input files exceed 16 GiB"));
                }
                digest.update(&buffer[..count]);
            }
            *remaining -= bytes;
            (bytes, format!("{:x}", digest.finalize()))
        } else {
            (0, String::new())
        };
        result.push(Entry {
            path: relative,
            directory: kind.is_dir(),
            mode: mode(&metadata),
            bytes,
            sha256,
        });
        if kind.is_dir() {
            pending.push(path);
        }
    }
    Ok(())
}

fn copy(root: &Path, destination: &Path, files: &[Entry]) -> Result<(), ClassifiedError> {
    use std::io::Read as _;

    for entry in files {
        let source = root.join(&entry.path);
        let output = destination.join(&entry.path);
        if entry.directory {
            std::fs::create_dir(&output).map_err(invalid)?;
        } else {
            let mut input = std::fs::File::open(&source)
                .map_err(invalid)?
                .take(entry.bytes + 1);
            let mut writer = std::fs::File::create_new(&output).map_err(invalid)?;
            if std::io::copy(&mut input, &mut writer).map_err(invalid)? != entry.bytes {
                return Err(invalid("input file changed during capture"));
            }
        }
    }
    for entry in files.iter().rev() {
        std::fs::set_permissions(
            destination.join(&entry.path),
            std::fs::metadata(root.join(&entry.path))
                .map_err(invalid)?
                .permissions(),
        )
        .map_err(invalid)?;
    }
    Ok(())
}

/// Capture the complete engine-visible workspace, excluding runtime-owned output.
pub(super) fn capture_workspace(root: &Path, destination: &Path) -> Result<(), ClassifiedError> {
    let files = entries(root, &["runs", "corpus", "out"])?;
    std::fs::create_dir(destination).map_err(invalid)?;
    copy(root, destination, &files)?;
    if entries(destination, &[])? != files {
        return Err(invalid("workspace changed during capture"));
    }
    Ok(())
}

fn config_value(config: &FuzzRunConfig) -> Result<serde_json::Value, ClassifiedError> {
    let mut config = config.clone();
    config.input_manifest_sha256 = None;
    serde_json::to_value(config).map_err(invalid)
}

fn invocation(config: &FuzzRunConfig) -> Vec<String> {
    // Run-owned paths differ only by UUID. Bind adapter behavior with that component normalized.
    hf_engine::registry::adapter_for(config.engine).build_run_args(
        config,
        "/work/runs/<run>/input/harness",
        "/work/runs/<run>/corpus",
        "/work/runs/<run>/out",
    )
}

/// Persist the manifest before the run row containing its digest is inserted.
pub(super) fn seal(
    root: &Path,
    image: &str,
    config: &mut FuzzRunConfig,
) -> Result<(), ClassifiedError> {
    let manifest = Manifest {
        version: 1,
        image: image.to_owned(),
        config: config_value(config)?,
        argv: invocation(config),
        entries: entries(root, &[MANIFEST])?,
    };
    let bytes = serde_json::to_vec(&manifest).map_err(invalid)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid("manifest exceeds 32 MiB"));
    }
    std::fs::write(root.join(MANIFEST), &bytes).map_err(invalid)?;
    config.input_manifest_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
    Ok(())
}

/// Verify every input, including unexpected added files, against durable identity.
pub(super) fn verify(root: &Path, config: &FuzzRunConfig) -> Result<String, ClassifiedError> {
    use std::io::Read as _;

    let expected = config.input_manifest_sha256.as_deref().ok_or_else(|| {
        invalid("immutable replay is unavailable: this run has no input manifest")
    })?;
    let path = root.join(MANIFEST);
    if !std::fs::symlink_metadata(&path)
        .map_err(invalid)?
        .file_type()
        .is_file()
    {
        return Err(invalid("manifest is not a regular file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(invalid)?
        .take(u64::try_from(MAX_MANIFEST_BYTES).map_err(invalid)? + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    if bytes.len() > MAX_MANIFEST_BYTES || format!("{:x}", Sha256::digest(&bytes)) != expected {
        return Err(invalid("manifest digest mismatch"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(invalid)?;
    if manifest.version != 1
        || manifest.config != config_value(config)?
        || manifest.argv != invocation(config)
    {
        return Err(invalid("manifest version or run configuration mismatch"));
    }
    if entries(root, &[MANIFEST])? != manifest.entries {
        return Err(invalid("input files changed or are missing"));
    }
    Ok(manifest.image)
}

/// Copy verified historical inputs; callers seal the new run's configuration.
pub(super) fn copy_verified(
    root: &Path,
    destination: &Path,
    config: &FuzzRunConfig,
) -> Result<String, ClassifiedError> {
    let image = verify(root, config)?;
    let files = entries(root, &[MANIFEST])?;
    copy(root, destination, &files)?;
    if entries(destination, &[])? != files {
        return Err(invalid("historical inputs changed during copy"));
    }
    std::fs::copy(root.join(MANIFEST), destination.join(MANIFEST)).map_err(invalid)?;
    // Verify the copy against the durable digest, not another mutable directory scan.
    verify(destination, config)?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> FuzzRunConfig {
        serde_json::from_value(serde_json::json!({
            "harness_id": uuid::Uuid::nil(), "engine": "libfuzzer",
            "duration": {"secs": 1, "nanos": 0}, "max_mem_mb": 512, "max_cpus": 1,
            "seed_corpus": null, "sanitizer": "Address", "env": [], "extra_args": [], "seed": 1
        }))
        .unwrap()
    }

    #[test]
    fn manifest_binds_configuration_and_all_retained_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("dictionary"), "original").unwrap();
        let mut config = config();
        seal(root.path(), "image", &mut config).unwrap();
        assert_eq!(verify(root.path(), &config).unwrap(), "image");
        let mut changed = config.clone();
        changed.env.push(("EXTRA".to_owned(), "1".to_owned()));
        assert!(verify(root.path(), &changed).is_err());
        std::fs::write(root.path().join("dictionary"), "modified").unwrap();
        assert!(verify(root.path(), &config).is_err());
        std::fs::remove_file(root.path().join("dictionary")).unwrap();
        assert!(verify(root.path(), &config).is_err());
    }

    #[test]
    fn capture_preserves_reserved_named_project_files_but_excludes_run_outputs() {
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("runs")).unwrap();
        std::fs::write(root.path().join("runs/old"), "old run").unwrap();
        std::fs::write(root.path().join(MANIFEST), "project-owned file").unwrap();
        let destination = target.path().join("capture");
        capture_workspace(root.path(), &destination).unwrap();
        assert!(!destination.join("runs").exists());
        assert_eq!(
            std::fs::read_to_string(destination.join(MANIFEST)).unwrap(),
            "project-owned file"
        );
    }

    #[test]
    fn sparse_oversized_input_is_rejected_before_copy() {
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::File::create(root.path().join("oversized"))
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert!(capture_workspace(root.path(), &target.path().join("capture")).is_err());
        assert!(!target.path().join("capture").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_changed_executable_permissions_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), root.path().join("foreign")).unwrap();
        assert!(capture_workspace(root.path(), &target.path().join("capture")).is_err());
        std::fs::remove_file(root.path().join("foreign")).unwrap();
        let binary = root.path().join("binary");
        std::fs::write(&binary, "binary").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = config();
        seal(root.path(), "image", &mut config).unwrap();
        std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify(root.path(), &config).is_err());
    }
}
