//! Validation immediately before an upstream fuzzer loads a managed native plugin.

use hf_core::{
    engine::{EngineKind, FuzzRunConfig},
    error::ClassifiedError,
    runtime::SandboxOptions,
};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Component, Path};

/// Native AFL++ plugin location inside the sandbox.
pub const LIBRARY_ENV: &str = "AFL_CUSTOM_MUTATOR_LIBRARY";
/// Retained expected digest for the plugin bytes.
pub const DIGEST_ENV: &str = "OXFUZZ_MUTATOR_SHA256";
/// Immutable image used to compile and load the plugin.
pub const IMAGE_ENV: &str = "OXFUZZ_MUTATOR_IMAGE_ID";

fn invalid(message: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!("managed mutator: {message}"))
}

/// Check the actual runtime-bound file, not just presentation or service metadata.
pub fn validate(
    engine: EngineKind,
    config: &FuzzRunConfig,
    workspace: &Path,
    sandbox: &SandboxOptions,
) -> Result<(), ClassifiedError> {
    let keys = [
        LIBRARY_ENV,
        DIGEST_ENV,
        IMAGE_ENV,
        "AFL_CUSTOM_MUTATOR_ONLY",
        "AFL_PYTHON_MODULE",
    ];
    if !config
        .env
        .iter()
        .any(|(key, _)| keys.contains(&key.as_str()))
    {
        return Ok(());
    }
    if !cfg!(feature = "managed-mutators") {
        return Err(invalid("managed-mutators feature is disabled"));
    }
    if engine != EngineKind::AflPlusPlus
        || config.env.iter().any(|(key, _)| key == "AFL_PYTHON_MODULE")
    {
        return Err(invalid(
            "managed shared libraries support only the AFL++ native API",
        ));
    }
    let get = |key: &str| -> Result<&str, ClassifiedError> {
        let mut values = config
            .env
            .iter()
            .filter(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str());
        let value = values
            .next()
            .ok_or_else(|| invalid("plugin lacks retained digest/image evidence"))?;
        if values.next().is_some() {
            return Err(invalid("duplicate plugin environment setting"));
        }
        Ok(value)
    };
    let library = get(LIBRARY_ENV)?;
    let digest = get(DIGEST_ENV)?;
    let image = get(IMAGE_ENV)?;
    if sandbox.image.as_deref() != Some(image) || !sandbox.workspace_read_only {
        return Err(invalid(
            "plugin requires its compiled image and read-only workspace",
        ));
    }
    hf_core::runtime::ImmutableImageReference::from_sha256_id(image.to_owned())?;
    let relative = library
        .strip_prefix("/work/")
        .map(Path::new)
        .ok_or_else(|| invalid("plugin must be staged below /work"))?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(invalid("plugin path must contain only normal components"));
    }
    let mut host_root = workspace;
    let mut host_relative = relative;
    let mut selected_prefix = "/work".len();
    let mut destinations = std::collections::HashSet::new();
    destinations.insert(std::path::PathBuf::from("/work"));
    for mount in &sandbox.extra_mounts {
        if !destinations.insert(std::path::PathBuf::from(&mount.container_path)) {
            return Err(invalid("ambiguous duplicate sandbox mount destination"));
        }
        if let Ok(suffix) = Path::new(library).strip_prefix(&mount.container_path) {
            if mount.container_path.len() > selected_prefix {
                if !mount.read_only {
                    return Err(invalid("plugin is covered by a writable sandbox mount"));
                }
                selected_prefix = mount.container_path.len();
                host_root = &mount.host_path;
                host_relative = suffix;
            }
        }
    }
    let mut path = host_root.to_owned();
    for part in host_relative.components() {
        path.push(part.as_os_str());
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| invalid(&format!("inspect plugin: {error}")))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("plugin path contains a symlink"));
        }
    }
    let metadata =
        std::fs::metadata(&path).map_err(|error| invalid(&format!("inspect plugin: {error}")))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 * 1024 {
        return Err(invalid(
            "plugin must be a nonempty regular file at most 64 MiB",
        ));
    }
    let file =
        std::fs::File::open(&path).map_err(|error| invalid(&format!("open plugin: {error}")))?;
    let mut reader = file.take(64 * 1024 * 1024 + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(&format!("read plugin: {error}")))?;
    if bytes.len() > 64 * 1024 * 1024 || format!("{:x}", Sha256::digest(bytes)) != digest {
        return Err(invalid("plugin bytes differ from the retained artifact"));
    }
    Ok(())
}
