//! Safe staging and sandbox configuration for syzkaller campaigns.

use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::runtime::{SandboxMount, SandboxOptions};
use serde_json::{json, Map, Value};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const CONTAINER_INPUTS: &str = "/syzbench/inputs";
const CONTAINER_SCRATCH: &str = "/syzbench/scratch";
const CONTAINER_WORKDIR: &str = "/syzbench/workdir";
pub(crate) const CONTAINER_MANAGER_CONFIG: &str = "/syzbench/inputs/manager.cfg";
const MAX_MANAGER_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_KERNEL_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const MAX_SSH_KEY_BYTES: u64 = 1024 * 1024;
const MAX_ROOTFS_IMAGE_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_WRITABLE_GROWTH_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_WRITABLE_ENTRIES: usize = 100_000;
pub(crate) const MAX_VM_COUNT: u32 = 4;
/// RAM (MiB) reserved for `syz-manager` and the container userland before any
/// guest is provisioned. Kept out of the pool divided among VMs.
const SYZ_MANAGER_OVERHEAD_MB: u64 = 512;
/// Smallest RAM (MiB) a KCOV-instrumented guest is given. VM fan-out is reduced
/// until every VM receives at least this much within the container budget.
const SYZ_MIN_VM_MEM_MB: u64 = 1024;
/// Parallel test processes per VM. This is syzkaller's `procs`, which is the
/// in-guest concurrency and is independent of the number of VMs.
const SYZ_PROCS_PER_VM: u32 = 6;

/// Inputs needed to prepare one isolated syzkaller campaign.
pub(crate) struct SyzkallerStageRequest {
    pub workspace_root: PathBuf,
    pub run_id: Uuid,
    pub target_triple: String,
    pub manager_cfg: Option<PathBuf>,
    pub kernel_image: Option<PathBuf>,
    pub disk_image: Option<PathBuf>,
    pub ssh_key: Option<PathBuf>,
    pub vm_count: Option<u32>,
    pub use_kvm: bool,
    /// Container memory budget in MiB. VM count and per-VM RAM are derived from
    /// this so the campaign cannot be provisioned to exceed the sandbox cgroup.
    pub container_mem_mb: u64,
    /// Container CPU budget. The per-VM vCPU count is derived from it.
    pub max_cpus: u32,
}

/// VM fan-out sized to fit within a container memory and CPU budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CampaignResources {
    /// Number of fuzzing VMs that fit within the budget.
    count: u32,
    /// RAM (MiB) handed to each guest via qemu `-m`.
    vm_mem_mb: u64,
    /// vCPUs handed to each guest.
    vm_cpu: u32,
}

/// Size the VM fan-out so `count * vm_mem_mb + manager overhead` never exceeds
/// the container memory budget.
///
/// The container runs swap-less (Docker `--memory-swap` is pinned to
/// `--memory`), so over-provisioning VMs OOM-kills qemu and yields a campaign
/// that reports success with near-zero coverage. The requested fan-out is
/// reduced until every VM receives at least [`SYZ_MIN_VM_MEM_MB`]; if not even a
/// single guest fits after reserving [`SYZ_MANAGER_OVERHEAD_MB`], the campaign
/// is rejected loudly rather than launched into a guaranteed OOM.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when the budget cannot host one VM.
fn plan_campaign_resources(
    container_mem_mb: u64,
    max_cpus: u32,
    requested_count: Option<u32>,
) -> Result<CampaignResources, ClassifiedError> {
    let requested = requested_count.unwrap_or(2).clamp(1, MAX_VM_COUNT);
    let available = container_mem_mb
        .checked_sub(SYZ_MANAGER_OVERHEAD_MB)
        .filter(|available| *available >= SYZ_MIN_VM_MEM_MB)
        .ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "syzkaller needs at least {} MiB (>= {SYZ_MIN_VM_MEM_MB} MiB per VM plus \
                 {SYZ_MANAGER_OVERHEAD_MB} MiB manager overhead) but the sandbox memory budget \
                 is {container_mem_mb} MiB; raise fuzzing.sandbox.max_mem_mb",
                SYZ_MIN_VM_MEM_MB + SYZ_MANAGER_OVERHEAD_MB
            ))
        })?;
    let max_fit = u32::try_from(available / SYZ_MIN_VM_MEM_MB)
        .unwrap_or(MAX_VM_COUNT)
        .clamp(1, MAX_VM_COUNT);
    let count = requested.min(max_fit);
    // count <= floor(available / SYZ_MIN_VM_MEM_MB), so this share is always
    // at least SYZ_MIN_VM_MEM_MB and the total never exceeds `available`.
    let vm_mem_mb = available / u64::from(count);
    let vm_cpu = max_cpus.clamp(1, 2);
    Ok(CampaignResources {
        count,
        vm_mem_mb,
        vm_cpu,
    })
}

/// Service-owned files and mounts for one syzkaller campaign.
#[derive(Debug)]
pub(crate) struct SyzkallerStage {
    pub root: PathBuf,
    pub mounts: Vec<SandboxMount>,
    pub writable_roots: Vec<PathBuf>,
    pub writable_budget_bytes: u64,
    pub writable_budget_entries: usize,
}

impl Drop for SyzkallerStage {
    fn drop(&mut self) {
        remove_staging_directory(&self.root);
    }
}

/// Live aggregate-budget monitor for one campaign's writable trees.
pub(crate) struct WritableBudgetMonitor {
    stop: CancellationToken,
    handle: Option<tokio::task::JoinHandle<()>>,
    exceeded: Arc<AtomicBool>,
    roots: Vec<PathBuf>,
    max_bytes: u64,
    max_entries: usize,
}

impl WritableBudgetMonitor {
    /// Start polling the writable trees and cancel the run on a violation.
    pub(crate) fn start(stage: &SyzkallerStage, run_cancel: CancellationToken) -> Self {
        let stop = CancellationToken::new();
        let exceeded = Arc::new(AtomicBool::new(false));
        let roots = stage.writable_roots.clone();
        let max_bytes = stage.writable_budget_bytes;
        let max_entries = stage.writable_budget_entries;
        let task_stop = stop.clone();
        let task_exceeded = Arc::clone(&exceeded);
        let task_roots = roots.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
            loop {
                tokio::select! {
                    () = task_stop.cancelled() => return,
                    _ = interval.tick() => {
                        let check_roots = task_roots.clone();
                        // A join failure is treated as transient, not an
                        // overflow: only a proven `Exceeded` verdict tears the
                        // run down, so a flaky tick cannot kill a healthy campaign.
                        let scan = tokio::task::spawn_blocking(move || {
                            writable_trees_scan(
                                &check_roots,
                                max_bytes,
                                max_entries,
                            )
                        })
                        .await
                        .unwrap_or(WritableBudgetScan::Indeterminate);
                        if scan == WritableBudgetScan::Exceeded {
                            task_exceeded.store(true, Ordering::Release);
                            run_cancel.cancel();
                            return;
                        }
                    }
                }
            }
        });
        Self {
            stop,
            handle: Some(handle),
            exceeded,
            roots,
            max_bytes,
            max_entries,
        }
    }

    /// Stop polling and perform one final fail-closed scan.
    pub(crate) async fn finish(mut self) -> bool {
        self.stop.cancel();
        if let Some(handle) = self.handle.take() {
            if handle.await.is_err() {
                self.exceeded.store(true, Ordering::Release);
            }
        }
        let roots = self.roots.clone();
        let max_bytes = self.max_bytes;
        let max_entries = self.max_entries;
        let final_within = tokio::task::spawn_blocking(move || {
            writable_trees_within_budget(&roots, max_bytes, max_entries)
        })
        .await
        .unwrap_or(false);
        final_within && !self.exceeded.load(Ordering::Acquire)
    }
}

impl Drop for WritableBudgetMonitor {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Copy selected inputs, rewrite the manager config, and return managed mounts.
pub(crate) fn prepare_stage(
    request: &SyzkallerStageRequest,
) -> Result<SyzkallerStage, ClassifiedError> {
    match std::fs::symlink_metadata(&request.workspace_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(ClassifiedError::Validation(format!(
                "workspace root is not a regular directory: {}",
                request.workspace_root.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&request.workspace_root).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "create workspace root {}: {error}",
                    request.workspace_root.display()
                ))
            })?;
        }
        Err(error) => {
            return Err(input_error(
                "inspect",
                "workspace root",
                &request.workspace_root,
                &error,
            ));
        }
    }
    let approved_root = regular_directory(&request.workspace_root, "workspace root")?;
    let syzkaller_root = ensure_child_directory(&approved_root, "syzkaller", true)?;
    let stage_root = ensure_child_directory(&syzkaller_root, &request.run_id.to_string(), false)?;

    let rootfs_size = match prepare_stage_contents(&stage_root, request) {
        Ok(size) => size,
        Err(error) => {
            remove_staging_directory(&stage_root);
            return Err(error);
        }
    };
    let writable_budget_bytes = rootfs_size
        .checked_add(MAX_WRITABLE_GROWTH_BYTES)
        .ok_or_else(|| {
            ClassifiedError::Validation("syzkaller writable budget overflow".to_owned())
        })?;

    let inputs = stage_root.join("inputs");
    let scratch = stage_root.join("scratch");
    let workdir = stage_root.join("workdir");
    let writable_roots = vec![scratch.clone(), workdir.clone()];
    Ok(SyzkallerStage {
        root: stage_root,
        mounts: vec![
            SandboxMount::read_only(inputs, CONTAINER_INPUTS),
            SandboxMount::writable(scratch, CONTAINER_SCRATCH),
            SandboxMount::writable(workdir.clone(), CONTAINER_WORKDIR),
        ],
        writable_roots,
        writable_budget_bytes,
        writable_budget_entries: MAX_WRITABLE_ENTRIES,
    })
}

/// Build the least-privilege runtime profile for a prepared stage.
pub(crate) fn sandbox_options(
    stage: &SyzkallerStage,
    platform: &str,
    use_kvm: bool,
) -> SandboxOptions {
    SandboxOptions {
        extra_mounts: stage.mounts.clone(),
        image: None,
        platform: Some(platform.to_owned()),
        network_mode: hf_core::runtime::SandboxNetworkMode::None,
        workdir: Some("/syzbench".to_owned()),
        relax_hardening: false,
        capabilities: Vec::new(),
        stdin: None,
        devices: if use_kvm {
            vec!["/dev/kvm".to_owned()]
        } else {
            Vec::new()
        },
        workspace_read_only: true,
        max_file_size_bytes: Some(stage.writable_budget_bytes),
    }
}

fn prepare_stage_contents(
    stage_root: &Path,
    request: &SyzkallerStageRequest,
) -> Result<u64, ClassifiedError> {
    let inputs = ensure_child_directory(stage_root, "inputs", false)?;
    let scratch = ensure_child_directory(stage_root, "scratch", false)?;
    ensure_child_directory(stage_root, "workdir", false)?;

    let supplied = request
        .manager_cfg
        .as_deref()
        .map(read_manager_config)
        .transpose()?;
    let (mut config, config_directory) = match supplied {
        Some((value, path)) => (value, path.parent().map(Path::to_path_buf)),
        None => (synthesized_config(request), None),
    };

    if request.manager_cfg.is_some() && config.get("type").and_then(Value::as_str) != Some("qemu") {
        return Err(ClassifiedError::Validation(
            "manager.cfg must select the qemu VM backend".to_owned(),
        ));
    }

    let implicit_kernel = config.pointer("/vm/kernel").and_then(Value::as_str);
    let implicit_disk = config.get("image").and_then(Value::as_str);
    let implicit_key = config.get("sshkey").and_then(Value::as_str);
    let kernel = select_input(
        request.kernel_image.as_deref(),
        implicit_kernel,
        config_directory.as_deref(),
        "kernel image",
        true,
    )?
    .ok_or_else(|| ClassifiedError::Validation("kernel image is required".to_owned()))?;
    let disk = select_input(
        request.disk_image.as_deref(),
        implicit_disk,
        config_directory.as_deref(),
        "rootfs disk image",
        true,
    )?
    .ok_or_else(|| ClassifiedError::Validation("rootfs disk image is required".to_owned()))?;
    let key = select_input(
        request.ssh_key.as_deref(),
        implicit_key,
        config_directory.as_deref(),
        "SSH key",
        false,
    )?;

    copy_file(
        &kernel,
        &inputs.join("kernel"),
        true,
        "kernel image",
        MAX_KERNEL_IMAGE_BYTES,
    )?;
    let rootfs_size = copy_file(
        &disk,
        &scratch.join("rootfs.img"),
        false,
        "rootfs disk image",
        MAX_ROOTFS_IMAGE_BYTES,
    )?;
    if let Some(key_path) = key.as_deref() {
        copy_file(
            key_path,
            &inputs.join("id_rsa"),
            true,
            "SSH key",
            MAX_SSH_KEY_BYTES,
        )?;
    }

    rewrite_manager_config(&mut config, request, key.is_some())?;
    reject_unmanaged_paths(&config, "$")?;
    write_manager_config(&inputs.join("manager.cfg"), &config)?;
    Ok(rootfs_size)
}

/// Build the manager.cfg skeleton for a campaign without a supplied config.
///
/// VM sizing fields (`procs`, `vm.count`, `vm.mem`, `vm.cpu`) are intentionally
/// left to [`rewrite_manager_config`], which is the single place that derives
/// them from the container budget for both synthesized and supplied configs.
fn synthesized_config(request: &SyzkallerStageRequest) -> Value {
    let machine = if request.target_triple.ends_with("/arm64") {
        "virt"
    } else {
        "pc"
    };
    let accel = if request.use_kvm { "kvm" } else { "tcg" };
    let cpu = if request.use_kvm { "host" } else { "max" };
    json!({
        "target": request.target_triple,
        "http": "127.0.0.1:56741",
        "workdir": CONTAINER_WORKDIR,
        "image": format!("{CONTAINER_SCRATCH}/rootfs.img"),
        "syzkaller": "/opt/syzkaller",
        "type": "qemu",
        "vm": {
            "kernel": format!("{CONTAINER_INPUTS}/kernel"),
            "qemu_args": format!("-machine {machine},accel={accel} -cpu {cpu}")
        }
    })
}

/// Normalize a supplied `qemu_args` for a sandbox that cannot pass `/dev/kvm`
/// through: rewrite `accel=kvm` to `accel=tcg` and `-cpu host` to `-cpu max` so
/// qemu boots under emulation instead of failing to find KVM and reporting an
/// empty campaign as complete.
fn normalize_qemu_accel_for_tcg(args: &str) -> String {
    args.replace("accel=kvm", "accel=tcg")
        .replace("-cpu host", "-cpu max")
}

fn rewrite_manager_config(
    config: &mut Value,
    request: &SyzkallerStageRequest,
    has_key: bool,
) -> Result<(), ClassifiedError> {
    let inherited_count = config
        .pointer("/vm/count")
        .and_then(Value::as_u64)
        .and_then(|count| u32::try_from(count).ok());
    let resources = plan_campaign_resources(
        request.container_mem_mb,
        request.max_cpus,
        request.vm_count.or(inherited_count),
    )?;
    let root = config.as_object_mut().ok_or_else(|| {
        ClassifiedError::Validation("manager.cfg must contain a JSON object".to_owned())
    })?;
    root.insert("target".to_owned(), json!(request.target_triple));
    root.insert("type".to_owned(), json!("qemu"));
    root.insert("http".to_owned(), json!("127.0.0.1:56741"));
    root.insert("workdir".to_owned(), json!(CONTAINER_WORKDIR));
    root.insert(
        "image".to_owned(),
        json!(format!("{CONTAINER_SCRATCH}/rootfs.img")),
    );
    root.insert("syzkaller".to_owned(), json!("/opt/syzkaller"));
    if has_key {
        root.insert(
            "sshkey".to_owned(),
            json!(format!("{CONTAINER_INPUTS}/id_rsa")),
        );
    } else {
        root.remove("sshkey");
    }

    // `procs` is the in-guest parallel-test-process count, not the number of
    // VMs; set it to an independent, budget-agnostic default.
    root.insert("procs".to_owned(), json!(SYZ_PROCS_PER_VM));
    let vm = root
        .get_mut("vm")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ClassifiedError::Validation("manager.cfg must contain a vm object".to_owned())
        })?;
    vm.insert(
        "kernel".to_owned(),
        json!(format!("{CONTAINER_INPUTS}/kernel")),
    );
    vm.insert("count".to_owned(), json!(resources.count));
    // Size guests to fit the container budget so the swap-less cgroup cannot
    // OOM-kill qemu (which would report a coverage-less campaign as success).
    vm.insert("mem".to_owned(), json!(resources.vm_mem_mb));
    vm.insert("cpu".to_owned(), json!(resources.vm_cpu));
    // Reconcile a supplied config's acceleration with what the sandbox can
    // actually provide: without host KVM, `/dev/kvm` is not passed through, so
    // an `accel=kvm` guest would fail to boot and look like a completed but
    // empty run.
    if !request.use_kvm {
        let normalized = vm
            .get("qemu_args")
            .and_then(Value::as_str)
            .map(normalize_qemu_accel_for_tcg);
        if let Some(normalized) = normalized {
            vm.insert("qemu_args".to_owned(), json!(normalized));
        }
    }
    Ok(())
}

fn read_manager_config(path: &Path) -> Result<(Value, PathBuf), ClassifiedError> {
    let resolved = regular_file(path, "manager.cfg")?;
    let bytes = read_bounded_file(&resolved, "manager.cfg", MAX_MANAGER_CONFIG_BYTES)?;
    let value = serde_json::from_slice(&bytes).map_err(|error| {
        ClassifiedError::Validation(format!("parse manager.cfg as JSON: {error}"))
    })?;
    Ok((value, resolved))
}

fn select_input(
    explicit: Option<&Path>,
    implicit: Option<&str>,
    config_directory: Option<&Path>,
    label: &str,
    required: bool,
) -> Result<Option<PathBuf>, ClassifiedError> {
    if let Some(path) = explicit {
        return regular_file(path, label).map(Some);
    }
    let Some(path) = implicit else {
        if required {
            return Err(ClassifiedError::Validation(format!("{label} is required")));
        }
        return Ok(None);
    };
    let directory = config_directory.ok_or_else(|| {
        ClassifiedError::Validation(format!(
            "{label} must be selected when no manager.cfg is supplied"
        ))
    })?;
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        directory.join(path)
    };
    let resolved = regular_file(&candidate, label)?;
    if !resolved.starts_with(directory) {
        return Err(ClassifiedError::Validation(format!(
            "{label} resolves outside manager.cfg directory: {}",
            candidate.display()
        )));
    }
    Ok(Some(resolved))
}

fn copy_file(
    source: &Path,
    destination: &Path,
    read_only: bool,
    label: &str,
    max_bytes: u64,
) -> Result<u64, ClassifiedError> {
    let mut input =
        std::fs::File::open(source).map_err(|error| input_error("open", label, source, &error))?;
    let before = input
        .metadata()
        .map_err(|error| input_error("inspect open", label, source, &error))?;
    if !before.file_type().is_file() {
        return Err(ClassifiedError::Validation(format!(
            "{label} is not a regular non-symlink file: {}",
            source.display()
        )));
    }
    if before.len() > max_bytes {
        return Err(ClassifiedError::Validation(format!(
            "{label} exceeds the {max_bytes}-byte limit: {} bytes",
            before.len()
        )));
    }
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| input_error("create staged", label, destination, &error))?;
    let copy_result = (|| {
        let mut bounded = (&mut input).take(max_bytes.saturating_add(1));
        let copied = std::io::copy(&mut bounded, &mut output)
            .map_err(|error| input_error("copy", label, source, &error))?;
        output
            .flush()
            .map_err(|error| input_error("flush staged", label, destination, &error))?;
        let after = input
            .metadata()
            .map_err(|error| input_error("reinspect open", label, source, &error))?;
        let staged_len = output
            .metadata()
            .map_err(|error| input_error("inspect staged", label, destination, &error))?
            .len();
        if copied > max_bytes {
            return Err(ClassifiedError::Validation(format!(
                "{label} grew beyond the {max_bytes}-byte limit while staging"
            )));
        }
        if copied != before.len() || staged_len != copied || !same_file_snapshot(&before, &after) {
            return Err(ClassifiedError::Validation(format!(
                "{label} changed while it was being staged: {}",
                source.display()
            )));
        }
        set_staged_permissions(destination, read_only).map_err(|error| {
            input_error("set permissions on staged", label, destination, &error)
        })?;
        Ok(copied)
    })();
    if copy_result.is_err() {
        std::fs::remove_file(destination).ok();
    }
    copy_result
}

fn read_bounded_file(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>, ClassifiedError> {
    let mut file =
        std::fs::File::open(path).map_err(|error| input_error("open", label, path, &error))?;
    let before = file
        .metadata()
        .map_err(|error| input_error("inspect open", label, path, &error))?;
    if !before.file_type().is_file() || before.len() > max_bytes {
        return Err(ClassifiedError::Validation(format!(
            "{label} exceeds the {max_bytes}-byte limit or is not a regular file"
        )));
    }
    let capacity = usize::try_from(before.len()).map_err(|_| {
        ClassifiedError::Validation(format!("{label} length does not fit in memory"))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut bounded = (&mut file).take(max_bytes.saturating_add(1));
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| input_error("read", label, path, &error))?;
    let after = file
        .metadata()
        .map_err(|error| input_error("reinspect open", label, path, &error))?;
    if bytes.len() as u64 != before.len()
        || bytes.len() as u64 > max_bytes
        || !same_file_snapshot(&before, &after)
    {
        return Err(ClassifiedError::Validation(format!(
            "{label} changed or exceeded its limit while being read: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_snapshot(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.size() == after.size()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn write_manager_config(path: &Path, config: &Value) -> Result<(), ClassifiedError> {
    let bytes = serde_json::to_vec_pretty(config).map_err(|error| {
        ClassifiedError::Internal(format!("serialize staged manager.cfg: {error}"))
    })?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| input_error("create staged", "manager.cfg", path, &error))?;
    file.write_all(&bytes)
        .and_then(|()| file.flush())
        .map_err(|error| input_error("write staged", "manager.cfg", path, &error))?;
    set_staged_permissions(path, true)
        .map_err(|error| input_error("set permissions on staged", "manager.cfg", path, &error))
}

fn regular_file(path: &Path, label: &str) -> Result<PathBuf, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| input_error("inspect", label, path, &error))?;
    if !metadata.file_type().is_file() {
        return Err(ClassifiedError::Validation(format!(
            "{label} is not a regular non-symlink file: {}",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|error| input_error("resolve", label, path, &error))
}

fn regular_directory(path: &Path, label: &str) -> Result<PathBuf, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| input_error("inspect", label, path, &error))?;
    if !metadata.file_type().is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "{label} is not a regular directory: {}",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|error| input_error("resolve", label, path, &error))
}

fn ensure_child_directory(
    parent: &Path,
    name: &str,
    allow_existing: bool,
) -> Result<PathBuf, ClassifiedError> {
    if name.is_empty()
        || Path::new(name).is_absolute()
        || !Path::new(name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "unsafe staging directory name: {name}"
        )));
    }
    let canonical_parent = regular_directory(parent, "staging parent")?;
    let child = canonical_parent.join(name);
    match std::fs::symlink_metadata(&child) {
        Ok(metadata) if allow_existing && metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(ClassifiedError::Validation(format!(
                "staging directory already exists or is not a directory: {}",
                child.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&child).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "create staging directory {}: {error}",
                    child.display()
                ))
            })?;
        }
        Err(error) => {
            return Err(ClassifiedError::Validation(format!(
                "inspect staging directory {}: {error}",
                child.display()
            )));
        }
    }
    regular_directory(&child, "staging directory")
}

fn reject_unmanaged_paths(value: &Value, location: &str) -> Result<(), ClassifiedError> {
    match value {
        Value::String(text) => validate_config_string(text, location),
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_unmanaged_paths(value, &format!("{location}[{index}]"))?;
            }
            Ok(())
        }
        Value::Object(values) => validate_object_paths(values, location),
        _ => Ok(()),
    }
}

fn validate_object_paths(
    values: &Map<String, Value>,
    location: &str,
) -> Result<(), ClassifiedError> {
    for (name, value) in values {
        reject_unmanaged_paths(value, &format!("{location}.{name}"))?;
    }
    Ok(())
}

fn validate_config_string(text: &str, location: &str) -> Result<(), ClassifiedError> {
    for token in std::iter::once(text).chain(text.split_ascii_whitespace()) {
        let token = token.trim_matches(['\'', '"', ',', ';']);
        let path = Path::new(token);
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(ClassifiedError::Validation(format!(
                "manager.cfg contains an unmanaged path at {location}: {text}"
            )));
        }
        if path.is_absolute() && !is_managed_container_path(path) {
            return Err(ClassifiedError::Validation(format!(
                "manager.cfg contains an unmanaged path at {location}: {text}"
            )));
        }
    }
    Ok(())
}

fn is_managed_container_path(path: &Path) -> bool {
    let components_are_safe = path
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    components_are_safe
        && (path == Path::new("/opt/syzkaller")
            || path == Path::new(CONTAINER_INPUTS)
            || path.starts_with(CONTAINER_INPUTS)
            || path == Path::new(CONTAINER_SCRATCH)
            || path.starts_with(CONTAINER_SCRATCH)
            || path == Path::new(CONTAINER_WORKDIR)
            || path.starts_with(CONTAINER_WORKDIR))
}

/// Verdict of one writable-tree budget scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WritableBudgetScan {
    /// The trees are within their byte and entry budget.
    Within,
    /// A hard budget or structural violation was observed: an oversize tree,
    /// too many entries, a symlink, or a special file. The run must stop.
    Exceeded,
    /// A transient IO error (for example `EINTR`/`EMFILE`, or an entry that
    /// vanished mid-scan) prevented a complete measurement. This is not
    /// evidence of an overflow, so the caller should retry rather than kill a
    /// healthy campaign.
    Indeterminate,
}

/// Measure the aggregate logical size and entry count of writable campaign
/// trees without following symlinks or accepting special files.
///
/// Security and structural violations fail closed ([`WritableBudgetScan::Exceeded`]);
/// transient IO faults are reported as [`WritableBudgetScan::Indeterminate`] so
/// a single flaky `read_dir`/`metadata` tick does not tear down a healthy run.
pub(crate) fn writable_trees_scan(
    roots: &[PathBuf],
    max_bytes: u64,
    max_entries: usize,
) -> WritableBudgetScan {
    let mut pending: Vec<(PathBuf, bool)> =
        roots.iter().cloned().map(|root| (root, true)).collect();
    let mut total_bytes = 0_u64;
    let mut entries = 0usize;
    while let Some((directory, is_root)) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            // A subtree that vanished mid-scan only reduces usage; a missing
            // root cannot be measured, so defer to the next tick.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if is_root {
                    return WritableBudgetScan::Indeterminate;
                }
                continue;
            }
            Err(_) => return WritableBudgetScan::Indeterminate,
        };
        // A writable root that is not a directory is a structural violation.
        if !metadata.file_type().is_dir() {
            return WritableBudgetScan::Exceeded;
        }
        let children = match std::fs::read_dir(&directory) {
            Ok(children) => children,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if is_root {
                    return WritableBudgetScan::Indeterminate;
                }
                continue;
            }
            Err(_) => return WritableBudgetScan::Indeterminate,
        };
        for child in children {
            let child = match child {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return WritableBudgetScan::Indeterminate,
            };
            let Some(next_entries) = entries.checked_add(1) else {
                return WritableBudgetScan::Exceeded;
            };
            entries = next_entries;
            if entries > max_entries {
                return WritableBudgetScan::Exceeded;
            }
            let path = child.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                // A concurrent delete only reduces retained usage. The next
                // scan observes any replacement; other errors are transient.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return WritableBudgetScan::Indeterminate,
            };
            if metadata.file_type().is_dir() {
                pending.push((path, false));
            } else if metadata.file_type().is_file() {
                let Some(next_bytes) = total_bytes.checked_add(metadata.len()) else {
                    return WritableBudgetScan::Exceeded;
                };
                total_bytes = next_bytes;
                if total_bytes > max_bytes {
                    return WritableBudgetScan::Exceeded;
                }
            } else {
                // Symlink or special file: never allowed in a writable tree.
                return WritableBudgetScan::Exceeded;
            }
        }
    }
    WritableBudgetScan::Within
}

/// Fail-closed convenience wrapper over [`writable_trees_scan`]: only a proven
/// overflow or structural violation is treated as out of budget. A transient
/// IO fault is not, so a flaky final scan does not fail an otherwise clean run.
pub(crate) fn writable_trees_within_budget(
    roots: &[PathBuf],
    max_bytes: u64,
    max_entries: usize,
) -> bool {
    !matches!(
        writable_trees_scan(roots, max_bytes, max_entries),
        WritableBudgetScan::Exceeded
    )
}

/// Copy a finished campaign's crash reproducers and corpus database out of the
/// disposable staging workdir into a retained evidence directory that survives
/// the [`SyzkallerStage`] teardown.
///
/// Without this, `syz-manager`'s `workdir/crashes` and `workdir/corpus.db` are
/// deleted on drop, so found crashes never reach triage and the corpus never
/// persists across runs. Returns the destination when any evidence was copied.
///
/// The copy never follows symlinks and refuses special files, and is bounded by
/// the same size/entry ceilings as the live writable budget, so untrusted
/// campaign output cannot redirect writes outside `destination` or exhaust disk.
///
/// # Errors
/// Returns [`ClassifiedError`] if the destination cannot be created or a bounded
/// copy fails.
pub(crate) fn retain_campaign_evidence(
    stage_root: &Path,
    destination: &Path,
) -> Result<Option<PathBuf>, ClassifiedError> {
    let workdir = stage_root.join("workdir");
    let crashes_src = workdir.join("crashes");
    let corpus_src = workdir.join("corpus.db");
    let has_crashes = std::fs::symlink_metadata(&crashes_src)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false);
    let has_corpus = std::fs::symlink_metadata(&corpus_src)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false);
    if !has_crashes && !has_corpus {
        return Ok(None);
    }
    std::fs::create_dir_all(destination).map_err(|error| {
        ClassifiedError::Internal(format!(
            "create syzkaller evidence directory {}: {error}",
            destination.display()
        ))
    })?;
    if has_crashes {
        copy_tree_within_limits(
            &crashes_src,
            &destination.join("crashes"),
            MAX_WRITABLE_GROWTH_BYTES,
            MAX_WRITABLE_ENTRIES,
        )?;
    }
    if has_corpus {
        let metadata = std::fs::symlink_metadata(&corpus_src)
            .map_err(|error| input_error("inspect", "syzkaller corpus", &corpus_src, &error))?;
        if metadata.file_type().is_file() && metadata.len() <= MAX_WRITABLE_GROWTH_BYTES {
            std::fs::copy(&corpus_src, destination.join("corpus.db"))
                .map_err(|error| input_error("copy", "syzkaller corpus", &corpus_src, &error))?;
        }
    }
    Ok(Some(destination.to_path_buf()))
}

/// Recursively copy `src` into `dst`, skipping symlinks and special files and
/// bounding the aggregate byte and entry counts. Used to lift retained campaign
/// evidence out of the disposable staging area.
fn copy_tree_within_limits(
    src: &Path,
    dst: &Path,
    max_bytes: u64,
    max_entries: usize,
) -> Result<(), ClassifiedError> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    let mut copied_bytes = 0_u64;
    let mut copied_entries = 0usize;
    while let Some((from, to)) = stack.pop() {
        let metadata = std::fs::symlink_metadata(&from)
            .map_err(|error| input_error("inspect evidence", "syzkaller output", &from, &error))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            // Never follow a symlink out of the untrusted workdir.
            continue;
        }
        if file_type.is_dir() {
            std::fs::create_dir_all(&to).map_err(|error| {
                input_error("create evidence directory", "syzkaller output", &to, &error)
            })?;
            let children = std::fs::read_dir(&from)
                .map_err(|error| input_error("read evidence", "syzkaller output", &from, &error))?;
            for child in children {
                let child = child.map_err(|error| {
                    input_error("read evidence entry", "syzkaller output", &from, &error)
                })?;
                copied_entries = copied_entries
                    .checked_add(1)
                    .filter(|n| *n <= max_entries)
                    .ok_or_else(|| {
                        ClassifiedError::Validation(
                            "syzkaller evidence exceeds the retained entry budget".to_owned(),
                        )
                    })?;
                let name = child.file_name();
                stack.push((from.join(&name), to.join(&name)));
            }
        } else if file_type.is_file() {
            copied_bytes = copied_bytes
                .checked_add(metadata.len())
                .filter(|total| *total <= max_bytes)
                .ok_or_else(|| {
                    ClassifiedError::Validation(
                        "syzkaller evidence exceeds the retained size budget".to_owned(),
                    )
                })?;
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    input_error(
                        "create evidence directory",
                        "syzkaller output",
                        parent,
                        &error,
                    )
                })?;
            }
            std::fs::copy(&from, &to)
                .map_err(|error| input_error("copy evidence", "syzkaller output", &from, &error))?;
        }
        // Special files (sockets, fifos, devices) are silently skipped.
    }
    Ok(())
}

fn input_error(
    operation: &str,
    label: &str,
    path: &Path,
    error: &std::io::Error,
) -> ClassifiedError {
    ClassifiedError::Validation(format!("{operation} {label} {}: {error}", path.display()))
}

#[cfg(unix)]
fn set_staged_permissions(path: &Path, read_only: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if read_only { 0o400 } else { 0o600 }),
    )
}

#[cfg(not(unix))]
fn set_staged_permissions(path: &Path, read_only: bool) -> std::io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(read_only);
    std::fs::set_permissions(path, permissions)
}

fn remove_staging_directory(path: &Path) {
    #[cfg(not(unix))]
    if let Ok(entries) = std::fs::read_dir(path.join("inputs")) {
        for entry in entries.flatten() {
            if let Ok(mut permissions) = entry.metadata().map(|metadata| metadata.permissions()) {
                permissions.set_readonly(false);
                std::fs::set_permissions(entry.path(), permissions).ok();
            }
        }
    }
    // Remove immutable inputs first so a cleanup failure in tool-created
    // workdir content cannot strand the copied SSH key or manager config.
    for child in ["inputs", "scratch", "workdir"] {
        let child = path.join(child);
        if let Err(error) = std::fs::remove_dir_all(&child) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %child.display(),
                    "could not remove syzkaller staging content: {error}"
                );
            }
        }
    }
    if let Err(error) = std::fs::remove_dir(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                path = %path.display(),
                "could not remove syzkaller staging directory: {error}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::{json, Value};
    use uuid::Uuid;

    use super::{
        plan_campaign_resources, prepare_stage, retain_campaign_evidence, sandbox_options,
        writable_trees_scan, writable_trees_within_budget, SyzkallerStageRequest,
        WritableBudgetScan, MAX_SSH_KEY_BYTES, SYZ_MANAGER_OVERHEAD_MB, SYZ_MIN_VM_MEM_MB,
        SYZ_PROCS_PER_VM,
    };

    fn write_artifacts(directory: &Path) {
        std::fs::write(directory.join("kernel"), b"kernel-v1").unwrap();
        std::fs::write(directory.join("rootfs.img"), b"rootfs-v1").unwrap();
        std::fs::write(directory.join("id_rsa"), b"key-v1").unwrap();
    }

    fn supplied_config(directory: &Path, extra: Value) -> std::path::PathBuf {
        let mut config = json!({
            "target": "linux/amd64",
            "http": "0.0.0.0:56741",
            "workdir": "old-workdir",
            "image": "rootfs.img",
            "sshkey": "id_rsa",
            "syzkaller": "/untrusted/syzkaller",
            "type": "qemu",
            "vm": {
                "count": 1,
                "kernel": "kernel",
                "qemu_args": "-machine pc,accel=tcg -cpu max"
            }
        });
        let Value::Object(extra) = extra else {
            panic!("test config extension must be an object")
        };
        config.as_object_mut().unwrap().extend(extra);
        let path = directory.join("manager.cfg");
        std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        path
    }

    fn request(workspace: &Path, config: &Path) -> SyzkallerStageRequest {
        SyzkallerStageRequest {
            workspace_root: workspace.to_path_buf(),
            run_id: Uuid::new_v4(),
            target_triple: "linux/amd64".to_owned(),
            manager_cfg: Some(config.to_path_buf()),
            kernel_image: None,
            disk_image: None,
            ssh_key: None,
            vm_count: Some(1),
            use_kvm: false,
            container_mem_mb: 4096,
            max_cpus: 2,
        }
    }

    #[test]
    fn supplied_config_is_rewritten_to_staged_container_paths() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));

        let stage = prepare_stage(&request(workspace.path(), &config)).unwrap();
        let staged: Value =
            serde_json::from_slice(&std::fs::read(stage.root.join("inputs/manager.cfg")).unwrap())
                .unwrap();

        assert_eq!(staged["target"], "linux/amd64");
        assert_eq!(staged["http"], "127.0.0.1:56741");
        assert_eq!(staged["workdir"], "/syzbench/workdir");
        assert_eq!(staged["image"], "/syzbench/scratch/rootfs.img");
        assert_eq!(staged["sshkey"], "/syzbench/inputs/id_rsa");
        assert_eq!(staged["syzkaller"], "/opt/syzkaller");
        assert_eq!(staged["vm"]["kernel"], "/syzbench/inputs/kernel");
        let rendered = serde_json::to_string(&staged).unwrap();
        assert!(!rendered.contains(artifacts.path().to_string_lossy().as_ref()));

        assert_eq!(stage.mounts.len(), 3);
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        assert!(stage
            .mounts
            .iter()
            .all(|mount| mount.host_path.starts_with(&canonical_workspace)));
        assert!(stage.mounts[0].read_only);
        assert!(!stage.mounts[1].read_only);
        assert!(!stage.mounts[2].read_only);
    }

    #[test]
    fn supplied_config_vm_fanout_is_bounded() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(
            artifacts.path(),
            json!({
                "procs": 50_000,
                "vm": {
                    "count": 50_000,
                    "kernel": "kernel",
                    "qemu_args": "-machine pc,accel=tcg -cpu max"
                }
            }),
        );
        let mut stage_request = request(workspace.path(), &config);
        stage_request.vm_count = None;
        // Ample memory so the MAX_VM_COUNT clamp, not the budget, bounds fan-out.
        stage_request.container_mem_mb = 16_384;

        let stage = prepare_stage(&stage_request).unwrap();
        let staged: Value =
            serde_json::from_slice(&std::fs::read(stage.root.join("inputs/manager.cfg")).unwrap())
                .unwrap();

        assert_eq!(staged["vm"]["count"], 4);
        // procs is per-VM parallelism, independent of the VM count.
        assert_eq!(staged["procs"], SYZ_PROCS_PER_VM);
        assert_ne!(staged["procs"], staged["vm"]["count"]);
    }

    #[test]
    fn staged_rootfs_is_disposable_and_does_not_mutate_the_original() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));

        let stage = prepare_stage(&request(workspace.path(), &config)).unwrap();
        std::fs::write(stage.root.join("scratch/rootfs.img"), b"mutated").unwrap();

        assert_eq!(
            std::fs::read(artifacts.path().join("rootfs.img")).unwrap(),
            b"rootfs-v1"
        );
        let stage_root = stage.root.clone();
        drop(stage);
        assert!(!stage_root.exists());
    }

    #[test]
    fn explicit_external_artifacts_produce_a_managed_config() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let stage = prepare_stage(&SyzkallerStageRequest {
            workspace_root: workspace.path().to_path_buf(),
            run_id: Uuid::new_v4(),
            target_triple: "linux/arm64".to_owned(),
            manager_cfg: None,
            kernel_image: Some(artifacts.path().join("kernel")),
            disk_image: Some(artifacts.path().join("rootfs.img")),
            ssh_key: Some(artifacts.path().join("id_rsa")),
            vm_count: Some(2),
            use_kvm: false,
            container_mem_mb: 8192,
            max_cpus: 2,
        })
        .unwrap();
        let staged: Value =
            serde_json::from_slice(&std::fs::read(stage.root.join("inputs/manager.cfg")).unwrap())
                .unwrap();

        assert_eq!(staged["target"], "linux/arm64");
        assert_eq!(staged["http"], "127.0.0.1:56741");
        assert_eq!(staged["image"], "/syzbench/scratch/rootfs.img");
        assert_eq!(staged["vm"]["kernel"], "/syzbench/inputs/kernel");
        assert_eq!(staged["vm"]["count"], 2);
        assert_eq!(
            staged["vm"]["qemu_args"],
            "-machine virt,accel=tcg -cpu max"
        );
        assert!(!serde_json::to_string(&staged)
            .unwrap()
            .contains(artifacts.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn oversized_ssh_key_is_rejected_before_it_is_staged() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        std::fs::write(
            artifacts.path().join("id_rsa"),
            vec![0_u8; usize::try_from(MAX_SSH_KEY_BYTES + 1).unwrap()],
        )
        .unwrap();
        let config = supplied_config(artifacts.path(), json!({}));

        let error = prepare_stage(&request(workspace.path(), &config)).unwrap_err();

        assert!(error.to_string().contains("SSH key exceeds"));
        assert_eq!(
            std::fs::read_dir(workspace.path().join("syzkaller"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn implicit_config_artifact_cannot_escape_the_config_directory() {
        let workspace = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let artifacts = parent.path().join("artifacts");
        std::fs::create_dir(&artifacts).unwrap();
        write_artifacts(&artifacts);
        std::fs::write(parent.path().join("outside.img"), b"outside").unwrap();
        let config = supplied_config(&artifacts, json!({"image": "../outside.img"}));

        let error = prepare_stage(&request(workspace.path(), &config)).unwrap_err();
        assert!(error.to_string().contains("outside manager.cfg directory"));
    }

    #[test]
    fn supplied_config_rejects_unmanaged_absolute_paths() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(
            artifacts.path(),
            json!({"kernel_obj": "/private/kernel/build"}),
        );

        let error = prepare_stage(&request(workspace.path(), &config)).unwrap_err();
        assert!(error.to_string().contains("unmanaged path"));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_symlink_input_is_rejected() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));
        let linked_kernel = artifacts.path().join("linked-kernel");
        symlink(artifacts.path().join("kernel"), &linked_kernel).unwrap();
        let mut stage_request = request(workspace.path(), &config);
        stage_request.kernel_image = Some(linked_kernel);

        let error = prepare_stage(&stage_request).unwrap_err();
        assert!(error.to_string().contains("regular non-symlink file"));
    }

    #[cfg(unix)]
    #[test]
    fn staging_root_cannot_be_redirected_through_a_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let redirected = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));
        symlink(redirected.path(), workspace.path().join("syzkaller")).unwrap();

        let error = prepare_stage(&request(workspace.path(), &config)).unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read_dir(redirected.path()).unwrap().count(), 0);
    }

    #[test]
    fn sandbox_profile_keeps_hardening_and_only_writable_stage_mounts() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));
        let stage = prepare_stage(&request(workspace.path(), &config)).unwrap();

        let sandbox = sandbox_options(&stage, "linux/amd64", true);

        assert_eq!(
            sandbox.network_mode,
            hf_core::runtime::SandboxNetworkMode::None
        );
        assert!(!sandbox.relax_hardening);
        assert!(sandbox.workspace_read_only);
        assert_eq!(
            sandbox.max_file_size_bytes,
            Some(stage.writable_budget_bytes)
        );
        assert_eq!(sandbox.devices, ["/dev/kvm"]);
        assert_eq!(sandbox.workdir.as_deref(), Some("/syzbench"));
        assert!(sandbox.extra_mounts[0].read_only);
        assert!(sandbox.extra_mounts[1..]
            .iter()
            .all(|mount| !mount.read_only));

        let args = hf_runtime::docker::build_exec_args_with(
            &hf_runtime::RuntimeConfig::default(),
            &hf_core::runtime::ResourceLimits {
                max_mem_mb: 4096,
                max_cpus: 4,
                max_duration_secs: 90,
                env: std::collections::HashMap::new(),
                ptrace: false,
            },
            &["syz-manager".to_owned()],
            &sandbox,
        );
        let joined = args.join(" ");
        assert!(joined.contains("--network=none"), "{joined}");
        assert!(joined.contains("--cap-drop=ALL"), "{joined}");
        assert!(joined.contains("no-new-privileges"), "{joined}");
        assert!(joined.contains("--device=/dev/kvm"), "{joined}");
        assert!(
            joined.contains(&format!(
                "--ulimit=fsize={0}:{0}",
                stage.writable_budget_bytes
            )),
            "{joined}"
        );
        assert!(joined.contains("/work:ro"), "{joined}");
        assert!(
            joined.contains("target=/syzbench/inputs,readonly"),
            "{joined}"
        );
        assert!(joined.contains("target=/syzbench/scratch"), "{joined}");
        assert!(!joined.contains(artifacts.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn aggregate_writable_budget_fails_closed_on_growth_or_special_entries() {
        let scratch = tempfile::tempdir().unwrap();
        let workdir = tempfile::tempdir().unwrap();
        std::fs::write(scratch.path().join("rootfs.img"), b"1234").unwrap();
        std::fs::write(workdir.path().join("corpus"), b"56").unwrap();
        let roots = [scratch.path().to_path_buf(), workdir.path().to_path_buf()];

        assert!(writable_trees_within_budget(&roots, 6, 2));
        assert!(!writable_trees_within_budget(&roots, 5, 2));
        assert!(!writable_trees_within_budget(&roots, 6, 1));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            symlink("rootfs.img", scratch.path().join("link")).unwrap();
            assert!(!writable_trees_within_budget(&roots, 100, 10));
        }
    }

    #[tokio::test]
    async fn live_budget_monitor_cancels_a_growing_campaign() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));
        let mut stage = prepare_stage(&request(workspace.path(), &config)).unwrap();
        stage.writable_budget_bytes = std::fs::metadata(stage.root.join("scratch/rootfs.img"))
            .unwrap()
            .len();
        let cancel = tokio_util::sync::CancellationToken::new();
        let monitor = super::WritableBudgetMonitor::start(&stage, cancel.clone());

        std::fs::write(stage.root.join("workdir/growth"), b"x").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), cancel.cancelled())
            .await
            .expect("budget monitor did not cancel the campaign");

        assert!(!monitor.finish().await);
    }

    #[test]
    fn campaign_memory_fits_within_container_budget() {
        // A 2048 MiB swap-less container hosts exactly one guest after the
        // manager overhead; requesting two would OOM, so the count is reduced.
        let one = plan_campaign_resources(2048, 1, Some(2)).unwrap();
        assert_eq!(one.count, 1);
        assert!(one.vm_mem_mb >= SYZ_MIN_VM_MEM_MB);
        assert!(one.vm_mem_mb * u64::from(one.count) + SYZ_MANAGER_OVERHEAD_MB <= 2048);

        // A larger budget admits the requested fan-out and still fits.
        let three = plan_campaign_resources(6144, 2, Some(3)).unwrap();
        assert_eq!(three.count, 3);
        assert!(three.vm_mem_mb >= SYZ_MIN_VM_MEM_MB);
        assert!(three.vm_mem_mb * u64::from(three.count) + SYZ_MANAGER_OVERHEAD_MB <= 6144);

        // Too small to host even one guest fails loudly instead of OOM-as-success.
        let error = plan_campaign_resources(1024, 1, Some(1)).unwrap_err();
        assert!(
            error.to_string().contains("syzkaller needs at least"),
            "{error}"
        );
    }

    #[test]
    fn synthesized_config_memory_fits_a_small_budget() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let stage = prepare_stage(&SyzkallerStageRequest {
            workspace_root: workspace.path().to_path_buf(),
            run_id: Uuid::new_v4(),
            target_triple: "linux/amd64".to_owned(),
            manager_cfg: None,
            kernel_image: Some(artifacts.path().join("kernel")),
            disk_image: Some(artifacts.path().join("rootfs.img")),
            ssh_key: None,
            vm_count: Some(2),
            use_kvm: false,
            container_mem_mb: 2048,
            max_cpus: 1,
        })
        .unwrap();
        let staged: Value =
            serde_json::from_slice(&std::fs::read(stage.root.join("inputs/manager.cfg")).unwrap())
                .unwrap();

        let count = staged["vm"]["count"].as_u64().unwrap();
        let mem = staged["vm"]["mem"].as_u64().unwrap();
        assert_eq!(count, 1, "two guests would OOM a 2048 MiB swap-less cgroup");
        assert!(mem >= SYZ_MIN_VM_MEM_MB);
        assert!(mem * count + SYZ_MANAGER_OVERHEAD_MB <= 2048);
    }

    #[test]
    fn writable_scan_distinguishes_overflow_from_transient_gaps() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::write(scratch.path().join("rootfs.img"), b"1234").unwrap();
        let roots = [scratch.path().to_path_buf()];

        // A real oversize tree is a hard overflow.
        assert_eq!(
            writable_trees_scan(&roots, 3, 10),
            WritableBudgetScan::Exceeded
        );
        // Within budget.
        assert_eq!(
            writable_trees_scan(&roots, 10, 10),
            WritableBudgetScan::Within
        );

        // A vanished root cannot be measured and must be Indeterminate, never
        // Exceeded, so a transient gap does not kill a healthy campaign.
        let missing = scratch.path().join("does-not-exist");
        let missing_roots = [missing];
        assert_eq!(
            writable_trees_scan(&missing_roots, 10, 10),
            WritableBudgetScan::Indeterminate
        );
        // The fail-closed wrapper does not report a transient gap as overflow.
        assert!(writable_trees_within_budget(&missing_roots, 10, 10));
    }

    #[test]
    fn retained_evidence_copies_crashes_and_corpus_out_of_staging() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));
        let stage = prepare_stage(&request(workspace.path(), &config)).unwrap();

        // Simulate syz-manager output inside the disposable workdir.
        let crash_dir = stage.root.join("workdir/crashes/0123abcd");
        std::fs::create_dir_all(&crash_dir).unwrap();
        std::fs::write(crash_dir.join("repro.prog"), b"syscall-sequence").unwrap();
        std::fs::write(stage.root.join("workdir/corpus.db"), b"corpus-bytes").unwrap();

        let destination = workspace.path().join("evidence");
        let retained = retain_campaign_evidence(&stage.root, &destination)
            .unwrap()
            .expect("evidence should be retained");

        assert_eq!(retained, destination);
        assert_eq!(
            std::fs::read(destination.join("crashes/0123abcd/repro.prog")).unwrap(),
            b"syscall-sequence"
        );
        assert_eq!(
            std::fs::read(destination.join("corpus.db")).unwrap(),
            b"corpus-bytes"
        );

        // Evidence survives the staging teardown.
        let stage_root = stage.root.clone();
        drop(stage);
        assert!(!stage_root.exists());
        assert!(destination.join("crashes/0123abcd/repro.prog").exists());
    }

    #[test]
    fn retained_evidence_is_absent_when_no_output_exists() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(artifacts.path(), json!({}));
        let stage = prepare_stage(&request(workspace.path(), &config)).unwrap();

        let destination = workspace.path().join("evidence");
        assert!(retain_campaign_evidence(&stage.root, &destination)
            .unwrap()
            .is_none());
    }

    #[test]
    fn supplied_kvm_config_is_normalized_for_a_tcg_sandbox() {
        let workspace = tempfile::tempdir().unwrap();
        let artifacts = tempfile::tempdir().unwrap();
        write_artifacts(artifacts.path());
        let config = supplied_config(
            artifacts.path(),
            json!({
                "vm": {
                    "count": 2,
                    "kernel": "kernel",
                    "qemu_args": "-machine pc,accel=kvm -cpu host"
                }
            }),
        );
        let mut stage_request = request(workspace.path(), &config);
        stage_request.use_kvm = false;
        stage_request.vm_count = Some(2);
        stage_request.container_mem_mb = 8192;

        let stage = prepare_stage(&stage_request).unwrap();
        let staged: Value =
            serde_json::from_slice(&std::fs::read(stage.root.join("inputs/manager.cfg")).unwrap())
                .unwrap();

        // KVM acceleration is normalized to TCG since /dev/kvm is not provided.
        assert_eq!(staged["vm"]["qemu_args"], "-machine pc,accel=tcg -cpu max");
        // procs is set independently of the VM count.
        assert_eq!(staged["procs"], SYZ_PROCS_PER_VM);
        assert_ne!(staged["procs"], staged["vm"]["count"]);
    }
}
