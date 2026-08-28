//! A syzkaller campaign's kernel crashes reach triage.
//!
//! Before this path existed, a campaign minted a local run id, persisted
//! nothing, and copied its evidence into a tree triage never reads -- so kernel
//! bugs were found and then lost.

mod common;

use std::path::Path;
use std::sync::Arc;

use hf_service::ServiceContainer;

const KASAN_REPORT: &str = "\
BUG: KASAN: slab-out-of-bounds in ext4_xattr_set_entry+0x1234/0x1500 fs/ext4/xattr.c:1650
Read of size 4 at addr ffff88810a3b2c84 by task syz-executor.0/1234
Call Trace:
 dump_stack_lvl+0x8d/0xcf lib/dump_stack.c:106
 kasan_report+0x8a/0xb0 mm/kasan/report.c:495
 ext4_xattr_set_entry+0x1234/0x1500 fs/ext4/xattr.c:1650
 ext4_xattr_block_set+0x2a1/0x900 fs/ext4/xattr.c:1990
";

const WARNING_REPORT: &str = "\
WARNING: CPU: 0 PID: 12 at fs/ext4/inode.c:99 ext4_write_inode+0x1/0x2
Call Trace:
 ext4_write_inode+0x1/0x2 fs/ext4/inode.c:99
 write_inode fs/fs-writeback.c:1503 [inline]
";

/// Stage a finished campaign's retained evidence the way `run_syzkaller` now
/// leaves it: under the run-owned output directory of the kernel workspace.
fn stage_kernel_evidence(workspace: &Path, run_id: uuid::Uuid) {
    let crashes = workspace
        .join("runs")
        .join(run_id.to_string())
        .join("out")
        .join("crashes");

    let kasan = crashes.join("0123abcd");
    std::fs::create_dir_all(&kasan).unwrap();
    std::fs::write(
        kasan.join("description"),
        "KASAN: slab-out-of-bounds Read in ext4_xattr_set_entry",
    )
    .unwrap();
    std::fs::write(kasan.join("report0"), KASAN_REPORT).unwrap();
    std::fs::write(kasan.join("repro.prog"), b"syscall-sequence").unwrap();

    let warning = crashes.join("beef0001");
    std::fs::create_dir_all(&warning).unwrap();
    std::fs::write(warning.join("description"), "WARNING in ext4_write_inode").unwrap();
    std::fs::write(warning.join("report0"), WARNING_REPORT).unwrap();
}

#[tokio::test]
async fn a_kernel_campaigns_crashes_are_triaged_and_persisted() {
    common::install_managed_workspace("oxfuzz_syzkaller_triage_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("kernel_project");
    std::fs::create_dir_all(&project).unwrap();
    let project = std::fs::canonicalize(&project).unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("syz.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(Arc::new(hf_runtime::adapter::StubRuntime), None)
        .with_store(Arc::clone(&store));

    // A campaign that has already run: the record `run_syzkaller` persists,
    // with no harness_rev and no binary_rev because a kernel campaign has
    // neither.
    let target = "kernel-bzImage";
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy().to_string(),
        hf_core::engine::EngineKind::Syzkaller,
        None,
        chrono::Utc::now(),
    );
    run.status = hf_storage::RunStatus::Done;
    run.evidence_dir = Some(format!("runs/{}/out", run.id));
    store.insert_run(&run).await.unwrap();

    let workspace = hf_service::workspace_dir(&project, target);
    stage_kernel_evidence(&workspace, run.id);

    let crashes = container
        .triage_run(&project, target, run.id)
        .await
        .expect("a kernel run triages without a harness binary");

    assert_eq!(crashes.len(), 2, "one crash per retained report directory");
    for crash in &crashes {
        assert_eq!(crash.kind, hf_core::crash::CrashKind::KernelBug);
        assert!(
            !crash.stack_signature.is_empty(),
            "kernel crashes must dedup by their call trace"
        );
        assert_eq!(crash.run_id, run.id);
        assert!(!crash.minimized);
    }
    assert_ne!(
        crashes[0].stack_signature, crashes[1].stack_signature,
        "a KASAN fault and a WARN_ON are different bugs"
    );

    let persisted = store.list_crashes_by_run(run.id).await.unwrap();
    assert_eq!(persisted.len(), 2, "kernel crashes reach storage");

    // Re-triage is idempotent, exactly as it is for a userspace run.
    let again = container
        .triage_run(&project, target, run.id)
        .await
        .unwrap();
    assert_eq!(again.len(), 2);
    assert_eq!(store.list_crashes_by_run(run.id).await.unwrap().len(), 2);

    std::fs::remove_dir_all(&workspace).ok();
}

/// A kernel run's target is proven by where its evidence lives, so naming
/// another kernel must not triage this one's crashes.
#[tokio::test]
async fn a_kernel_run_is_not_triaged_under_another_kernel_label() {
    common::install_managed_workspace("oxfuzz_syzkaller_target_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("kernel_project_b");
    std::fs::create_dir_all(&project).unwrap();
    let project = std::fs::canonicalize(&project).unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("syz_b.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(Arc::new(hf_runtime::adapter::StubRuntime), None)
        .with_store(Arc::clone(&store));

    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy().to_string(),
        hf_core::engine::EngineKind::Syzkaller,
        None,
        chrono::Utc::now(),
    );
    run.status = hf_storage::RunStatus::Done;
    run.evidence_dir = Some(format!("runs/{}/out", run.id));
    store.insert_run(&run).await.unwrap();

    let workspace = hf_service::workspace_dir(&project, "kernel-bzImage");
    stage_kernel_evidence(&workspace, run.id);

    let wrong = container.triage_run(&project, "kernel-other", run.id).await;
    let message = wrong.expect_err("must be refused").to_string();
    assert!(
        message.contains("does not own terminal evidence"),
        "must be refused by the ownership check, not incidentally: {message}"
    );

    std::fs::remove_dir_all(&workspace).ok();
}
