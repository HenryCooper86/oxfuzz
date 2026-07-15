//! Filesystem-boundary tests for the Docker runtime.
//!
//! These never start Docker. They exercise host reads/writes and prove a
//! caller cannot escape the root that a `DockerRuntime` was approved to mount.

use std::sync::Arc;

use hf_core::runtime::{RuntimeAdapter, SandboxMount, SandboxOptions};
use hf_runtime::config::RuntimeConfig;
use hf_runtime::docker::DockerRuntime;

#[tokio::test]
async fn host_io_rejects_paths_outside_the_approved_workspace() {
    let temp = tempfile::tempdir().expect("temp root");
    let workspace = temp.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let outside = temp.path().join("outside.txt");
    std::fs::write(&outside, "secret").expect("outside fixture");
    let runtime: Arc<dyn RuntimeAdapter> =
        Arc::new(DockerRuntime::new(RuntimeConfig::default(), &workspace));

    assert!(
        runtime.read_file(&outside).await.is_err(),
        "the runtime read a host file outside its approved workspace"
    );
    let escaped_write = temp.path().join("escaped.txt");
    assert!(
        runtime.write_file(&escaped_write, "bad").await.is_err(),
        "the runtime wrote a host file outside its approved workspace"
    );
    assert!(!escaped_write.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn host_io_rejects_symlink_escape_from_the_workspace() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temp root");
    let workspace = temp.path().join("workspace");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&outside).expect("outside");
    symlink(&outside, workspace.join("escape")).expect("symlink fixture");
    let runtime: Arc<dyn RuntimeAdapter> =
        Arc::new(DockerRuntime::new(RuntimeConfig::default(), &workspace));

    let escaped_write = workspace.join("escape").join("owned.txt");
    assert!(runtime.write_file(&escaped_write, "bad").await.is_err());
    assert!(!outside.join("owned.txt").exists());

    let dangling_target = outside.join("created-through-link.txt");
    let dangling_link = workspace.join("dangling-file");
    symlink(&dangling_target, &dangling_link).expect("dangling symlink fixture");
    assert!(runtime.write_file(&dangling_link, "bad").await.is_err());
    assert!(!dangling_target.exists());
}

#[cfg(unix)]
#[test]
fn sandbox_mounts_reject_symlink_escape_from_the_workspace() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temp root");
    let workspace = temp.path().join("workspace");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, workspace.join("corpus")).unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), &workspace);
    let options = SandboxOptions {
        extra_mounts: vec![SandboxMount::writable(
            workspace.join("corpus"),
            "/work/corpus",
        )],
        ..SandboxOptions::default()
    };

    assert!(runtime.validate_sandbox_options(&options).is_err());
}

#[test]
fn sandbox_mounts_are_canonicalized_inside_the_workspace() {
    let temp = tempfile::tempdir().expect("temp root");
    let workspace = temp.path().join("workspace");
    let output = workspace.join("output");
    std::fs::create_dir_all(&output).unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), &workspace);
    let options = SandboxOptions {
        extra_mounts: vec![SandboxMount::writable(output.clone(), "/work/output")],
        ..SandboxOptions::default()
    };

    let validated = runtime.validate_sandbox_options(&options).unwrap();
    assert_eq!(
        validated.extra_mounts[0].host_path,
        output.canonicalize().unwrap()
    );
}

#[test]
fn sandbox_rejects_oversized_stdin_before_launch() {
    let temp = tempfile::tempdir().expect("temp root");
    let workspace = temp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), &workspace);
    let options = SandboxOptions {
        stdin: Some(vec![b'x'; 4 * 1024 * 1024 + 1]),
        ..SandboxOptions::default()
    };

    assert!(runtime.validate_sandbox_options(&options).is_err());
}

#[test]
fn sandbox_rejects_an_unsafe_image_override_before_launch() {
    let temp = tempfile::tempdir().expect("temp root");
    let workspace = temp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), &workspace);
    let options = SandboxOptions {
        image: Some("sidecar:2.7.0\n--privileged".to_owned()),
        ..SandboxOptions::default()
    };

    assert!(runtime.validate_sandbox_options(&options).is_err());
}
