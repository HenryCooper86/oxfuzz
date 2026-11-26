//! Disassembly around a binary-only finding's crash, for its explanation.
//!
//! The replay report names frames as module offsets (`/work/target+0xcbc`).
//! For the faulting frame and the first caller in the target, GNU `objdump`
//! from the sandbox image disassembles a small window of the session's own
//! copy of the binary. The binary is untrusted, so objdump runs in the
//! sandbox with the session directory read-only; the host only turns the
//! offset into an address (from the ELF program headers it already parses
//! for inspection) and renders the bounded text. The result is cached in the
//! session directory, so it is computed once and shown with the explanation.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandTermination, SandboxOptions};
use uuid::Uuid;

use super::binary_issue::finding_in_report;
use super::binary_only::{limits, MAX_BINARY_BYTES};
use super::binary_profile::load_base;
use super::ServiceContainer;

/// Bytes disassembled before and after each offset.
const WINDOW_BEFORE: u64 = 0x60;
const WINDOW_AFTER: u64 = 0x20;
/// Target frames disassembled: the faulting one and its first caller.
const MAX_FRAMES: usize = 2;
/// Instruction lines kept per window, and the largest output read.
const MAX_LINES: usize = 40;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const DISASSEMBLE_SECS: u64 = 60;
/// Where a finding's disassembly is cached in the session directory.
const DISASSEMBLY_DIR: &str = "disassembly";
/// What separates two windows in objdump's combined output.
const WINDOW_MARK: &str = "@@oxfuzz-window ";

/// Module offsets of the frames in the target, innermost first, unique, at
/// most [`MAX_FRAMES`].
fn target_offsets(frames: &[String]) -> Vec<u64> {
    let mut offsets = Vec::new();
    for frame in frames {
        let Some(start) = frame.find("/work/target+0x") else {
            continue;
        };
        let digits: String = frame[start + "/work/target+0x".len()..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        let Ok(offset) = u64::from_str_radix(&digits, 16) else {
            continue;
        };
        if !offsets.contains(&offset) {
            offsets.push(offset);
        }
        if offsets.len() == MAX_FRAMES {
            break;
        }
    }
    offsets
}

/// The shell script that disassembles each window. It is built from numbers
/// only, so nothing from the binary or its report reaches the shell.
fn disassembly_script(base: u64, offsets: &[u64]) -> String {
    let mut script = String::new();
    for offset in offsets {
        let address = base.saturating_add(*offset);
        let start = address.saturating_sub(WINDOW_BEFORE);
        let stop = address.saturating_add(WINDOW_AFTER);
        let _ = write!(
            script,
            "echo '{WINDOW_MARK}{offset:x}'; objdump -d --no-show-raw-insn \
             --start-address=0x{start:x} --stop-address=0x{stop:x} /work/target; "
        );
    }
    script
}

/// One instruction line of objdump's output: its address and its text.
fn instruction(line: &str) -> Option<(u64, String)> {
    let (address, rest) = line.trim_start().split_once(":\t")?;
    let address = u64::from_str_radix(address, 16).ok()?;
    let text = rest.split_whitespace().collect::<Vec<_>>().join(" ");
    (!text.is_empty()).then_some((address, text))
}

/// The windows of objdump's output as text for the explanation: a heading
/// per frame and its instructions, the faulting one marked `=>`.
fn render(base: u64, output: &str) -> Option<String> {
    let mut text = String::new();
    for (index, window) in output.split(WINDOW_MARK).skip(1).enumerate() {
        let mut lines = window.lines();
        let Some(offset) = lines
            .next()
            .and_then(|first| u64::from_str_radix(first.trim(), 16).ok())
        else {
            continue;
        };
        let fault = base.saturating_add(offset);
        let symbol = window
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_suffix(">:")
                    .and_then(|head| head.split_once(" <"))
            })
            .map(|(_, symbol)| format!(" (window starts in {symbol})"))
            .unwrap_or_default();
        // The faulting frame's address is the faulting instruction; a
        // caller's is its return address, the instruction after the call.
        let (heading, mark) = if index == 0 {
            ("faulting frame".to_owned(), "=>")
        } else {
            ("caller".to_owned(), "->")
        };
        let mut body = String::new();
        for (address, code) in lines.filter_map(instruction).take(MAX_LINES) {
            let marker = if address == fault { mark } else { "  " };
            let _ = writeln!(body, "{marker} {address:>8x}: {code}");
        }
        if !body.is_empty() {
            let note = if index == 0 {
                String::new()
            } else {
                format!(", return address marked {mark}")
            };
            let _ = writeln!(text, "{heading} at target+0x{offset:x}{note}{symbol}:");
            text.push_str(&body);
        }
    }
    (!text.is_empty()).then_some(text)
}

fn cache_path(workspace: &Path, finding_sha256: &str) -> PathBuf {
    workspace.join(DISASSEMBLY_DIR).join(format!(
        "{}.txt",
        &finding_sha256[..16.min(finding_sha256.len())]
    ))
}

/// A cached disassembly, when one was written and is a small regular file.
pub(super) fn cached_disassembly(workspace: &Path, finding_sha256: &str) -> Option<String> {
    let path = cache_path(workspace, finding_sha256);
    let metadata = path.symlink_metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_OUTPUT_BYTES as u64 {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

impl ServiceContainer {
    /// The disassembly around one finding's crash: computed in the sandbox
    /// once, then read from the session directory. `None` when the finding
    /// has no frame in the target or objdump produced nothing.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] when the session or finding
    /// does not exist, and sandbox errors when objdump cannot be started.
    pub async fn binary_finding_disassembly(
        &self,
        project: &Path,
        session: Uuid,
        finding: &str,
    ) -> Result<Option<String>, ClassifiedError> {
        let outcome = self.binary_session(project, session)?;
        let found = finding_in_report(&outcome, finding)?;
        let workspace = &outcome.workspace;
        if let Some(cached) = cached_disassembly(workspace, &found.sha256) {
            return Ok(Some(cached));
        }
        let offsets = target_offsets(&found.frames);
        if offsets.is_empty() {
            return Ok(None);
        }
        let target = workspace.join("target");
        let is_file = target
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= MAX_BINARY_BYTES);
        if !is_file {
            return Ok(None);
        }
        let image = std::fs::read(&target)
            .map_err(|error| ClassifiedError::Internal(format!("read session binary: {error}")))?;
        let base = load_base(&image)?;
        let result = self
            .runtime
            .run_command_opts(
                &[
                    "sh".to_owned(),
                    "-c".to_owned(),
                    disassembly_script(base, &offsets),
                ],
                workspace,
                &limits(DISASSEMBLE_SECS, HashMap::new()),
                &SandboxOptions {
                    workspace_read_only: true,
                    ..SandboxOptions::default()
                },
            )
            .await?;
        if result.termination != CommandTermination::Completed {
            return Ok(None);
        }
        let output: String = result.stdout.chars().take(MAX_OUTPUT_BYTES).collect();
        let Some(text) = render(base, &output) else {
            return Ok(None);
        };
        let directory = workspace.join(DISASSEMBLY_DIR);
        // A cache that cannot be written only means the next request
        // disassembles again; the text is still returned.
        if std::fs::create_dir_all(&directory).is_ok() {
            let _ = std::fs::write(cache_path(workspace, &found.sha256), &text);
        }
        Ok(Some(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PICINFO: &str = "\n/work/target:     file format elf64-littleaarch64\n\n\nDisassembly of section .text:\n\n\
0000000000000c80 <main+0x168>:\n c80:\tcmp\tw1, #0xfd\n c84:\tb.ls\tc90 <main+0x178>  // b.plast\n \
c88:\tmov\tx22, #0x0                   \t// #0\n cbc:\tldrb\tw2, [x22, x0]\n cc0:\tadrp\tx1, 0 <__abi_tag-0x278>\n";

    #[test]
    fn target_frames_are_read_innermost_first_and_bounded() {
        let frames = [
            "#0 0x5500000cbc (/work/target+0xcbc)",
            "#1 0x55018d84c4 (/lib/aarch64-linux-gnu/libc.so.6+0x284c4)",
            "#2 0x5500000a30 in main (/work/target+0xa30)",
            "#3 0x5500000cbc (/work/target+0xcbc)",
            "#4 0x5500000b00 (/work/target+0xb00)",
        ]
        .map(str::to_owned);
        assert_eq!(target_offsets(&frames), [0xcbc, 0xa30]);
        assert!(target_offsets(&["#0 0x1 (/lib/libc.so.6+0x10)".to_owned()]).is_empty());
        assert!(target_offsets(&["#0 (/work/target+0xzz)".to_owned()]).is_empty());
    }

    #[test]
    fn the_script_is_numbers_and_fixed_text_only() {
        let script = disassembly_script(0x40_0000, &[0xcbc, 0x10]);
        assert!(script.contains("--start-address=0x400c5c --stop-address=0x400cdc /work/target"));
        // A window near the start does not underflow.
        assert!(script.contains("--start-address=0x3fffb0"));
        assert!(script.contains("echo '@@oxfuzz-window cbc'"));
        assert_eq!(script.matches("objdump").count(), 2);
    }

    #[test]
    fn the_fault_is_marked_and_the_text_is_compact() {
        let output = format!("{WINDOW_MARK}cbc\n{PICINFO}");
        let text = render(0, &output).unwrap();
        assert!(text.starts_with("faulting frame at target+0xcbc (window starts in main+0x168):"));
        assert!(text.contains("=>      cbc: ldrb w2, [x22, x0]"), "{text}");
        assert!(text.contains("        c88: mov x22, #0x0 // #0"), "{text}");
        assert!(!text.contains("file format"));
        // A caller's address is its return address, marked differently.
        let both = format!("{WINDOW_MARK}cbc\n{PICINFO}{WINDOW_MARK}c88\n{PICINFO}");
        let text = render(0, &both).unwrap();
        assert!(
            text.contains("caller at target+0xc88, return address marked ->"),
            "{text}"
        );
        assert!(text.contains("->      c88: mov x22"), "{text}");
        assert_eq!(text.matches("=>").count(), 1, "{text}");
        assert_eq!(render(0, "objdump: error"), None);
        assert_eq!(render(0, &format!("{WINDOW_MARK}zz\n{PICINFO}")), None);
    }

    #[test]
    fn a_window_keeps_at_most_forty_instructions() {
        let mut output = format!("{WINDOW_MARK}0\n");
        for address in 0..100 {
            let _ = writeln!(output, " {address:x}:\tnop");
        }
        assert_eq!(render(0, &output).unwrap().lines().count(), MAX_LINES + 1);
    }

    /// objdump in the sandbox disassembles a real finding's crash site, and
    /// the second request reads the cache. Needs `HF_WORKSPACE_DIR` holding a
    /// session of `OXFUZZ_LIVE_PROJECT` with a finding that has frames.
    #[tokio::test]
    #[ignore = "requires a local Docker daemon, the pinned sandbox image and a recorded session"]
    async fn live_objdump_disassembles_a_findings_crash_site_in_the_sandbox() {
        assert!(hf_runtime::docker_daemon_ready());
        // The runtime mounts only directories under its root: the workspace.
        let workspace = PathBuf::from(std::env::var("HF_WORKSPACE_DIR").unwrap());
        let runtime = hf_runtime::docker::DockerRuntime::new(
            hf_runtime::RuntimeConfig::default(),
            &workspace,
        );
        let container = ServiceContainer::new(std::sync::Arc::new(runtime), None);
        let project = PathBuf::from(std::env::var("OXFUZZ_LIVE_PROJECT").unwrap());
        let session = container
            .binary_sessions(&project)
            .unwrap()
            .into_iter()
            .find(|session| session.findings > 0)
            .expect("a session with a finding");
        let outcome = container.binary_session(&project, session.session).unwrap();
        let finding = &outcome.findings[0].sha256;
        let cache = cache_path(&outcome.workspace, finding);
        let _ = std::fs::remove_file(&cache);
        let text = container
            .binary_finding_disassembly(&project, session.session, finding)
            .await
            .unwrap()
            .expect("disassembly");
        println!("{text}");
        assert!(text.starts_with("faulting frame at target+0x"), "{text}");
        assert_eq!(
            text.lines().filter(|line| line.starts_with("=>")).count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.lines().filter(|line| line.starts_with("->")).count(),
            1,
            "{text}"
        );
        assert!(cache.is_file());
        let again = container
            .binary_finding_disassembly(&project, session.session, finding)
            .await
            .unwrap();
        assert_eq!(again.as_deref(), Some(text.as_str()));
    }

    #[test]
    fn a_cached_disassembly_is_read_only_from_a_small_regular_file() {
        let workspace = tempfile::tempdir().unwrap();
        let sha = "ab".repeat(32);
        assert_eq!(cached_disassembly(workspace.path(), &sha), None);
        std::fs::create_dir_all(workspace.path().join(DISASSEMBLY_DIR)).unwrap();
        std::fs::write(cache_path(workspace.path(), &sha), "=> cbc: ldrb").unwrap();
        assert_eq!(
            cached_disassembly(workspace.path(), &sha).as_deref(),
            Some("=> cbc: ldrb")
        );
        std::fs::write(
            cache_path(workspace.path(), &sha),
            "x".repeat(MAX_OUTPUT_BYTES + 1),
        )
        .unwrap();
        assert_eq!(cached_disassembly(workspace.path(), &sha), None);
    }
}
