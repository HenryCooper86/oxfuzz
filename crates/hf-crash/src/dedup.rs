//! Deduplication of crashes: one finding per bug.
//!
//! The stack signature is the primary identity. Two more keys catch the same
//! bug under a different signature:
//!
//! - An unsymbolized crash line names the module by its full path
//!   (`/work/runs/<run>/input/harness+0x111dfc`), and that path differs per
//!   run; the module's base name and offset do not.
//! - When symbolization fails for some replays and not others, one report says
//!   `/work/utf8.c:31:27` and another `harness+0x111dfc` for the same faulting
//!   instruction. Replays run without ASLR, so the absolute addresses of the
//!   top frames still match; together with the sanitizer's class they identify
//!   the bug.

use hf_core::crash::Crash;

/// Deduplicate crashes, keeping one representative per bug.
///
/// The first crash of each bug is kept, except that a symbolized report
/// replaces an unsymbolized representative of the same bug, so the finding
/// that survives names a source line where one is known.
#[must_use]
pub fn dedup(crashes: Vec<Crash>) -> Vec<Crash> {
    let mut owner: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut result: Vec<Crash> = Vec::new();
    for crash in crashes {
        let keys = identity_keys(&crash);
        if keys.is_empty() {
            // No signature or stack (e.g. an AFL++ raw crash): keep all.
            result.push(crash);
            continue;
        }
        if let Some(&index) = keys.iter().find_map(|key| owner.get(key)) {
            if !is_symbolized(&result[index]) && is_symbolized(&crash) {
                for key in &keys {
                    owner.insert(key.clone(), index);
                }
                result[index] = crash;
            }
            continue;
        }
        for key in keys {
            owner.insert(key, result.len());
        }
        result.push(crash);
    }
    result
}

/// One key per crash, equal for crashes that are the same bug: the id of the
/// first crash of its bug, grouping transitively through
/// [`identity_keys`]. A crash with no identity is its own group.
#[must_use]
pub fn bug_keys(crashes: &[Crash]) -> Vec<String> {
    // Union-find over crash positions; identity keys connect positions.
    let mut parent: Vec<usize> = (0..crashes.len()).collect();
    let mut owner: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (index, crash) in crashes.iter().enumerate() {
        for key in identity_keys(crash) {
            match owner.get(&key) {
                Some(&other) => {
                    let (a, b) = (root(&mut parent, index), root(&mut parent, other));
                    // The earlier position stays the root, so the key is the
                    // first crash of the bug in input order.
                    let (keep, drop) = if a < b { (a, b) } else { (b, a) };
                    parent[drop] = keep;
                }
                None => {
                    owner.insert(key, index);
                }
            }
        }
    }
    (0..crashes.len())
        .map(|index| crashes[root(&mut parent, index)].id.to_string())
        .collect()
}

/// The union-find root of `index`, compressing the path on the way.
fn root(parent: &mut [usize], mut index: usize) -> usize {
    while parent[index] != index {
        parent[index] = parent[parent[index]];
        index = parent[index];
    }
    index
}

/// Every key under which `crash` is the same bug as another crash.
#[must_use]
pub fn identity_keys(crash: &Crash) -> Vec<String> {
    let mut keys = Vec::new();
    if !crash.stack_signature.is_empty() {
        keys.push(format!(
            "sig:{}",
            normalized_signature(&crash.stack_signature)
        ));
    }
    if let Some(casr) = &crash.casr {
        let addresses: Vec<&str> = casr
            .stack
            .iter()
            .filter_map(|frame| frame_address(frame))
            .take(2)
            .collect();
        if addresses.len() == 2 {
            keys.push(format!(
                "pc:{}/{}|{}",
                addresses[0], addresses[1], casr.severity_short
            ));
        }
    }
    keys
}

/// `<dir>/module+0xOFF` becomes `module+0xOFF`; any other signature is kept.
fn normalized_signature(signature: &str) -> &str {
    match signature.rsplit_once('/') {
        Some((_, tail)) if is_module_offset(tail) => tail,
        _ => signature,
    }
}

/// `harness+0x111dfc`: a module name, `+0x`, and hex digits.
fn is_module_offset(text: &str) -> bool {
    text.split_once("+0x").is_some_and(|(module, offset)| {
        !module.is_empty() && !offset.is_empty() && offset.chars().all(|c| c.is_ascii_hexdigit())
    })
}

/// The absolute address of a sanitizer frame line (`#0 0xaaaaaabb1dfc in ...`).
fn frame_address(frame: &str) -> Option<&str> {
    let mut fields = frame.split_whitespace();
    let index = fields.next()?;
    if !index.starts_with('#') {
        return None;
    }
    let address = fields.next()?;
    let digits = address.strip_prefix("0x")?;
    (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit())).then_some(address)
}

/// Whether the crash names a source location rather than a module offset.
fn is_symbolized(crash: &Crash) -> bool {
    let line = crash
        .casr
        .as_ref()
        .map_or(crash.stack_signature.as_str(), |casr| {
            casr.crashline.as_str()
        });
    !line.is_empty() && !is_module_offset(line.rsplit('/').next().unwrap_or(line))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use hf_core::crash::{CasrReport, Crash, CrashKind, CrashOrigin, CrashSeverity};
    use uuid::Uuid;

    use super::dedup;

    fn crash(crashline: &str, frames: &[&str]) -> Crash {
        Crash {
            reproduction: None,
            id: Uuid::new_v4(),
            run_id: Uuid::nil(),
            target_id: Uuid::nil(),
            input_path: PathBuf::from("/work/out/crash"),
            stack_signature: crashline.to_owned(),
            kind: CrashKind::Asan,
            summary: format!("heap-buffer-overflow(read) at {crashline}"),
            minimized: false,
            bug_report: None,
            casr: Some(CasrReport {
                severity: CrashSeverity::NotExploitable,
                severity_short: "heap-buffer-overflow(read)".to_owned(),
                crashline: crashline.to_owned(),
                stack: frames.iter().map(|frame| (*frame).to_owned()).collect(),
                cluster: None,
            }),
            origin: CrashOrigin::Target,
        }
    }

    /// The three findings one honggfuzz campaign on `utf8_decoder` reported for
    /// a single overflow: one symbolized, two not, from two run directories.
    #[test]
    fn symbolized_and_unsymbolized_reports_of_one_bug_are_one_finding() {
        let unsymbolized = |run: &str| {
            crash(
                &format!("/work/runs/{run}/input/harness+0x111dfc"),
                &[
                    &format!("    #0 0xaaaaaabb1dfc  (/work/runs/{run}/input/harness+0x111dfc) (BuildId: 6be2)"),
                    &format!("    #1 0xaaaaaabb1b90  (/work/runs/{run}/input/harness+0x111b90) (BuildId: 6be2)"),
                ],
            )
        };
        let symbolized = crash(
            "/work/utf8.c:31:27",
            &[
                "    #0 0xaaaaaabb1dfc in decode_utf8 /work/utf8.c:31:27",
                "    #1 0xaaaaaabb1b90 in LLVMFuzzerTestOneInput /work/harness.c:20:5",
            ],
        );

        let kept = dedup(vec![
            unsymbolized("6185ff24"),
            symbolized,
            unsymbolized("3da6fc31"),
        ]);

        assert_eq!(kept.len(), 1, "{kept:#?}");
        assert_eq!(kept[0].stack_signature, "/work/utf8.c:31:27");
    }

    /// Triage groups findings across runs by this key; the two unsymbolized
    /// copies and the symbolized report of one overflow share it.
    #[test]
    fn findings_of_one_bug_share_a_bug_key() {
        let unsymbolized = |run: &str| {
            crash(
                &format!("/work/runs/{run}/input/harness+0x111dfc"),
                &[
                    &format!("    #0 0xaaaaaabb1dfc  (/work/runs/{run}/input/harness+0x111dfc)"),
                    &format!("    #1 0xaaaaaabb1b90  (/work/runs/{run}/input/harness+0x111b90)"),
                ],
            )
        };
        let symbolized = crash(
            "/work/utf8.c:31:27",
            &[
                "    #0 0xaaaaaabb1dfc in decode_utf8 /work/utf8.c:31:27",
                "    #1 0xaaaaaabb1b90 in LLVMFuzzerTestOneInput /work/harness.c:20:5",
            ],
        );
        let other = crash(
            "/work/b.c:20:1",
            &[
                "    #0 0xaaaaaabb3000 in b /work/b.c:20:1",
                "    #1 0xaaaaaabb2000 in main",
            ],
        );
        let crashes = vec![unsymbolized("a"), other, symbolized, unsymbolized("b")];
        let keys = super::bug_keys(&crashes);
        assert_eq!(keys[0], keys[2]);
        assert_eq!(keys[0], keys[3]);
        assert_ne!(keys[0], keys[1]);
        let mut raw = crash("", &[]);
        raw.casr = None;
        let mut second = raw.clone();
        second.id = Uuid::new_v4();
        let alone = super::bug_keys(&[raw, second]);
        assert_ne!(alone[0], alone[1], "no identity, no grouping");
    }

    #[test]
    fn distinct_bugs_stay_distinct() {
        let first = crash(
            "/work/a.c:10:1",
            &[
                "    #0 0xaaaaaabb1000 in a /work/a.c:10:1",
                "    #1 0xaaaaaabb2000 in main",
            ],
        );
        let second = crash(
            "/work/b.c:20:1",
            &[
                "    #0 0xaaaaaabb3000 in b /work/b.c:20:1",
                "    #1 0xaaaaaabb2000 in main",
            ],
        );
        assert_eq!(dedup(vec![first, second]).len(), 2);
    }

    #[test]
    fn crashes_without_any_identity_are_all_kept() {
        let mut raw = crash("", &[]);
        raw.casr = None;
        assert_eq!(dedup(vec![raw.clone(), raw]).len(), 2);
    }
}
