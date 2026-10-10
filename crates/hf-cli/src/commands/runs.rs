//! Run lifecycle commands: `runs list`, `runs status`, `runs stop`.
//!
//! Thin presentation over `hf-service` (Engineering Protocol 2.9): the listing
//! is [`hf_service::ServiceContainer::run_history`], the detail view is
//! [`hf_service::ServiceContainer::run_detail`], and stopping goes through the same
//! [`hf_service::ServiceContainer::request_run_cancel`] the web `POST /runs/{id}/cancel`
//! route uses. Cancellation is cooperative and in-process, so a one-shot CLI
//! can only stop a run it owns; a run owned by another process (a server, a
//! TUI, another CLI) is reported, not signalled.

use std::fmt::Write as _;
use std::path::PathBuf;

use hf_service::{RunCancelOutcome, RunDetailView, RunHistoryItem, RunLifecycleStatus};

/// Non-terminal lifecycle states for `runs list --active`, spelled as
/// `run_history` renders them (`RunStatus` debug names; the desktop GUI matches
/// on the same strings).
pub(crate) fn is_active_status(status: &str) -> bool {
    matches!(status, "Pending" | "Running")
}

/// The short run id `runs list` prints and `runs status`/`runs stop` accept.
pub(crate) fn short_run_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

/// `2026-10-08T10:00:00+00:00` -> `2026-10-08 10:00:00Z`.
fn format_timestamp(rfc3339: &str) -> String {
    rfc3339.replace('T', " ").replace("+00:00", "Z")
}

fn format_duration(duration_secs: Option<i64>) -> String {
    duration_secs.map_or_else(|| "-".to_owned(), |secs| format!("{secs}s"))
}

fn format_optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// Header + one row per run, columns padded to the widest cell.
pub(crate) fn run_list_lines(items: &[RunHistoryItem]) -> Vec<String> {
    let header = [
        "ID", "TARGET", "ENGINE", "STATUS", "STARTED", "DURATION", "CRASHES",
    ];
    let rows: Vec<[String; 7]> = items
        .iter()
        .map(|item| {
            [
                short_run_id(&item.id).to_owned(),
                item.target.clone().unwrap_or_else(|| "-".to_owned()),
                item.engine.clone(),
                item.status.clone(),
                format_timestamp(&item.started_at),
                format_duration(item.duration_secs),
                item.crashes.to_string(),
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row.iter()) {
            *width = (*width).max(cell.len());
        }
    }
    let render = |cells: [&str; 7]| {
        let mut line = String::new();
        for (width, cell) in widths.iter().zip(cells.iter()) {
            // Swallowed: `write!` on a String cannot fail (its `fmt::Write`
            // impl is infallible); nothing else can reach the error.
            let _ = write!(line, "{cell:<width$}  ");
        }
        line.trim_end().to_owned()
    };
    let mut lines = vec![render(header)];
    lines.extend(
        rows.iter()
            .map(|row| render(row.each_ref().map(String::as_str))),
    );
    lines
}

/// The full detail view as `key: value` lines; absent fields stay absent
/// rather than rendering a misleading zero.
pub(crate) fn run_detail_lines(detail: &RunDetailView) -> Vec<String> {
    let run = &detail.run;
    let mut lines = vec![
        format!("run:        {}", run.id),
        format!("project:    {}", run.project_root),
        format!(
            "target:     {}",
            run.target_selector
                .as_deref()
                .or(run.target.as_deref())
                .unwrap_or("-")
        ),
        format!("kind:       {}", run.kind),
        format!("engine:     {}", run.engine),
        format!(
            "status:     {}{}",
            run.status,
            if detail.active_in_this_process {
                " (active in this process)"
            } else {
                ""
            }
        ),
        format!("started:    {}", format_timestamp(&run.started_at)),
    ];
    if let Some(ended_at) = &run.ended_at {
        lines.push(format!("ended:      {}", format_timestamp(ended_at)));
    }
    lines.push(format!(
        "duration:   {}",
        format_duration(run.duration_secs)
    ));
    if let Some(requested) = run.requested_duration_secs {
        lines.push(format!("requested:  {requested}s"));
    }
    lines.push(format!("crashes:    {}", run.crashes));
    lines.push(format!("edges:      {}", format_optional(run.edges)));
    lines.push(format!(
        "execs/s:    {}",
        run.execs
            .map_or_else(|| "-".to_owned(), |execs| format!("{execs:.1}"))
    ));
    if let Some(harness_rev) = &run.harness_rev {
        lines.push(format!("harness:    {harness_rev}"));
    }
    if let Some(binary_rev) = &run.binary_rev {
        lines.push(format!("binary:     {binary_rev}"));
    }
    if let Some(evidence_dir) = &run.evidence_dir {
        lines.push(format!("evidence:   {evidence_dir}"));
    }
    if let Some(telemetry) = &detail.telemetry {
        lines.push(format!(
            "telemetry:  observed {}",
            format_timestamp(&telemetry.observed_at)
        ));
        lines.push(format!("  edges:    {}", format_optional(telemetry.edges)));
        if let Some(current) = telemetry.current_execs {
            lines.push(format!(
                "  execs/s:  {current:.1} (mean {}, peak {})",
                telemetry
                    .mean_execs
                    .map_or_else(|| "-".to_owned(), |mean| format!("{mean:.1}")),
                telemetry
                    .peak_execs
                    .map_or_else(|| "-".to_owned(), |peak| format!("{peak:.1}")),
            ));
        }
        if let Some(free_disk_bytes) = telemetry.free_disk_bytes {
            lines.push(format!("  free disk: {free_disk_bytes} B"));
        }
    }
    lines
}

pub(crate) async fn cmd_runs_list(
    project: Option<PathBuf>,
    active: bool,
    json: bool,
    limit: usize,
) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    let mut items = container.run_history(project.as_deref()).await?;
    if active {
        items.retain(|item| is_active_status(&item.status));
    }
    items.truncate(limit);
    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("No runs recorded.");
        return Ok(());
    }
    for line in run_list_lines(&items) {
        println!("{line}");
    }
    Ok(())
}

pub(crate) async fn cmd_runs_status(id: &str, json: bool) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    let detail = container.run_detail(id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&detail)?);
        return Ok(());
    }
    for line in run_detail_lines(&detail) {
        println!("{line}");
    }
    Ok(())
}

pub(crate) async fn cmd_runs_stop(id: &str) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    let run_id = container.resolve_run_id(id).await?;
    let control = container.run_control_status(run_id).await?;
    match container.request_run_cancel(run_id).await? {
        RunCancelOutcome::Accepted => {
            println!(
                "cancel requested for run {run_id}; the engine stops cooperatively and the run closes as cancelled"
            );
            Ok(())
        }
        RunCancelOutcome::NotFound => anyhow::bail!("run '{id}' not found"),
        RunCancelOutcome::Inactive => {
            let Some(control) = control else {
                anyhow::bail!("run '{id}' not found");
            };
            match control.status {
                RunLifecycleStatus::Done
                | RunLifecycleStatus::Failed
                | RunLifecycleStatus::Cancelled => {
                    anyhow::bail!(
                        "run {run_id} already finished (status: {}); nothing to stop",
                        control.status.as_str()
                    )
                }
                RunLifecycleStatus::Pending => anyhow::bail!(
                    "run {run_id} is reserved but its engine has not started; there is nothing to stop yet"
                ),
                RunLifecycleStatus::Running if !control.active => anyhow::bail!(
                    "run {run_id} is running but owned by another process; cancellation is cooperative and in-process, \
                     so stop it from the owning process (its server's POST /runs/{run_id}/cancel, or Ctrl-C in the owning CLI/TUI)"
                ),
                RunLifecycleStatus::Running => anyhow::bail!(
                    "cancellation for run {run_id} was already requested"
                ),
            }
        }
    }
}

/// Render the edge-set diff as decided by `hf-service`: exact counts first,
/// then the capped id samples, then the cross-binary caveat (Engineering
/// Protocol 2.9).
#[cfg(feature = "run-closeout")]
pub(crate) fn edge_diff_lines(report: &hf_service::CoverageDiffReport) -> Vec<String> {
    let sample = |ids: &[u64], total: u64| -> String {
        let listed = ids
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if total > ids.len() as u64 {
            format!("{listed} (first {} of {total})", ids.len())
        } else {
            listed
        }
    };
    let mut lines = vec![
        format!(
            "edge diff: {} -> {}",
            short_run_id(&report.run_a.to_string()),
            short_run_id(&report.run_b.to_string())
        ),
        format!(
            "  run a: {} edges, run b: {} edges, common: {}, union: {}",
            report.edges_a, report.edges_b, report.common, report.union
        ),
        format!("  only in a (lost): {}", report.only_a),
        format!("    {}", sample(&report.only_a_sample, report.only_a)),
        format!("  only in b (gained): {}", report.only_b),
        format!("    {}", sample(&report.only_b_sample, report.only_b)),
    ];
    if !report.same_binary {
        lines.push(
            "  note: the runs measured different binaries; AFL edge ids are assigned per build, \
             so id-level differences may reflect reassignment rather than coverage change"
                .to_owned(),
        );
    }
    lines
}

#[cfg(feature = "run-closeout")]
pub(crate) async fn cmd_runs_diff(a: &str, b: &str, json: bool) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    let run_a = container.resolve_run_id(a).await?;
    let run_b = container.resolve_run_id(b).await?;
    let report = container.coverage_diff(run_a, run_b).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    for line in edge_diff_lines(&report) {
        println!("{line}");
    }
    Ok(())
}

#[cfg(feature = "run-closeout")]
pub(crate) async fn cmd_runs_capture_edges(id: &str, json: bool) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    let run_id = container.resolve_run_id(id).await?;
    let capture = container.capture_run_edge_set(run_id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&capture)?);
        return Ok(());
    }
    if capture.already_retained {
        println!(
            "run {} already retains an edge set: {} edges from {} inputs (captured {})",
            capture.run_id, capture.edges, capture.inputs, capture.collected_at
        );
    } else {
        println!(
            "captured edge set for run {}: {} edges from {} inputs",
            capture.run_id, capture.edges, capture.inputs
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hf_service::RunTelemetryView;

    use super::*;
    fn history_item(id: &str, status: &str) -> RunHistoryItem {
        RunHistoryItem {
            id: id.to_owned(),
            target_id: None,
            requested_duration_secs: Some(60),
            project_root: "/p".to_owned(),
            target: Some("parse_packet".to_owned()),
            target_selector: Some("src/parser.c::parse_packet".to_owned()),
            comparison_key: None,
            kind: "Campaign".to_owned(),
            engine: "LibFuzzer".to_owned(),
            status: status.to_owned(),
            started_at: "2026-10-08T10:00:00+00:00".to_owned(),
            ended_at: Some("2026-10-08T10:01:00+00:00".to_owned()),
            duration_secs: Some(60),
            crashes: 3,
            edges: Some(1523),
            execs: Some(842.5),
            harness_rev: Some("ab".repeat(32)),
            binary_rev: Some("cd".repeat(32)),
            evidence_dir: Some(format!("runs/{id}/out")),
        }
    }

    #[test]
    fn short_run_id_is_the_prefix_the_other_commands_accept() {
        assert_eq!(
            short_run_id("aaaaaaaa-1111-2222-3333-444444444444"),
            "aaaaaaaa"
        );
        assert_eq!(short_run_id("short"), "short");
    }

    #[test]
    fn active_status_covers_only_in_flight_states() {
        assert!(is_active_status("Pending"));
        assert!(is_active_status("Running"));
        for terminal in ["Done", "Failed", "Cancelled"] {
            assert!(!is_active_status(terminal), "{terminal}");
        }
    }

    #[test]
    fn list_rows_align_columns_and_render_only_persisted_fields() {
        let mut older = history_item("bbbbbbbb-1111-2222-3333-444444444444", "Running");
        older.ended_at = None;
        older.duration_secs = None;
        older.edges = None;
        older.execs = None;
        older.crashes = 0;
        let items = vec![
            history_item("aaaaaaaa-1111-2222-3333-444444444444", "Done"),
            older,
        ];

        let lines = run_list_lines(&items);

        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("ID"));
        assert!(lines[1].starts_with("aaaaaaaa"));
        assert!(lines[1].contains("parse_packet"));
        assert!(lines[1].contains("LibFuzzer"));
        assert!(lines[1].contains("Done"));
        assert!(lines[1].contains("2026-10-08 10:00:00Z"));
        assert!(lines[1].contains("60s"));
        assert!(lines[1].ends_with('3'));
        assert!(lines[2].starts_with("bbbbbbbb"));
        assert!(lines[2].contains("Running"));
        // A running run has no persisted duration yet: a placeholder, not 0s.
        assert!(lines[2].contains(" - "));
        // Columns start at the same offset in the header and every row.
        let offset = |line: &str, cell: &str| line.find(cell).expect(cell);
        for (header, cell) in [
            ("TARGET", "parse_packet"),
            ("STARTED", "2026-10-08 10:00:00Z"),
        ] {
            let expected = offset(&lines[0], header);
            for line in &lines[1..] {
                assert_eq!(offset(line, cell), expected, "ragged column: {line}");
            }
        }
        let status_offset = offset(&lines[0], "STATUS");
        assert_eq!(offset(&lines[1], "Done"), status_offset);
        assert_eq!(offset(&lines[2], "Running"), status_offset);
    }

    #[test]
    fn detail_lines_cover_the_record_and_telemetry_without_inventing_fields() {
        let detail = RunDetailView {
            run: history_item("aaaaaaaa-1111-2222-3333-444444444444", "Running"),
            active_in_this_process: false,
            telemetry: Some(RunTelemetryView {
                observed_at: "2026-10-08T10:00:30+00:00".to_owned(),
                last_progress_at: Some("2026-10-08T10:00:29+00:00".to_owned()),
                current_execs: Some(1200.0),
                mean_execs: Some(1000.0),
                peak_execs: Some(1300.0),
                edges: Some(777),
                free_disk_bytes: Some(1_048_576),
            }),
        };

        let text = run_detail_lines(&detail).join("\n");

        assert!(text.contains("run:        aaaaaaaa-1111-2222-3333-444444444444"));
        assert!(text.contains("target:     src/parser.c::parse_packet"));
        assert!(text.contains("kind:       Campaign"));
        assert!(text.contains("status:     Running"));
        assert!(!text.contains("active in this process"));
        assert!(text.contains("requested:  60s"));
        assert!(text.contains("crashes:    3"));
        assert!(text.contains("edges:      1523"));
        assert!(text.contains("execs/s:    842.5"));
        assert!(text.contains(&format!("harness:    {}", "ab".repeat(32))));
        assert!(text.contains("evidence:   runs/aaaaaaaa-1111-2222-3333-444444444444/out"));
        assert!(text.contains("telemetry:  observed 2026-10-08 10:00:30Z"));
        assert!(text.contains("  edges:    777"));
        assert!(text.contains("  execs/s:  1200.0 (mean 1000.0, peak 1300.0)"));
        assert!(text.contains("  free disk: 1048576 B"));
    }

    #[test]
    fn detail_lines_omit_absent_optionals_and_mark_process_ownership() {
        let mut run = history_item("aaaaaaaa-1111-2222-3333-444444444444", "Pending");
        run.ended_at = None;
        run.duration_secs = None;
        run.edges = None;
        run.execs = None;
        run.harness_rev = None;
        run.binary_rev = None;
        run.evidence_dir = None;
        run.target = None;
        run.target_selector = None;
        let detail = RunDetailView {
            run,
            active_in_this_process: true,
            telemetry: None,
        };

        let text = run_detail_lines(&detail).join("\n");

        assert!(text.contains("status:     Pending (active in this process)"));
        assert!(text.contains("target:     -"));
        assert!(text.contains("duration:   -"));
        assert!(text.contains("edges:      -"));
        assert!(text.contains("execs/s:    -"));
        assert!(!text.contains("ended:"));
        assert!(!text.contains("harness:"));
        assert!(!text.contains("telemetry:"));
    }
}

#[cfg(all(test, feature = "run-closeout"))]
mod edge_diff_render_tests {
    use super::edge_diff_lines;

    fn report(same_binary: bool) -> hf_service::CoverageDiffReport {
        hf_service::CoverageDiffReport {
            run_a: uuid::Uuid::from_u128(0xaaaa),
            run_b: uuid::Uuid::from_u128(0xbbbb),
            same_binary,
            edges_a: 3,
            edges_b: 2,
            only_a: 2,
            only_b: 1,
            common: 1,
            union: 4,
            only_a_sample: vec![1, 2],
            only_b_sample: vec![4],
            sample_cap: 64,
        }
    }

    #[test]
    fn diff_lines_render_counts_samples_and_direction() {
        let text = edge_diff_lines(&report(true)).join("\n");

        assert!(text.contains("edge diff:"), "{text}");
        assert!(
            text.contains("run a: 3 edges, run b: 2 edges, common: 1, union: 4"),
            "{text}"
        );
        assert!(text.contains("only in a (lost): 2"), "{text}");
        assert!(text.contains("1, 2"), "{text}");
        assert!(text.contains("only in b (gained): 1"), "{text}");
        assert!(!text.contains("different binaries"), "{text}");
    }

    #[test]
    fn diff_lines_note_a_binary_change_and_mark_truncated_samples() {
        let mut report = report(false);
        report.only_a = 500;
        report.only_a_sample = (0..64).collect();
        let text = edge_diff_lines(&report).join("\n");

        assert!(text.contains("different binaries"), "{text}");
        assert!(text.contains("first 64 of 500"), "{text}");
    }
}
