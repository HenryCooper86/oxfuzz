//! Human-readable rendering of `oxfuzz discover` output.
//!
//! The JSON inventory stays the machine contract: it is what a pipe or
//! `--json` receives. On a terminal, an operator gets this table instead, with
//! the best targets first and the command to fuzz the top one.

use hf_service::TargetLanguage;
use std::fmt::Write as _;

/// Rows shown before the table is truncated with a pointer to `--json`.
const MAX_ROWS: usize = 25;

/// Render discovery output as a table.
///
/// Accepts both shapes `discover` emits: a bare `TargetInventory`, and the
/// `--rank` advice that wraps it as `{"inventory": ..., "assessments": [...]}`.
/// When AI assessments are present the rows follow the advisory score; the
/// scan's fit score stays visible next to it.
pub(crate) fn render_discovery_table(
    value: &serde_json::Value,
    language: TargetLanguage,
) -> String {
    let inventory = value.get("inventory").unwrap_or(value);
    let project_root = inventory
        .get("project_root")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(".");
    let assessments = value
        .get("assessments")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let ai_score = |id: &str| {
        assessments
            .iter()
            .find(|assessment| assessment["target_id"].as_str() == Some(id))
            .and_then(|assessment| assessment["advisory_score"].as_f64())
    };

    let mut rows: Vec<Row> = inventory
        .get("candidates")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|candidate| Row::from_candidate(candidate, project_root, &ai_score))
        .collect();

    if rows.is_empty() {
        return format!(
            "No fuzz targets found in {project_root} for --lang {}.\n\
             Check the language, or point discover at the directory holding the sources.\n",
            language.as_str()
        );
    }

    rows.sort_by(|left, right| {
        right
            .ai
            .unwrap_or(-1.0)
            .total_cmp(&left.ai.unwrap_or(-1.0))
            .then(right.fit.total_cmp(&left.fit))
    });
    let show_ai = rows.iter().any(|row| row.ai.is_some());

    let total = rows.len();
    let shown = &rows[..total.min(MAX_ROWS)];
    let target_width = column_width("TARGET", shown.iter().map(|row| row.symbol.as_str()));
    let location_width = column_width("LOCATION", shown.iter().map(|row| row.location.as_str()));

    let noun = if total == 1 { "target" } else { "targets" };
    let mut out = format!("{total} {noun} in {project_root}\n\n");
    // Writing into a String cannot fail, so the fmt::Result is discarded.
    let _ = write!(
        out,
        "  {:>3}  {:<target_width$}  {:<location_width$}  {:>4}",
        "#", "TARGET", "LOCATION", "FIT"
    );
    if show_ai {
        let _ = write!(out, "  {:>4}", "AI");
    }
    out.push_str("  HARNESS\n");
    for (index, row) in shown.iter().enumerate() {
        let _ = write!(
            out,
            "  {:>3}  {:<target_width$}  {:<location_width$}  {:>4.2}",
            index + 1,
            row.symbol,
            row.location,
            row.fit
        );
        if show_ai {
            match row.ai {
                Some(score) => {
                    let _ = write!(out, "  {score:>4.2}");
                }
                None => {
                    let _ = write!(out, "  {:>4}", "-");
                }
            }
        }
        out.push_str(if row.harnessable { "  yes\n" } else { "  no\n" });
    }
    if total > shown.len() {
        let _ = writeln!(
            out,
            "  ... and {} more (use --json for the full inventory)",
            total - shown.len()
        );
    }

    if let Some(best) = rows.iter().find(|row| row.harnessable) {
        let _ = writeln!(
            out,
            "\nNext: oxfuzz fuzz {project_root} --target {} --lang {}",
            best.symbol,
            language.as_str()
        );
    }
    out
}

struct Row {
    symbol: String,
    location: String,
    fit: f64,
    ai: Option<f64>,
    harnessable: bool,
}

impl Row {
    fn from_candidate(
        candidate: &serde_json::Value,
        project_root: &str,
        ai_score: &impl Fn(&str) -> Option<f64>,
    ) -> Self {
        let file = candidate["location"]["file"].as_str().unwrap_or("?");
        let relative = std::path::Path::new(file)
            .strip_prefix(project_root)
            .map_or_else(|_| file.to_owned(), |path| path.display().to_string());
        let location = match candidate["location"]["line"].as_u64() {
            Some(line) => format!("{relative}:{line}"),
            None => relative,
        };
        Self {
            symbol: candidate["symbol"].as_str().unwrap_or("?").to_owned(),
            location,
            fit: candidate["fit_score"].as_f64().unwrap_or(0.0),
            ai: candidate["id"].as_str().and_then(ai_score),
            harnessable: candidate["harnessable"].as_bool().unwrap_or(true),
        }
    }
}

fn column_width<'a>(header: &str, values: impl Iterator<Item = &'a str>) -> usize {
    values
        .map(|value| value.chars().count())
        .chain(std::iter::once(header.len()))
        .max()
        .unwrap_or(header.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn candidate(id: &str, symbol: &str, file: &str, line: u64, fit: f64) -> serde_json::Value {
        json!({
            "id": id,
            "symbol": symbol,
            "location": {"file": file, "line": line},
            "fit_score": fit,
            "harnessable": true,
        })
    }

    #[test]
    fn plain_inventory_lists_targets_best_fit_first_with_relative_locations() {
        let value = json!({
            "project_root": "/src/proj",
            "candidates": [
                candidate("a", "helper", "/src/proj/util.c", 4, 0.31),
                candidate("b", "parse_packet", "/src/proj/net/packet.c", 10, 0.866),
            ],
        });

        let table = render_discovery_table(&value, TargetLanguage::C);

        assert!(table.starts_with("2 targets in /src/proj\n"), "{table}");
        let parse = table.find("parse_packet").expect("parse_packet row");
        let helper = table.find("helper").expect("helper row");
        assert!(parse < helper, "best fit first:\n{table}");
        assert!(
            table.contains("net/packet.c:10"),
            "relative location:\n{table}"
        );
        assert!(
            table.contains("0.87"),
            "fit rounded to two places:\n{table}"
        );
        assert!(
            !table.contains(" AI "),
            "no AI column without assessments:\n{table}"
        );
        assert!(
            table.contains("Next: oxfuzz fuzz /src/proj --target parse_packet --lang c"),
            "suggests fuzzing the best target:\n{table}"
        );
    }

    #[test]
    fn ranked_advice_orders_by_ai_score_and_shows_both_scores() {
        let value = json!({
            "inventory": {
                "project_root": "/p",
                "candidates": [
                    candidate("a", "high_fit", "/p/a.c", 1, 0.9),
                    candidate("b", "ai_pick", "/p/b.c", 2, 0.5),
                ],
            },
            "assessments": [
                {"target_id": "b", "advisory_score": 0.95},
                {"target_id": "a", "advisory_score": 0.40},
            ],
            "ranking_source": "ai",
        });

        let table = render_discovery_table(&value, TargetLanguage::Cpp);

        let header = table.lines().find(|line| line.contains("TARGET")).unwrap();
        assert!(header.contains("AI"), "AI column present: {header}");
        assert!(
            table.find("ai_pick").unwrap() < table.find("high_fit").unwrap(),
            "AI order wins:\n{table}"
        );
        assert!(table.contains("0.95"), "{table}");
        assert!(table.contains("0.90"), "fit stays visible:\n{table}");
        assert!(table.contains("--target ai_pick --lang cpp"), "{table}");
    }

    #[test]
    fn non_harnessable_targets_are_marked_and_never_suggested() {
        let mut go = candidate("g", "ParsePacket", "/g/parser.go", 3, 0.8);
        go["harnessable"] = json!(false);
        let value = json!({"project_root": "/g", "candidates": [go]});

        let table = render_discovery_table(&value, TargetLanguage::Go);

        let row = table
            .lines()
            .find(|line| line.contains("ParsePacket"))
            .unwrap();
        assert!(
            row.trim_end().ends_with("no"),
            "marked not harnessable: {row}"
        );
        assert!(!table.contains("Next:"), "no fuzz suggestion:\n{table}");
    }

    #[test]
    fn empty_inventory_says_so_and_names_the_language() {
        let value = json!({"project_root": "/empty", "candidates": []});

        let table = render_discovery_table(&value, TargetLanguage::Rust);

        assert!(
            table.contains("No fuzz targets found in /empty for --lang rust"),
            "{table}"
        );
    }

    #[test]
    fn long_inventories_are_truncated_with_a_pointer_to_json() {
        let candidates: Vec<_> = (0..30)
            .map(|index| {
                candidate(
                    &index.to_string(),
                    &format!("f{index}"),
                    "/p/x.c",
                    index,
                    0.5,
                )
            })
            .collect();
        let value = json!({"project_root": "/p", "candidates": candidates});

        let table = render_discovery_table(&value, TargetLanguage::C);

        assert!(table.starts_with("30 targets"), "{table}");
        assert!(
            table.contains("... and 5 more (use --json for the full inventory)"),
            "{table}"
        );
    }
}
