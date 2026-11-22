//! Line-by-line coverage derived from `llvm-cov export`, rendered as lcov
//! tracefile text or one self-contained HTML page.
//!
//! The export is produced inside the sandbox from an untrusted binary, so it
//! is parsed here with bounds: the number of files, the line span of each
//! file, and the source text shown per file are all capped.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Deserialize;

/// Files read from one export.
const MAX_FILES: usize = 5_000;
/// Lines one file may span between its first and last segment.
const MAX_LINE_SPAN: u64 = 500_000;
/// Source lines rendered for one file in the HTML page.
const MAX_SOURCE_LINES: usize = 50_000;

/// One function's entry count and where it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionHit {
    pub name: String,
    /// 1-based line the function starts on.
    pub line: u64,
    pub count: u64,
}

/// Line execution counts for one source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCoverage {
    /// The path as `llvm-cov` recorded it (a sandbox path).
    pub path: String,
    /// Execution count for every instrumented line, keyed by 1-based line.
    /// A line that is absent holds no executable code.
    pub lines: BTreeMap<u64, u64>,
    pub functions: Vec<FunctionHit>,
}

impl FileCoverage {
    /// Instrumented lines executed at least once.
    #[must_use]
    pub fn lines_hit(&self) -> usize {
        self.lines.values().filter(|count| **count > 0).count()
    }

    /// Percentage of instrumented lines executed (0.0 when there are none).
    #[must_use]
    pub fn line_percent(&self) -> f64 {
        if self.lines.is_empty() {
            return 0.0;
        }
        self.lines_hit() as f64 / self.lines.len() as f64 * 100.0
    }
}

/// Per-line coverage for every file in an export.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LineReport {
    pub files: Vec<FileCoverage>,
    /// Files left out because they exceeded a bound.
    pub skipped_files: usize,
}

#[derive(Deserialize)]
struct Export {
    data: Vec<DataEntry>,
}

#[derive(Deserialize)]
struct DataEntry {
    #[serde(default)]
    files: Vec<FileEntry>,
    #[serde(default)]
    functions: Vec<FunctionEntry>,
}

#[derive(Deserialize)]
struct FileEntry {
    #[serde(default)]
    filename: String,
    #[serde(default)]
    segments: Vec<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct FunctionEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    count: u64,
    #[serde(default)]
    filenames: Vec<String>,
    #[serde(default)]
    regions: Vec<Vec<u64>>,
}

/// One coverage segment: the count that applies from `line` until the next
/// segment.
#[derive(Clone, Copy)]
struct Segment {
    line: u64,
    count: u64,
    has_count: bool,
    is_region_entry: bool,
    is_gap: bool,
}

impl Segment {
    // Layout: [line, col, count, has_count, is_region_entry, is_gap_region].
    // Exports older than LLVM 9 omit the gap flag.
    fn parse(raw: &[serde_json::Value]) -> Option<Self> {
        Some(Self {
            line: raw.first()?.as_u64().filter(|line| *line > 0)?,
            count: raw.get(2)?.as_u64()?,
            has_count: raw.get(3)?.as_bool()?,
            is_region_entry: raw.get(4)?.as_bool()?,
            is_gap: raw
                .get(5)
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }

    const fn starts_region(&self) -> bool {
        !self.is_gap && self.has_count && self.is_region_entry
    }
}

/// The execution count of one line, or `None` when it holds no executable
/// code. This is the rule LLVM's `LineCoverageStats` applies: the count
/// carried in from the previous segment, raised to the largest count of a
/// region that starts on the line.
fn line_count(wrapped: Option<&Segment>, on_line: &[Segment]) -> Option<u64> {
    let region_starts = on_line.iter().filter(|segment| segment.starts_region());
    let starts_any = region_starts.clone().next().is_some();
    let starts_skipped = on_line
        .first()
        .is_some_and(|first| !first.has_count && first.is_region_entry);
    let mapped = (!starts_skipped
        && (wrapped.is_some_and(|segment| segment.has_count) || starts_any))
        || on_line
            .iter()
            .any(|segment| segment.is_region_entry && segment.has_count);
    if !mapped {
        return None;
    }
    let carried = wrapped.map_or(0, |segment| segment.count);
    Some(
        region_starts
            .map(|segment| segment.count)
            .fold(carried, u64::max),
    )
}

fn file_lines(segments: &[Segment]) -> Option<BTreeMap<u64, u64>> {
    let (first, last) = (segments.first()?.line, segments.last()?.line);
    if last.checked_sub(first)? > MAX_LINE_SPAN {
        return None;
    }
    let mut lines = BTreeMap::new();
    let mut next = 0;
    let mut wrapped: Option<Segment> = None;
    for line in first..=last {
        let start = next;
        while segments
            .get(next)
            .is_some_and(|segment| segment.line == line)
        {
            next += 1;
        }
        let on_line = &segments[start..next];
        if let Some(count) = line_count(wrapped.as_ref(), on_line) {
            lines.insert(line, count);
        }
        if let Some(last_on_line) = on_line.last() {
            wrapped = Some(*last_on_line);
        }
    }
    Some(lines)
}

/// Derive per-line coverage from an `llvm-cov export` JSON document.
///
/// Returns `None` for input that is not an export or holds no file with
/// segments.
#[must_use]
pub fn parse_llvm_cov_lines(json: &str) -> Option<LineReport> {
    let export: Export = serde_json::from_str(json).ok()?;
    let mut report = LineReport::default();
    let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
    for entry in export.data {
        for file in entry.files {
            if file.filename.is_empty() || by_path.contains_key(&file.filename) {
                continue;
            }
            let mut segments: Vec<Segment> = file
                .segments
                .iter()
                .filter_map(|raw| Segment::parse(raw))
                .collect();
            // llvm-cov emits segments in source order; a stable sort keeps
            // same-line order and makes the walk correct for any input.
            segments.sort_by_key(|segment| segment.line);
            let lines = if report.files.len() < MAX_FILES {
                file_lines(&segments)
            } else {
                None
            };
            let Some(lines) = lines else {
                report.skipped_files += 1;
                continue;
            };
            by_path.insert(file.filename.clone(), report.files.len());
            report.files.push(FileCoverage {
                path: file.filename,
                lines,
                functions: Vec::new(),
            });
        }
        for function in entry.functions {
            // The first region is the function body; its file id indexes the
            // function's own filename table.
            let Some(region) = function.regions.first().filter(|region| region.len() >= 6) else {
                continue;
            };
            let Some(index) = usize::try_from(region[5])
                .ok()
                .and_then(|id| function.filenames.get(id))
                .and_then(|path| by_path.get(path))
            else {
                continue;
            };
            if function.name.is_empty() || region[0] == 0 {
                continue;
            }
            report.files[*index].functions.push(FunctionHit {
                name: function.name,
                line: region[0],
                count: function.count,
            });
        }
    }
    (!report.files.is_empty()).then_some(report)
}

impl LineReport {
    /// Instrumented lines across every file.
    #[must_use]
    pub fn lines_total(&self) -> usize {
        self.files.iter().map(|file| file.lines.len()).sum()
    }

    /// Instrumented lines executed at least once, across every file.
    #[must_use]
    pub fn lines_hit(&self) -> usize {
        self.files.iter().map(FileCoverage::lines_hit).sum()
    }

    /// Render an lcov tracefile. `display_path` turns a recorded path into
    /// the `SF:` path a consumer should see (for example a project-relative
    /// one); line breaks in a path or function name are replaced so one
    /// record cannot forge another.
    #[must_use]
    pub fn to_lcov(&self, display_path: &dyn Fn(&str) -> String) -> String {
        let mut out = String::new();
        for file in &self.files {
            let _ = writeln!(out, "TN:");
            let _ = writeln!(out, "SF:{}", single_line(&display_path(&file.path)));
            for function in &file.functions {
                let _ = writeln!(out, "FN:{},{}", function.line, single_line(&function.name));
            }
            for function in &file.functions {
                let _ = writeln!(
                    out,
                    "FNDA:{},{}",
                    function.count,
                    single_line(&function.name)
                );
            }
            let _ = writeln!(out, "FNF:{}", file.functions.len());
            let _ = writeln!(
                out,
                "FNH:{}",
                file.functions
                    .iter()
                    .filter(|function| function.count > 0)
                    .count()
            );
            for (line, count) in &file.lines {
                let _ = writeln!(out, "DA:{line},{count}");
            }
            let _ = writeln!(out, "LF:{}", file.lines.len());
            let _ = writeln!(out, "LH:{}", file.lines_hit());
            let _ = writeln!(out, "end_of_record");
        }
        out
    }

    /// Render one self-contained HTML page: a file table, then each file's
    /// lines with their counts. `source` returns the text of a recorded path,
    /// or `None` when it is unavailable; such a file lists its instrumented
    /// lines without text. The page holds no script and loads nothing.
    #[must_use]
    pub fn to_html(
        &self,
        title: &str,
        display_path: &dyn Fn(&str) -> String,
        source: &dyn Fn(&str) -> Option<String>,
    ) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <title>{}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<h1>{}</h1>\n",
            escape(title),
            escape(title)
        );
        let (hit, total) = (self.lines_hit(), self.lines_total());
        let _ = writeln!(
            out,
            "<p class=\"total\">{hit} of {total} instrumented lines executed ({:.1}%) in {} \
             file(s).</p>",
            percent(hit, total),
            self.files.len()
        );
        if self.skipped_files > 0 {
            let _ = writeln!(
                out,
                "<p class=\"note\">{} file(s) exceeded the report bounds and are not shown.</p>",
                self.skipped_files
            );
        }
        let _ = writeln!(
            out,
            "<table class=\"files\">\n<thead><tr><th>File</th><th>Lines hit</th>\
             <th>Lines</th><th>Covered</th></tr></thead>\n<tbody>"
        );
        for (index, file) in self.files.iter().enumerate() {
            let _ = writeln!(
                out,
                "<tr><td><a href=\"#f{index}\">{}</a></td><td>{}</td><td>{}</td>\
                 <td>{:.1}%</td></tr>",
                escape(&display_path(&file.path)),
                file.lines_hit(),
                file.lines.len(),
                file.line_percent()
            );
        }
        let _ = writeln!(out, "</tbody>\n</table>");
        for (index, file) in self.files.iter().enumerate() {
            let _ = writeln!(
                out,
                "<details id=\"f{index}\" open>\n<summary>{} ({:.1}%)</summary>",
                escape(&display_path(&file.path)),
                file.line_percent()
            );
            write_listing(&mut out, file, source(&file.path).as_deref());
            let _ = writeln!(out, "</details>");
        }
        let _ = writeln!(out, "</body>\n</html>");
        out
    }
}

fn write_listing(out: &mut String, file: &FileCoverage, source: Option<&str>) {
    let Some(source) = source else {
        let _ = writeln!(
            out,
            "<p class=\"note\">Source text is not available; instrumented lines only.</p>"
        );
        let _ = writeln!(out, "<table class=\"src\"><tbody>");
        for (line, count) in file.lines.iter().take(MAX_SOURCE_LINES) {
            write_row(out, *line, Some(*count), "");
        }
        let _ = writeln!(out, "</tbody></table>");
        return;
    };
    let _ = writeln!(out, "<table class=\"src\"><tbody>");
    let mut shown = 0_usize;
    for (index, text) in source.lines().enumerate().take(MAX_SOURCE_LINES) {
        let line = index as u64 + 1;
        write_row(out, line, file.lines.get(&line).copied(), text);
        shown = index + 1;
    }
    let _ = writeln!(out, "</tbody></table>");
    if source.lines().nth(shown).is_some() {
        let _ = writeln!(
            out,
            "<p class=\"note\">Listing truncated after {MAX_SOURCE_LINES} lines.</p>"
        );
    }
}

fn write_row(out: &mut String, line: u64, count: Option<u64>, text: &str) {
    let (class, shown) = match count {
        Some(0) => ("miss", "0".to_owned()),
        Some(count) => ("hit", count.to_string()),
        None => ("none", String::new()),
    };
    let _ = writeln!(
        out,
        "<tr class=\"{class}\"><td class=\"n\">{line}</td><td class=\"c\">{shown}</td>\
         <td class=\"t\">{}</td></tr>",
        escape(text)
    );
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 / whole as f64 * 100.0
}

fn single_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

const STYLE: &str = "\
:root{--bg:#fff;--fg:#1b1f24;--muted:#5c6670;--line:#d8dde3;--hit:#e3f5e6;--miss:#fbe3e3;\
--link:#0b57b0}\
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e4e7ea;--muted:#9aa4ae;\
--line:#2c333a;--hit:#16351d;--miss:#4a1d1d;--link:#8ab4f8}}\
body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:0;\
padding:16px;max-width:1200px;margin-inline:auto}\
h1{font-size:20px}a{color:var(--link)}.note,.total{color:var(--muted)}\
.total{color:var(--fg)}\
table{border-collapse:collapse}\
.files{width:100%;margin:12px 0 24px}\
.files th,.files td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line)}\
.files td:not(:first-child),.files th:not(:first-child){text-align:right;white-space:nowrap}\
details{margin:0 0 16px;border:1px solid var(--line);border-radius:4px;overflow-x:auto}\
summary{cursor:pointer;padding:6px 8px;font-weight:600}\
.src{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;min-width:100%}\
.src td{padding:0 8px;vertical-align:top}\
.src .n,.src .c{text-align:right;color:var(--muted);user-select:none;white-space:nowrap}\
.src .t{white-space:pre;tab-size:4}\
.src .hit{background:var(--hit)}.src .miss{background:var(--miss)}";

#[cfg(test)]
mod tests {
    use super::*;

    // A two-function file: `parse` runs 5 times, its error branch (lines
    // 4-5) never runs, line 7 is a skipped preprocessor region, and `unused`
    // never runs.
    const EXPORT: &str = r#"{
      "data": [{
        "files": [{
          "filename": "/work/src/parse.c",
          "segments": [
            [1, 20, 5, true, true, false],
            [3, 9, 5, true, true, false],
            [3, 17, 0, true, true, false],
            [5, 4, 5, true, false, false],
            [6, 2, 0, false, false, false],
            [7, 1, 0, false, true, false],
            [8, 1, 0, false, false, false],
            [9, 19, 0, true, true, false],
            [11, 2, 0, false, false, false]
          ]
        }],
        "functions": [
          {"name": "parse", "count": 5, "filenames": ["/work/src/parse.c"],
           "regions": [[1,20,6,2,5,0,0,0]]},
          {"name": "unused", "count": 0, "filenames": ["/work/src/parse.c"],
           "regions": [[9,19,11,2,0,0,0,0]]}
        ],
        "totals": {"lines": {"count": 9, "covered": 4},
                   "functions": {"count": 2, "covered": 1},
                   "regions": {"count": 4, "covered": 2}}
      }],
      "type": "llvm.coverage.json.export",
      "version": "2.0.1"
    }"#;

    fn report() -> LineReport {
        parse_llvm_cov_lines(EXPORT).expect("fixture parses")
    }

    #[test]
    fn line_counts_follow_the_segment_walk() {
        let report = report();
        assert_eq!(report.files.len(), 1);
        let lines = &report.files[0].lines;
        let expected: BTreeMap<u64, u64> = [
            (1, 5),
            (2, 5),
            // Line 3 starts both the taken condition and the untaken branch;
            // the line count is the larger.
            (3, 5),
            (4, 0),
            // The branch's closing line carries the branch's count in: the
            // segment that resumes the outer count starts mid-line and does
            // not begin a region.
            (5, 0),
            (6, 5),
            (9, 0),
            (10, 0),
            (11, 0),
        ]
        .into_iter()
        .collect();
        assert_eq!(lines, &expected);
        // Line 7 starts a skipped region and line 8 follows a segment with
        // no counter: neither holds executable code.
        assert!(!lines.contains_key(&7) && !lines.contains_key(&8));
        assert_eq!(report.lines_total(), 9);
        assert_eq!(report.lines_hit(), 4);
    }

    #[test]
    fn functions_attach_to_their_file() {
        let report = report();
        assert_eq!(
            report.files[0].functions,
            vec![
                FunctionHit {
                    name: "parse".to_owned(),
                    line: 1,
                    count: 5
                },
                FunctionHit {
                    name: "unused".to_owned(),
                    line: 9,
                    count: 0
                },
            ]
        );
    }

    #[test]
    fn lcov_text_has_one_record_per_file() {
        let lcov = report().to_lcov(&|path| path.trim_start_matches("/work/").to_owned());
        let expected = "TN:\nSF:src/parse.c\nFN:1,parse\nFN:9,unused\nFNDA:5,parse\n\
                        FNDA:0,unused\nFNF:2\nFNH:1\nDA:1,5\nDA:2,5\nDA:3,5\nDA:4,0\nDA:5,0\n\
                        DA:6,5\nDA:9,0\nDA:10,0\nDA:11,0\nLF:9\nLH:4\nend_of_record\n";
        assert_eq!(lcov, expected);
    }

    #[test]
    fn a_path_cannot_forge_an_lcov_record() {
        let lcov = report().to_lcov(&|_| "a.c\nend_of_record\nSF:/etc/passwd".to_owned());
        assert_eq!(lcov.matches("end_of_record").count(), 2);
        assert_eq!(
            lcov.lines().filter(|line| line.starts_with("SF:")).count(),
            1
        );
    }

    #[test]
    fn html_escapes_source_and_marks_each_line() {
        let source = "int parse(const char *s) {\n  int n = 0;\n  if (s[0] == '<') {\n    \
                      n = -1;\n  }\n  return n; }\n#if 0\n#endif\nint unused(void) {\n  \
                      return 1 && 2;\n}\n";
        let html = report().to_html(
            "Coverage <demo>",
            &|path| path.trim_start_matches("/work/").to_owned(),
            &|_| Some(source.to_owned()),
        );
        assert!(
            html.contains("<title>Coverage &lt;demo&gt;</title>"),
            "{html}"
        );
        assert!(html.contains("4 of 9 instrumented lines executed (44.4%)"));
        assert!(html.contains(
            "<tr class=\"hit\"><td class=\"n\">3</td><td class=\"c\">5</td>\
             <td class=\"t\">  if (s[0] == &#39;&lt;&#39;) {</td></tr>"
        ));
        assert!(html.contains("<tr class=\"miss\"><td class=\"n\">4</td><td class=\"c\">0</td>"));
        assert!(html.contains("<tr class=\"none\"><td class=\"n\">7</td><td class=\"c\"></td>"));
        assert!(html.contains("return 1 &amp;&amp; 2;"));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn html_lists_instrumented_lines_when_source_is_unavailable() {
        let html = report().to_html("t", &str::to_owned, &|_| None);
        assert!(html.contains("Source text is not available"));
        assert!(html.contains("<tr class=\"miss\"><td class=\"n\">10</td>"));
    }

    #[test]
    fn a_file_spanning_an_absurd_line_range_is_skipped_not_allocated() {
        let json = r#"{"data":[{"files":[
            {"filename":"/work/huge.c","segments":[
                [1,1,1,true,true,false],[4000000000,1,0,false,false,false]]},
            {"filename":"/work/ok.c","segments":[
                [1,1,1,true,true,false],[2,1,0,false,false,false]]}
        ]}]}"#;
        let report = parse_llvm_cov_lines(json).unwrap();
        assert_eq!(report.skipped_files, 1);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/work/ok.c");
    }

    #[test]
    fn input_that_is_not_an_export_yields_nothing() {
        assert!(parse_llvm_cov_lines("not json").is_none());
        assert!(parse_llvm_cov_lines("{}").is_none());
        assert!(parse_llvm_cov_lines(r#"{"data":[{"files":[]}]}"#).is_none());
    }
}
