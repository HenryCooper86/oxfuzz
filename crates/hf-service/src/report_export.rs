//! Export a composed Markdown report to other document formats.
//!
//! Markdown and HTML are produced in-process (pure Rust). PDF and DOCX are
//! delegated to `pandoc` when it is installed (PDF additionally needs a PDF
//! engine such as `wkhtmltopdf`, `weasyprint`, or a LaTeX toolchain). Callers
//! should consult [`available_formats`] before offering a format so the user is
//! never sent to a save dialog for an export that cannot run.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use hf_core::error::ClassifiedError;

use crate::report::ReportLanguage;

/// The BCP 47 language tag an exported document declares. `zh-CN` (Simplified
/// Chinese) rather than bare `zh`, matching what the desktop app already sets on
/// `document.documentElement.lang`.
const fn html_lang_tag(language: ReportLanguage) -> &'static str {
    match language {
        ReportLanguage::En => "en",
        ReportLanguage::Zh => "zh-CN",
    }
}

/// Output document format for an exported report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Raw Markdown (the composed report as-is).
    Md,
    /// Standalone styled HTML document.
    Html,
    /// PDF (via `pandoc` + a PDF engine).
    Pdf,
    /// Microsoft Word document (via `pandoc`).
    Docx,
}

impl ReportFormat {
    /// Parse a format id (`md`, `html`, `pdf`, `docx`) case-insensitively.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "md" | "markdown" => Some(Self::Md),
            "html" | "htm" => Some(Self::Html),
            "pdf" => Some(Self::Pdf),
            "docx" | "doc" => Some(Self::Docx),
            _ => None,
        }
    }

    /// The file extension for this format (no dot).
    #[must_use]
    pub fn ext(self) -> &'static str {
        match self {
            Self::Md => "md",
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Docx => "docx",
        }
    }
}

/// Formats exportable on this host. Markdown and HTML are always available;
/// DOCX requires `pandoc`; PDF requires `pandoc` plus a PDF engine.
#[must_use]
pub fn available_formats() -> Vec<String> {
    let mut out = vec!["md".to_owned(), "html".to_owned()];
    if pandoc_available() {
        out.push("docx".to_owned());
        if pdf_engine().is_some() {
            out.push("pdf".to_owned());
        }
    }
    out
}

/// Render `markdown` (a composed report) to `out_path` in `format`.
///
/// `language` is the language `markdown` is written in; it is declared on the
/// HTML document so assistive technology picks the right voice and browsers pick
/// the right fonts and line-breaking rules.
///
/// # Errors
/// Returns an error on IO failure, or when a required external tool (pandoc, or
/// a PDF engine) is unavailable for the requested format.
pub fn write_report(
    markdown: &str,
    title: &str,
    format: ReportFormat,
    out_path: &Path,
    language: ReportLanguage,
) -> Result<(), ClassifiedError> {
    match format {
        // Markdown is the canonical source: keep the Mermaid diagrams so a
        // Mermaid-aware viewer renders them.
        ReportFormat::Md => std::fs::write(out_path, markdown)
            .map_err(|e| ClassifiedError::Internal(format!("write report: {e}"))),
        // Every exported format below is rendered by a tool that has no Mermaid
        // renderer, so the raw ```mermaid source would show as an ugly code
        // block. Strip it; the same data is already in the ASCII bar charts and
        // tables. The GUI preview keeps the original markdown and renders Mermaid.
        ReportFormat::Html => std::fs::write(
            out_path,
            markdown_to_html(&strip_mermaid_blocks(markdown), title, language),
        )
        .map_err(|e| ClassifiedError::Internal(format!("write report: {e}"))),
        ReportFormat::Docx => pandoc_convert(&strip_mermaid_blocks(markdown), out_path, None),
        ReportFormat::Pdf => {
            let engine = pdf_engine().ok_or_else(|| {
                ClassifiedError::Validation(
                    "PDF export needs a PDF engine (wkhtmltopdf, weasyprint, or a LaTeX install). \
                     Export HTML and print to PDF instead."
                        .to_owned(),
                )
            })?;
            // LaTeX-based PDF engines (xelatex/pdflatex) use fonts that lack the
            // box-drawing / block / arrow glyphs a report can contain (sparklines,
            // mermaid arrows), which get silently dropped. Substitute ASCII so the
            // PDF renders cleanly. Then insert zero-width break hints so long
            // paths wrap. MD/HTML/DOCX keep the original text.
            let prepared = sanitize_for_latex(&insert_break_hints(&strip_mermaid_blocks(markdown)));
            pandoc_convert(&prepared, out_path, Some(engine))
        }
    }
}

/// Insert a zero-width space (U+200B) after each path separator `/` that is not
/// inside a fenced code block, so LaTeX can wrap long inline paths (in prose and
/// table cells) at segment boundaries instead of running off the page. The
/// character is invisible and pdfstring-safe (unlike a `\texttt` redefinition,
/// which breaks hyperref bookmarks when inline code appears in a heading).
/// Fenced code blocks are skipped -- fvextra already wraps those, and a ZWSP
/// could show as a missing glyph in a monospace verbatim block.
#[derive(Clone, Copy)]
struct Fence {
    marker: char,
    length: usize,
}

fn parse_fence(line: &str) -> Option<(Fence, &str)> {
    let trimmed = line.trim_start();
    let marker = trimmed.chars().next()?;
    if !matches!(marker, '`' | '~') {
        return None;
    }
    let length = trimmed
        .chars()
        .take_while(|character| *character == marker)
        .count();
    (length >= 3).then(|| (Fence { marker, length }, &trimmed[length..]))
}

fn closes_fence(line: &str, active: Fence) -> bool {
    parse_fence(line).is_some_and(|(candidate, suffix)| {
        candidate.marker == active.marker
            && candidate.length >= active.length
            && suffix.trim().is_empty()
    })
}

fn insert_break_hints(md: &str) -> String {
    const ZWSP: char = '\u{200B}';
    let mut out = String::with_capacity(md.len() + md.len() / 16);
    let mut active_fence: Option<Fence> = None;
    for line in md.lines() {
        if let Some(active) = active_fence {
            out.push_str(line);
            out.push('\n');
            if closes_fence(line, active) {
                active_fence = None;
            }
            continue;
        }

        if let Some((fence, _)) = parse_fence(line) {
            active_fence = Some(fence);
            out.push_str(line);
            out.push('\n');
            continue;
        }

        for c in line.chars() {
            out.push(c);
            if c == '/' {
                out.push(ZWSP);
            }
        }
        out.push('\n');
    }
    out
}

/// Remove Mermaid fenced code blocks (info string `mermaid`). Exported formats
/// (HTML/PDF/DOCX) have no Mermaid renderer, so those blocks would otherwise
/// dump raw diagram source (`xychart-beta ...`, `pie ...`); the report already
/// carries the same numbers as ASCII bar charts and tables.
fn strip_mermaid_blocks(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut active_fence: Option<(Fence, bool)> = None;
    for line in md.lines() {
        if let Some((active, strip)) = active_fence {
            if !strip {
                out.push_str(line);
                out.push('\n');
            }
            if closes_fence(line, active) {
                active_fence = None;
            }
            continue;
        }

        if let Some((fence, info)) = parse_fence(line) {
            let strip = info
                .split_whitespace()
                .next()
                .is_some_and(|language| language.eq_ignore_ascii_case("mermaid"));
            active_fence = Some((fence, strip));
            if !strip {
                out.push_str(line);
                out.push('\n');
            }
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Convert Markdown to a standalone, styled HTML document (pure Rust, GFM).
/// `language` is declared as the document's `lang` attribute.
#[must_use]
pub fn markdown_to_html(markdown: &str, title: &str, language: ReportLanguage) -> String {
    let mut opts = comrak::Options::default();
    opts.extension.table = true;
    opts.extension.strikethrough = true;
    opts.extension.autolink = true;
    opts.extension.tasklist = true;
    let body = comrak::markdown_to_html(markdown, &opts);
    format!(
        "<!doctype html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n<style>{REPORT_CSS}</style>\n</head>\n<body>\n\
         <main class=\"report\">\n{body}\n</main>\n</body>\n</html>\n",
        lang = html_lang_tag(language),
        title = html_escape(title),
    )
}

/// Print-friendly stylesheet embedded in exported HTML so the file is
/// self-contained (no external assets) and prints cleanly to PDF.
const REPORT_CSS: &str = "\
:root{color-scheme:light}\
body{margin:0;background:#fff;color:#1a1a1a;font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}\
main.report{max-width:820px;margin:0 auto;padding:48px 32px}\
h1,h2,h3,h4{line-height:1.25;margin:1.6em 0 .6em;font-weight:600}\
h1{font-size:1.9em;border-bottom:1px solid #e5e5e5;padding-bottom:.3em}\
h2{font-size:1.45em;border-bottom:1px solid #eee;padding-bottom:.25em}\
h3{font-size:1.2em}\
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;background:#f4f4f5;padding:.15em .35em;border-radius:4px;overflow-wrap:anywhere;word-break:break-word}\
pre{background:#f6f8fa;border:1px solid #e5e5e5;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}\
pre code{background:none;padding:0;overflow-wrap:anywhere}\
table{border-collapse:collapse;width:100%;margin:1em 0;table-layout:fixed}\
th,td{border:1px solid #e0e0e0;padding:8px 12px;text-align:left;overflow-wrap:anywhere;word-break:break-word;vertical-align:top}\
th{background:#f7f7f8}\
blockquote{margin:1em 0;padding:.2em 1em;border-left:3px solid #d0d0d0;color:#555}\
a{color:#0b6bcb}\
@media print{main.report{max-width:none;padding:0}a{color:inherit}}";

/// Replace box-drawing, block-element, shade, and arrow glyphs with ASCII so a
/// LaTeX PDF engine (whose default fonts lack them) renders without dropping
/// characters. Only applied to the PDF path; other formats keep the originals.
fn sanitize_for_latex(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    for c in md.chars() {
        match c {
            // Shades (progress bars / sparklines).
            '\u{2591}' => out.push('.'),
            '\u{2592}' => out.push(':'),
            '\u{2593}' => out.push('='),
            // Remaining block elements (full/partial/eighth blocks).
            '\u{2580}'..='\u{259F}' => out.push('#'),
            // Box drawing: horizontals, verticals, everything else -> - | +.
            '\u{2500}' | '\u{2501}' | '\u{2504}' | '\u{2505}' | '\u{2508}' | '\u{2509}'
            | '\u{254C}' | '\u{254D}' => out.push('-'),
            '\u{2502}' | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250A}' | '\u{250B}'
            | '\u{254E}' | '\u{254F}' => out.push('|'),
            '\u{2500}'..='\u{257F}' => out.push('+'),
            // Arrows (common in mermaid / prose).
            '\u{2190}' => out.push_str("<-"),
            '\u{2192}' => out.push_str("->"),
            '\u{2194}' => out.push_str("<->"),
            '\u{21D2}' => out.push_str("=>"),
            '\u{2191}' => out.push('^'),
            '\u{2193}' => out.push('v'),
            _ => out.push(c),
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn pandoc_available() -> bool {
    tool_on_path("pandoc")
}

fn pdf_engine() -> Option<&'static str> {
    [
        "wkhtmltopdf",
        "weasyprint",
        "xelatex",
        "tectonic",
        "pdflatex",
    ]
    .into_iter()
    .find(|e| tool_on_path(e))
}

/// Whether the PDF engine is a LaTeX toolchain (as opposed to an HTML-based one
/// like wkhtmltopdf/weasyprint), so we only inject LaTeX preamble for those.
fn is_latex_engine(engine: &str) -> bool {
    matches!(engine, "xelatex" | "pdflatex" | "lualatex" | "tectonic")
}

fn tool_on_path(tool: &str) -> bool {
    // Resolve against well-known install dirs, not just the (possibly stripped)
    // PATH: a Finder-launched `.app` does not inherit the shell PATH, so bare
    // `pandoc`/`xelatex` would otherwise be invisible even when installed.
    hf_runtime::scrubbed_command(hf_runtime::resolve_bin(tool))
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn pandoc_convert(
    markdown: &str,
    out_path: &Path,
    pdf_engine: Option<&str>,
) -> Result<(), ClassifiedError> {
    if !pandoc_available() {
        return Err(ClassifiedError::Validation(
            "This format needs pandoc, which is not installed. Markdown and HTML are always available."
                .to_owned(),
        ));
    }
    let mut cmd = hf_runtime::scrubbed_command(hf_runtime::resolve_bin("pandoc"));
    cmd.arg("-f")
        .arg("gfm")
        .arg("--standalone")
        .arg("-o")
        .arg(out_path);
    if let Some(engine) = pdf_engine {
        cmd.arg(format!("--pdf-engine={engine}"));
        if is_latex_engine(engine) {
            // LaTeX doesn't wrap long lines in code blocks or long unbroken
            // tokens (file paths, stack-trace frames) by default, so they run
            // off the right margin. `--no-highlight` makes fenced code plain
            // `verbatim` (pandoc's syntax highlighting wraps each line in a
            // \NormalTok{} group that fvextra will not break inside); fvextra
            // then wraps those verbatim lines. Inline paths carry zero-width
            // break hints (insert_break_hints); tighter margins + \sloppy let
            // prose reflow.
            cmd.arg("--no-highlight");
            cmd.args([
                "--variable=geometry:margin=0.85in",
                r"--variable=header-includes:\usepackage{fvextra}",
                r"--variable=header-includes:\DefineVerbatimEnvironment{verbatim}{Verbatim}{breaklines,breakanywhere}",
                r"--variable=header-includes:\fvset{breaklines=true,breakanywhere=true}",
                r"--variable=header-includes:\sloppy",
                r"--variable=header-includes:\emergencystretch=3em",
            ]);
        }
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| ClassifiedError::Internal(format!("pandoc not runnable: {e}")))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ClassifiedError::Internal("pandoc stdin unavailable".to_owned()))?;
        if let Err(e) = stdin.write_all(markdown.as_bytes()) {
            // pandoc exited early (broken pipe): reap it before returning so a
            // failed export does not leave an unwaited/zombie process behind.
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClassifiedError::Internal(format!("pandoc write: {e}")));
        }
    } // stdin dropped -> EOF so pandoc can finish
    let out = child
        .wait_with_output()
        .map_err(|e| ClassifiedError::Internal(format!("pandoc wait: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(ClassifiedError::Internal(format!(
            "pandoc export failed: {}",
            err.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_to_html_wraps_body_and_renders_tables() {
        let html = markdown_to_html(
            "# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n",
            "My Report",
            ReportLanguage::En,
        );
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<title>My Report</title>"));
        assert!(html.contains("<table>"));
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<html lang=\"en\">"));
    }

    #[test]
    fn html_declares_the_document_language() {
        // Assistive technology picks a voice from this attribute, and browsers
        // pick fonts and line-breaking rules from it, so a Chinese document
        // must not claim to be English.
        let zh = markdown_to_html("# 标题\n", "报告", ReportLanguage::Zh);
        assert!(
            zh.contains("<html lang=\"zh-CN\">"),
            "a Chinese document must declare zh-CN"
        );
        assert!(!zh.contains("<html lang=\"en\">"));

        let en = markdown_to_html("# Title\n", "Report", ReportLanguage::En);
        assert!(en.contains("<html lang=\"en\">"));
        assert!(!en.contains("zh-CN"));
    }

    #[test]
    fn write_html_carries_the_language_into_the_document() {
        // The exported file, not just the in-memory string: `write_report` is
        // what every export path calls.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.html");
        write_report("# Hi\n", "t", ReportFormat::Html, &path, ReportLanguage::Zh).unwrap();
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("<html lang=\"zh-CN\">"));
    }

    #[test]
    fn available_formats_always_includes_md_and_html() {
        let f = available_formats();
        assert!(f.contains(&"md".to_owned()));
        assert!(f.contains(&"html".to_owned()));
    }

    #[test]
    fn write_md_and_html_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let md = "# Hi\n\nbody\n";
        let mdp = dir.path().join("r.md");
        write_report(md, "t", ReportFormat::Md, &mdp, ReportLanguage::En).unwrap();
        assert_eq!(std::fs::read_to_string(&mdp).unwrap(), md);
        let htmlp = dir.path().join("r.html");
        write_report(md, "t", ReportFormat::Html, &htmlp, ReportLanguage::En).unwrap();
        let html = std::fs::read_to_string(&htmlp).unwrap();
        assert!(html.contains("<h1>Hi</h1>"));
    }

    #[test]
    fn sanitize_for_latex_maps_drawing_and_arrows_to_ascii() {
        let s = sanitize_for_latex("bar ░▒▓█ box ─│┼ arrow A→B ⇒ C");
        assert!(!s.chars().any(|c| ('\u{2500}'..='\u{259F}').contains(&c)));
        assert!(!s.contains('\u{2192}') && !s.contains('\u{21D2}'));
        assert!(s.contains("A->B"));
        assert!(s.contains("=>"));
        // Plain ASCII and normal text are untouched.
        assert!(s.contains("bar ") && s.contains("box ") && s.contains(" C"));
    }

    #[test]
    fn strip_mermaid_removes_blocks_but_keeps_surrounding_content() {
        let md = "Intro.\n\n```mermaid\nxychart-beta\n    bar [1, 2]\n```\n\nMiddle.\n\n\
                  ```mermaid\npie showData\n    \"A\" : 1\n```\n\nOutro.\n";
        let out = strip_mermaid_blocks(md);
        assert!(!out.contains("xychart-beta"), "mermaid source must be gone");
        assert!(!out.contains("pie showData"));
        assert!(!out.contains("```mermaid"));
        // Prose around the blocks is preserved.
        assert!(out.contains("Intro."));
        assert!(out.contains("Middle."));
        assert!(out.contains("Outro."));
    }

    #[test]
    fn strip_mermaid_leaves_non_mermaid_code_fences() {
        let md = "```text\nstack frame\n```\n\n```mermaid\npie\n```\n";
        let out = strip_mermaid_blocks(md);
        assert!(out.contains("```text"), "other code fences are kept");
        assert!(out.contains("stack frame"));
        assert!(!out.contains("```mermaid") && !out.contains("\npie\n"));
    }

    #[test]
    fn fence_aware_mermaid_stripping_ignores_short_and_nested_markers() {
        let markdown = "Before\n````mermaid\nchart\n```\nstill chart\n````\nAfter\n\
                        ~~~text\n```mermaid\nliteral\n```\n~~~\n";
        let output = strip_mermaid_blocks(markdown);

        assert!(!output.contains("chart\n```\nstill chart"));
        assert!(output.contains("Before\nAfter"));
        assert!(output.contains("~~~text\n```mermaid\nliteral\n```\n~~~"));
    }

    #[test]
    fn insert_break_hints_adds_zwsp_after_slashes_outside_fences() {
        let out = insert_break_hints("path `/a/b/c` here\n```text\n/no/hint/in/code\n```\n");
        // Prose/inline slashes get a zero-width space after them.
        assert!(out.contains("/\u{200B}a/\u{200B}b/\u{200B}c"));
        // Inside a fenced block, slashes are untouched (fvextra wraps those).
        assert!(out.contains("/no/hint/in/code"));
        assert!(!out.contains("/\u{200B}no"));
    }

    #[test]
    fn fence_aware_break_hints_skip_long_and_tilde_fences() {
        let output = insert_break_hints(
            "````text\n/long/fence\n```\n/still/in/fence\n````\n\
             ~~~text\n/tilde/fence\n~~~\n/outside/path\n",
        );

        assert!(output.contains("/long/fence"));
        assert!(output.contains("/still/in/fence"));
        assert!(output.contains("/tilde/fence"));
        assert!(!output.contains("/\u{200B}long"));
        assert!(!output.contains("/\u{200B}still"));
        assert!(!output.contains("/\u{200B}tilde"));
        assert!(output.contains("/\u{200B}outside/\u{200B}path"));
    }

    #[test]
    fn is_latex_engine_classifies_engines() {
        assert!(is_latex_engine("xelatex"));
        assert!(is_latex_engine("pdflatex"));
        assert!(!is_latex_engine("wkhtmltopdf"));
        assert!(!is_latex_engine("weasyprint"));
    }

    #[test]
    fn format_parse_and_ext() {
        assert_eq!(ReportFormat::parse("PDF"), Some(ReportFormat::Pdf));
        assert_eq!(ReportFormat::parse("markdown"), Some(ReportFormat::Md));
        assert_eq!(ReportFormat::parse("nope"), None);
        assert_eq!(ReportFormat::Docx.ext(), "docx");
    }
}
