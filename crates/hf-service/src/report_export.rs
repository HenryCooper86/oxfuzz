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
/// # Errors
/// Returns an error on IO failure, or when a required external tool (pandoc, or
/// a PDF engine) is unavailable for the requested format.
pub fn write_report(
    markdown: &str,
    title: &str,
    format: ReportFormat,
    out_path: &Path,
) -> Result<(), ClassifiedError> {
    match format {
        ReportFormat::Md => std::fs::write(out_path, markdown)
            .map_err(|e| ClassifiedError::Internal(format!("write report: {e}"))),
        ReportFormat::Html => std::fs::write(out_path, markdown_to_html(markdown, title))
            .map_err(|e| ClassifiedError::Internal(format!("write report: {e}"))),
        ReportFormat::Docx => pandoc_convert(markdown, out_path, None),
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
            // PDF renders cleanly. MD/HTML/DOCX keep the original glyphs.
            pandoc_convert(&sanitize_for_latex(markdown), out_path, Some(engine))
        }
    }
}

/// Convert Markdown to a standalone, styled HTML document (pure Rust, GFM).
#[must_use]
pub fn markdown_to_html(markdown: &str, title: &str) -> String {
    let mut opts = comrak::Options::default();
    opts.extension.table = true;
    opts.extension.strikethrough = true;
    opts.extension.autolink = true;
    opts.extension.tasklist = true;
    let body = comrak::markdown_to_html(markdown, &opts);
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n<style>{REPORT_CSS}</style>\n</head>\n<body>\n\
         <main class=\"report\">\n{body}\n</main>\n</body>\n</html>\n",
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
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;background:#f4f4f5;padding:.15em .35em;border-radius:4px}\
pre{background:#f6f8fa;border:1px solid #e5e5e5;border-radius:8px;padding:14px;overflow:auto}\
pre code{background:none;padding:0}\
table{border-collapse:collapse;width:100%;margin:1em 0}\
th,td{border:1px solid #e0e0e0;padding:8px 12px;text-align:left}\
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

fn tool_on_path(tool: &str) -> bool {
    Command::new(tool)
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
    let mut cmd = Command::new("pandoc");
    cmd.arg("-f")
        .arg("gfm")
        .arg("--standalone")
        .arg("-o")
        .arg(out_path);
    if let Some(engine) = pdf_engine {
        cmd.arg(format!("--pdf-engine={engine}"));
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
        stdin
            .write_all(markdown.as_bytes())
            .map_err(|e| ClassifiedError::Internal(format!("pandoc write: {e}")))?;
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
        let html = markdown_to_html("# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n", "My Report");
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<title>My Report</title>"));
        assert!(html.contains("<table>"));
        assert!(html.contains("<h1>Title</h1>"));
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
        write_report(md, "t", ReportFormat::Md, &mdp).unwrap();
        assert_eq!(std::fs::read_to_string(&mdp).unwrap(), md);
        let htmlp = dir.path().join("r.html");
        write_report(md, "t", ReportFormat::Html, &htmlp).unwrap();
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
    fn format_parse_and_ext() {
        assert_eq!(ReportFormat::parse("PDF"), Some(ReportFormat::Pdf));
        assert_eq!(ReportFormat::parse("markdown"), Some(ReportFormat::Md));
        assert_eq!(ReportFormat::parse("nope"), None);
        assert_eq!(ReportFormat::Docx.ext(), "docx");
    }
}
