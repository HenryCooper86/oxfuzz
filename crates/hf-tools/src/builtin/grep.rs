//! `Grep` built-in tool: powerful search tool built on ripgrep libraries.
//!
//! Uses `grep-searcher`, `grep-regex`, and `ignore` crates for performant,
//! in-process file content matching. Supports full regex syntax, file type
//! filtering, glob filtering, and multiline matching.
//!
//! Reference: cursor Grep.js tool implementation.

use std::collections::HashSet;

use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{MmapChoice, Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch};
use hf_core::grep_limits::GrepLimits;
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use ignore::WalkBuilder;

use hf_core::exec::RuntimeCapability;
use hf_core::tool::{
    Tool, ToolCategory, ToolDefinition, ToolError, ToolInput, ToolOutput, ToolType,
};
use hf_core::types::ToolName;

use super::path_utils::{resolve_read_path, DropGuard};

/// Default `head_limit` when unspecified.
const DEFAULT_HEAD_LIMIT: u64 = 250;

/// Built-in Grep tool for file content searching.
///
/// Accepts a regex `pattern` and multiple optional arguments like `path`, `glob`, `type`, etc.
/// Uses ripgrep library crates for fast, in-process file content searching.
pub struct GrepTool {
    def: ToolDefinition,
    limits: hf_core::grep_limits::GrepLimits,
    #[cfg(test)]
    worker_observer: Option<Arc<cancellation_tests::SearchObserver>>,
}

impl GrepTool {
    /// Create a new `GrepTool`.
    ///
    /// # Panics
    /// Panics if compiled default allowances are invalid.
    pub fn new() -> Self {
        Self {
            def: Self::tool_definition(),
            #[cfg(test)]
            worker_observer: None,
            limits: hf_core::grep_limits::GrepLimitsConfig::default()
                .resolve()
                .expect("valid Grep defaults"),
        }
    }

    /// Apply a validated deployment snapshot.
    #[must_use]
    pub fn with_limits(mut self, limits: hf_core::grep_limits::GrepLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The tool definition for `Grep`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: ToolName::from_string("Grep"),
            description: "A powerful search tool built on ripgrep.\n\n\
                Usage:\n\
                - ALWAYS use Grep for search tasks. NEVER invoke `Grep` or `rg` as a Bash command. The Grep tool has been optimized for correct permissions and access.\n\
                - Supports full regex syntax (e.g., \"log.*Error\", \"function\\\\s+\\\\w+\")\n\
                - Filter files with Glob parameter (e.g., \"*.js\", \"**/*.tsx\") or type parameter (e.g., \"js\", \"py\", \"rust\")\n\
                - Output modes: \"content\" shows matching lines, \"files_with_matches\" shows only file paths (default), \"count\" shows match counts\n\
                - Use Search tool for open-ended searches requiring multiple rounds\n\
                - Pattern syntax: Uses ripgrep (not grep) - literal braces need escaping (use `interface\\{\\}` to find `interface{}` in Go code)\n\
                - Multiline matching: By default patterns match within single lines only. For cross-line patterns like `struct \\{[\\s\\S]*?field`, use `multiline: true`"
                .into(),
            help: Some(
                "Use this tool to search file contents using regex.\n\
                 Provides functionality equivalent to ripgrep (rg)."
                    .into(),
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "The regular expression pattern to search for in file contents"
                    },
                    "path": {
                        "type": "string",
                        "description": "File or directory to search in (rg PATH). Defaults to the session workspace if available, otherwise the current working directory. Relative paths are resolved against the session workspace."
                    },
                    "Glob": {
                        "type": "string",
                        "description": "Glob pattern to filter files (e.g. \"*.js\", \"*.{ts,tsx}\") - maps to rg --glob"
                    },
                    "output_mode": {
                        "type": "string",
                        "enum": ["content", "files_with_matches", "count"],
                        "description": "Output mode: \"content\" shows matching records (supports -n line numbers, head_limit; context options are reserved and ignored), \"files_with_matches\" shows file paths (supports head_limit), \"count\" shows match counts (supports head_limit). Defaults to \"files_with_matches\"."
                    },
                    "-B": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Reserved context option; matching-record output ignores context events."
                    },
                    "-A": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Reserved context option; matching-record output ignores context events."
                    },
                    "-C": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Reserved context option; matching-record output ignores context events."
                    },
                    "context": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Reserved context option; matching-record output ignores context events."
                    },
                    "-n": {
                        "type": "boolean",
                        "description": "Show line numbers in output (rg -n). Requires output_mode: \"content\", ignored otherwise. Defaults to true."
                    },
                    "-i": {
                        "type": "boolean",
                        "description": "Case insensitive search (rg -i)"
                    },
                    "type": {
                        "type": "string",
                        "description": "File type to search (rg --type). Common types: js, py, rust, go, java, etc. More efficient than include for standard file types."
                    },
                    "head_limit": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Limit output to first N lines/entries, equivalent to \"| head -N\". Works across all output modes: content (limits output lines), files_with_matches (limits file paths), count (limits count entries). Defaults to 250 when unspecified. Pass 0 for no entry limit; the finite result byte allowance still applies."
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Skip first N lines/entries before applying head_limit, equivalent to \"| tail -n +N | head -N\". Works across all output modes. Defaults to 0."
                    },
                    "multiline": {
                        "type": "boolean",
                        "description": "Enable multiline mode where . matches newlines and patterns can span lines (rg -U --multiline-dotall). Default: false."
                    }
                },
                "required": ["pattern"]
            }),
            result_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "description": "Output mode used for formatting the result"
                    },
                    "numFiles": {
                        "type": "integer",
                        "description": "Number of matching files"
                    },
                    "filenames": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of matched file names, empty when mode is content or count"
                    },
                    "content": {
                        "type": "string",
                        "description": "Matched contents or aggregated output based on output format"
                    },
                    "numLines": {
                        "type": "integer",
                        "description": "Number of matched lines (content mode only)"
                    },
                    "numMatches": {
                        "type": "integer",
                        "description": "Total number of matches (count mode only)"
                    },
                    "truncated": { "type": "boolean", "description": "A page or byte allowance stopped output." },
                    "hasMore": { "type": "boolean", "description": "More entries or omitted record text may exist." },
                    "totalsComplete": { "type": "boolean", "description": "The whole search completed; otherwise totals are observed only." },
                    "numReturned": { "type": "integer" },
                    "nextOffset": { "type": "integer", "description": "Offset after consumed returned records; truncated content consumes its record." },
                    "limitingReason": { "type": ["string", "null"], "enum": ["head_limit", "output_bytes", null] },
                    "appliedLimit": {
                        "type": "integer",
                        "description": "The head_limit applied, if any"
                    },
                    "appliedOffset": {
                        "type": "integer",
                        "description": "The offset applied, if any"
                    }
                }
            })),
            category: ToolCategory::Search,
            tool_type: ToolType::BuiltIn,
            capabilities: RuntimeCapability::default(),
            is_dangerous: false,
        }
    }

    fn execute_search(
        params: &SearchParams,
        control: &SearchControl<'_>,
    ) -> Result<SearchPage, ToolError> {
        let search_path = Path::new(&params.search_path);
        let mut matcher_builder = RegexMatcherBuilder::new();
        matcher_builder.case_insensitive(params.case_insensitive);
        if params.multiline {
            matcher_builder.multi_line(true).dot_matches_new_line(true);
        }
        let matcher = matcher_builder
            .build(&params.pattern)
            .map_err(|_| search_error("invalid regex pattern"))?;
        let mut walk_builder = WalkBuilder::new(search_path);
        walk_builder.hidden(false).standard_filters(false);
        if let Some(glob) = &params.glob_filter {
            let mut builder = OverrideBuilder::new(search_path);
            builder
                .add(glob)
                .map_err(|_| search_error("invalid glob filter"))?;
            walk_builder.overrides(
                builder
                    .build()
                    .map_err(|_| search_error("invalid glob filter"))?,
            );
        }
        if let Some(file_type) = &params.type_filter {
            let mut builder = TypesBuilder::new();
            builder.add_defaults().select(file_type);
            walk_builder.types(
                builder
                    .build()
                    .map_err(|_| search_error("invalid file type"))?,
            );
        }
        let mut builder = SearcherBuilder::new();
        builder
            .multi_line(params.multiline)
            .line_number(params.show_line_numbers)
            .heap_limit(Some(params.limits.heap_bytes()))
            .memory_map(MmapChoice::never());
        if params.mode == "content" {
            let context_limit = params.limits.heap_bytes() as u64;
            let before = params
                .context
                .or(params.before_context)
                .unwrap_or(0)
                .min(context_limit);
            let after = params
                .context
                .or(params.after_context)
                .unwrap_or(0)
                .min(context_limit);
            builder
                .before_context(before as usize)
                .after_context(after as usize);
        }
        let mut searcher = builder.build();
        let mut page = SearchPage::new(params);
        let mut search_file = |path: &Path| -> Result<bool, ToolError> {
            control
                .check()
                .map_err(|error| control.tool_error(&error, params.limits))?;
            let file = std::fs::File::open(path)
                .map_err(|_| search_error("failed to open search file"))?;
            let reader = SearchReader {
                inner: file,
                control,
            };
            let path = path.to_string_lossy();
            let mut sink = MatchSink {
                params,
                matcher: &matcher,
                page: &mut page,
                control,
                path: &path,
                count: 0,
            };
            searcher
                .search_reader(&matcher, reader, &mut sink)
                .map_err(|error| control.tool_error(&error, params.limits))?;
            let count = sink.count;
            if params.mode == "count" && count > 0 {
                page.matches = page.matches.saturating_add(count);
                page.observed = page.observed.saturating_add(1);
                let count = count.to_string();
                page.retain(&[&path, ":", &count], &path, true)
                    .map_err(|error| control.tool_error(&error, params.limits))?;
            }
            Ok(page.stopped)
        };
        if search_path.is_file() {
            search_file(search_path)?;
        } else {
            for entry in walk_builder.build() {
                control
                    .check()
                    .map_err(|error| control.tool_error(&error, params.limits))?;
                let entry =
                    entry.map_err(|_| search_error("failed to traverse search directory"))?;
                // Directory enumeration excludes links and special files; explicit in-root links remain permitted.
                if entry.file_type().is_none_or(|kind| !kind.is_file()) {
                    continue;
                }
                if search_file(entry.path())? {
                    break;
                }
            }
        }
        control
            .check()
            .map_err(|error| control.tool_error(&error, params.limits))?;
        Ok(page)
    }
}

/// Parameters for the grep search, extracted from `ToolInput` for Send + 'static.
struct SearchParams {
    pattern: String,
    search_path: String,
    mode: String,
    case_insensitive: bool,
    multiline: bool,
    glob_filter: Option<String>,
    type_filter: Option<String>,
    show_line_numbers: bool,
    context: Option<u64>,
    before_context: Option<u64>,
    after_context: Option<u64>,
    offset: u64,
    head_limit: u64,
    limits: GrepLimits,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default = "default_mode", rename = "output_mode")]
    mode: String,
    #[serde(default, rename = "-i")]
    case_insensitive: bool,
    #[serde(default)]
    multiline: bool,
    #[serde(default, rename = "Glob")]
    glob_filter: Option<String>,
    #[serde(default, rename = "type")]
    type_filter: Option<String>,
    #[serde(default = "show_line_numbers", rename = "-n")]
    show_line_numbers: bool,
    #[serde(default)]
    context: Option<u64>,
    #[serde(default, rename = "-C")]
    context_alias: Option<u64>,
    #[serde(default, rename = "-B")]
    before_context: Option<u64>,
    #[serde(default, rename = "-A")]
    after_context: Option<u64>,
    #[serde(default)]
    offset: u64,
    #[serde(default = "default_head_limit")]
    head_limit: u64,
}
fn default_mode() -> String {
    "files_with_matches".into()
}
const fn show_line_numbers() -> bool {
    true
}
const fn default_head_limit() -> u64 {
    DEFAULT_HEAD_LIMIT
}

fn search_error(message: &str) -> ToolError {
    ToolError::RuntimeError {
        name: "Grep".into(),
        message: message.into(),
    }
}

struct SearchControl<'a> {
    cancelled: &'a AtomicBool,
    deadline: Instant,
    #[cfg(test)]
    observer: Option<Arc<cancellation_tests::SearchObserver>>,
}
impl SearchControl<'_> {
    fn check(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Relaxed) || Instant::now() >= self.deadline {
            // Interrupted would be retried by buffered readers.
            return Err(io::Error::other("search interrupted"));
        }
        Ok(())
    }
    fn tool_error(&self, error: &io::Error, limits: GrepLimits) -> ToolError {
        if Instant::now() >= self.deadline {
            ToolError::Timeout {
                timeout_secs: limits.timeout_secs(),
            }
        } else if self.cancelled.load(Ordering::Relaxed) {
            ToolError::Cancelled
        } else {
            search_error(&format!("search failed: {error}"))
        }
    }
}
struct SearchReader<'a, R> {
    inner: R,
    control: &'a SearchControl<'a>,
}
impl<R: Read> Read for SearchReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.control.check()?;
        #[cfg(test)]
        if let Some(observer) = &self.control.observer {
            observer.pause_before_read();
        }
        self.inner.read(buffer)
    }
}

struct SearchPage {
    mode: String,
    output: String,
    filenames: Vec<String>,
    represented_files: HashSet<String>,
    observed: u64,
    matches: u64,
    returned: u64,
    used_bytes: usize,
    budget: usize,
    offset: u64,
    head_limit: u64,
    stopped: bool,
    limiting_reason: Option<&'static str>,
}
impl SearchPage {
    fn new(params: &SearchParams) -> Self {
        Self {
            mode: params.mode.clone(),
            output: String::new(),
            filenames: Vec::new(),
            represented_files: HashSet::new(),
            observed: 0,
            matches: 0,
            returned: 0,
            used_bytes: 0,
            budget: params.limits.output_bytes(),
            offset: params.offset,
            head_limit: params.head_limit,
            stopped: false,
            limiting_reason: None,
        }
    }
    fn stop(&mut self, reason: &'static str) -> bool {
        self.stopped = true;
        self.limiting_reason = Some(reason);
        false
    }
    fn retain(&mut self, parts: &[&str], path: &str, atomic: bool) -> io::Result<bool> {
        if self.observed <= self.offset {
            return Ok(true);
        }
        if self.head_limit != 0 && self.returned >= self.head_limit {
            return Ok(self.stop("head_limit"));
        }
        let separator = usize::from(self.returned > 0);
        let length = parts
            .iter()
            .fold(0usize, |total, part| total.saturating_add(part.len()));
        let remaining = self.budget - self.used_bytes;
        if atomic && length.saturating_add(separator) > remaining {
            if length > self.budget {
                return Err(io::Error::other(
                    "result entry exceeds output_bytes; raise the allowance or narrow the query",
                ));
            }
            return Ok(self.stop("output_bytes"));
        }
        if remaining <= separator {
            return Ok(self.stop("output_bytes"));
        }
        if separator > 0 && self.mode != "files_with_matches" {
            self.output.push('\n');
        }
        let mut available = remaining - separator;
        let mut retained = String::new();
        for part in parts {
            let mut end = part.len().min(available);
            while !part.is_char_boundary(end) {
                end -= 1;
            }
            retained.push_str(&part[..end]);
            available -= end;
            if end < part.len() {
                break;
            }
        }
        self.used_bytes += retained.len() + separator;
        self.returned = self.returned.saturating_add(1);
        if self.mode == "files_with_matches" {
            self.filenames.push(retained);
        } else {
            self.output.push_str(&retained);
        }
        if self.mode == "content" {
            self.represented_files.insert(path.to_owned());
        }
        if length > remaining - separator {
            return Ok(self.stop("output_bytes"));
        }
        Ok(true)
    }
    fn into_content(self) -> serde_json::Value {
        let mut content = serde_json::json!({
            "mode": self.mode, "numFiles": if self.mode == "content" { self.represented_files.len() as u64 } else { self.observed },
            "appliedLimit":self.head_limit, "appliedOffset":self.offset,
            "truncated":self.stopped, "hasMore":self.stopped, "totalsComplete":!self.stopped,
            "numReturned":self.returned, "nextOffset":self.offset.saturating_add(self.returned), "limitingReason":self.limiting_reason,
        });
        if self.mode == "files_with_matches" {
            content["filenames"] = serde_json::json!(self.filenames);
        } else {
            content["content"] = serde_json::json!(self.output);
        }
        if self.mode == "content" {
            content["numLines"] = serde_json::json!(self.observed);
        }
        if self.mode == "count" {
            content["numMatches"] = serde_json::json!(self.matches);
        }
        content
    }
}

struct MatchSink<'a> {
    params: &'a SearchParams,
    matcher: &'a grep_regex::RegexMatcher,
    page: &'a mut SearchPage,
    control: &'a SearchControl<'a>,
    path: &'a str,
    count: u64,
}
impl Sink for MatchSink<'_> {
    type Error = io::Error;
    fn matched(&mut self, _: &Searcher, matched: &SinkMatch<'_>) -> io::Result<bool> {
        self.control.check()?;
        match self.params.mode.as_str() {
            "files_with_matches" => {
                self.page.observed = self.page.observed.saturating_add(1);
                self.page.retain(&[self.path], self.path, true)?;
                Ok(false)
            }
            "count" => {
                let mut interrupted = false;
                self.matcher
                    .find_iter(matched.bytes(), |_| {
                        if self.control.check().is_err() {
                            interrupted = true;
                            return false;
                        }
                        self.count = self.count.saturating_add(1);
                        true
                    })
                    .map_err(|_| io::Error::other("failed to count matches"))?;
                if interrupted {
                    self.control.check()?;
                }
                Ok(true)
            }
            _ => {
                let line = std::str::from_utf8(matched.bytes())
                    .map_err(|_| io::Error::other("matching text is not UTF-8"))?
                    .trim_end_matches('\n');
                self.page.observed = self.page.observed.saturating_add(1);
                if self.params.show_line_numbers {
                    let number = matched
                        .line_number()
                        .expect("line numbers enabled")
                        .to_string();
                    self.page
                        .retain(&[self.path, ":", &number, ":", line], self.path, false)
                } else {
                    self.page.retain(&[self.path, ":", line], self.path, false)
                }
            }
        }
    }
    fn context(&mut self, _: &Searcher, _: &SinkContext<'_>) -> io::Result<bool> {
        self.control.check()?;
        Ok(!self.page.stopped)
    }
}

impl Default for GrepTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for GrepTool {
    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError> {
        for key in ["head_limit", "offset", "-B", "-A", "-C", "context"] {
            if input
                .arguments
                .get(key)
                .is_some_and(|value| value.as_u64().is_none())
            {
                return Err(ToolError::ValidationError {
                    message: format!("{key} must be a nonnegative integer"),
                });
            }
        }
        let request: SearchRequest =
            serde_json::from_value(input.arguments).map_err(|_| ToolError::ValidationError {
                message: "invalid Grep arguments; numeric values must be nonnegative integers"
                    .into(),
            })?;
        if !["content", "count", "files_with_matches"].contains(&request.mode.as_str()) {
            return Err(ToolError::ValidationError {
                message: "invalid Grep output_mode".into(),
            });
        }
        let search_path = resolve_read_path(
            "Grep",
            request.path.as_deref().filter(|path| !path.is_empty()),
            input.working_dir.as_deref(),
            &input.additional_read_dirs,
        )?
        .to_string_lossy()
        .into_owned();
        let params = SearchParams {
            pattern: request.pattern,
            search_path,
            mode: request.mode,
            case_insensitive: request.case_insensitive,
            multiline: request.multiline,
            glob_filter: request.glob_filter,
            type_filter: request.type_filter,
            show_line_numbers: request.show_line_numbers,
            context: request.context.or(request.context_alias),
            before_context: request.before_context,
            after_context: request.after_context,
            offset: request.offset,
            head_limit: request.head_limit,
            limits: self.limits,
        };
        let timeout = Duration::from_secs(self.limits.timeout_secs());
        let deadline = Instant::now() + timeout;
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let guard = DropGuard(Some(cancelled));
        #[cfg(test)]
        let observer = self.worker_observer.clone();
        let page = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || {
                let control = SearchControl {
                    cancelled: &worker_cancelled,
                    deadline,
                    #[cfg(test)]
                    observer,
                };
                let result = Self::execute_search(&params, &control);
                #[cfg(test)]
                if let Some(observer) = &control.observer {
                    observer
                        .worker_finished(worker_cancelled.load(Ordering::Relaxed), result.is_ok());
                }
                result
            }),
        )
        .await
        .map_err(|_| ToolError::Timeout {
            timeout_secs: self.limits.timeout_secs(),
        })?
        .map_err(|_| search_error("search worker failed"))??;
        drop(guard);
        Ok(ToolOutput {
            success: true,
            content: page.into_content(),
            warnings: vec![],
            metadata: serde_json::json!({}),
        })
    }

    fn definition(&self) -> &ToolDefinition {
        &self.def
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::io::Read;
    pub(super) struct SearchObserver {
        started: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        finished: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<(bool, bool)>>>,
    }

    impl SearchObserver {
        pub(super) fn pause_before_read(&self) {
            if let Some(started) = self.started.lock().unwrap().take() {
                started.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
        }
        pub(super) fn worker_finished(&self, cancelled: bool, succeeded: bool) {
            self.finished
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send((cancelled, succeeded))
                .unwrap();
        }
    }

    async fn exercise_executor_worker_exit(caller_drop: bool) {
        use crate::{ToolExecutor, ToolRegistryConfig, ToolRegistryImpl};
        use hf_core::types::SessionId;
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("source.txt"), "needle\n").unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let observer = Arc::new(SearchObserver {
            started: std::sync::Mutex::new(Some(started_tx)),
            resume: std::sync::Mutex::new(resume_rx),
            finished: std::sync::Mutex::new(Some(finished_tx)),
        });
        let mut tool = GrepTool::new().with_limits(
            hf_core::grep_limits::GrepLimitsConfig {
                timeout_secs: if caller_drop { 30 } else { 2 },
                ..Default::default()
            }
            .resolve()
            .unwrap(),
        );
        tool.worker_observer = Some(observer);
        let registry = Arc::new(ToolRegistryImpl::new(ToolRegistryConfig::default()));
        let definition = tool.definition().clone();
        registry
            .register_tool(Arc::new(tool), definition)
            .await
            .unwrap();
        let working_dir = project.path().display().to_string();
        let pending = tokio::spawn(async move {
            ToolExecutor::new().execute(&registry, &ToolName::from_string("Grep"), ToolInput {
                call_id:"worker-exit".into(), name:ToolName::from_string("Grep"),
                arguments:serde_json::json!({"pattern":"needle","path":"source.txt","output_mode":"content"}),
                session_id:SessionId::new(), working_dir:Some(working_dir), additional_read_dirs:vec![], command_runner:None,
            }).await
        });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        if caller_drop {
            pending.abort();
            assert!(pending.await.unwrap_err().is_cancelled());
        } else {
            let error = tokio::time::timeout(Duration::from_secs(4), pending)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert!(error.to_string().contains("timed out"), "{error}");
        }
        resume_tx.send(()).unwrap();
        let (cancelled, succeeded) = tokio::time::timeout(Duration::from_secs(5), finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            cancelled,
            "the dropped executor future did not signal its worker"
        );
        assert!(
            !succeeded,
            "the worker continued its file search after cancellation"
        );
    }

    #[tokio::test]
    async fn executor_caller_drop_stops_single_file_worker() {
        exercise_executor_worker_exit(true).await;
    }

    #[tokio::test]
    async fn executor_timeout_stops_single_file_worker() {
        exercise_executor_worker_exit(false).await;
    }

    #[test]
    fn buffered_matches_observe_cancellation_in_every_mode() {
        struct CancelOnRead<'a>(&'a AtomicBool, usize);
        impl Read for CancelOnRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let bytes = b"needle needle\nneedle\n";
                let count = buffer.len().min(bytes.len() - self.1);
                buffer[..count].copy_from_slice(&bytes[self.1..self.1 + count]);
                self.1 += count;
                if self.1 == bytes.len() {
                    self.0.store(true, Ordering::Relaxed);
                }
                Ok(count)
            }
        }
        for mode in ["content", "count", "files_with_matches"] {
            let cancelled = AtomicBool::new(false);
            let control = SearchControl {
                cancelled: &cancelled,
                deadline: Instant::now() + Duration::from_secs(1),
                observer: None,
            };
            let params = SearchParams {
                pattern: "needle".into(),
                search_path: "text".into(),
                mode: mode.into(),
                case_insensitive: false,
                multiline: false,
                glob_filter: None,
                type_filter: None,
                show_line_numbers: true,
                context: None,
                before_context: None,
                after_context: None,
                offset: 0,
                head_limit: 0,
                limits: hf_core::grep_limits::GrepLimitsConfig::default()
                    .resolve()
                    .unwrap(),
            };
            let mut page = SearchPage::new(&params);
            let matcher = RegexMatcherBuilder::new().build("needle").unwrap();
            let mut sink = MatchSink {
                params: &params,
                matcher: &matcher,
                page: &mut page,
                control: &control,
                path: "text",
                count: 0,
            };
            let result = SearcherBuilder::new().build().search_reader(
                &matcher,
                SearchReader {
                    inner: CancelOnRead(&cancelled, 0),
                    control: &control,
                },
                &mut sink,
            );
            assert!(result.is_err(), "{mode}");
            assert_eq!(sink.count, 0);
            assert_eq!(page.observed, 0);
        }
    }

    #[test]
    fn reader_checks_cancellation_and_deadline_before_touching_input() {
        struct MustNotRead;
        impl Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("underlying read reached");
            }
        }
        let cancelled = AtomicBool::new(true);
        let control = SearchControl {
            cancelled: &cancelled,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
            observer: None,
        };
        assert!(SearchReader {
            inner: MustNotRead,
            control: &control
        }
        .read(&mut [0; 1])
        .is_err());
        cancelled.store(false, Ordering::Relaxed);
        let expired = SearchControl {
            cancelled: &cancelled,
            deadline: std::time::Instant::now(),
            observer: None,
        };
        assert!(SearchReader {
            inner: MustNotRead,
            control: &expired
        }
        .read(&mut [0; 1])
        .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::types::SessionId;
    use std::path::PathBuf;

    fn make_input(args: serde_json::Value) -> ToolInput {
        ToolInput {
            call_id: "call_grep_001".into(),
            name: ToolName::from_string("Grep"),
            arguments: args,
            session_id: SessionId::new(),
            working_dir: None,
            additional_read_dirs: vec![],
            command_runner: None,
        }
    }

    fn make_input_with_working_dir(args: serde_json::Value, working_dir: &Path) -> ToolInput {
        let mut input = make_input(args);
        input.working_dir = Some(working_dir.display().to_string());
        input
    }

    fn target_test_dir() -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/y-tools-tests/grep-outside");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn test_grep_basic_pattern() {
        let tool = GrepTool::new();
        let input = make_input(serde_json::json!({"pattern": "fn main"}));
        let output = tool.execute(input).await.unwrap();
        assert!(output.success);
        // Default mode is files_with_matches.
        assert_eq!(output.content["mode"], "files_with_matches");
    }

    #[tokio::test]
    async fn test_grep_content_mode() {
        let tool = GrepTool::new();
        let input = make_input(serde_json::json!({
            "pattern": "fn main",
            "output_mode": "content"
        }));
        let output = tool.execute(input).await.unwrap();
        assert!(output.success);
        assert_eq!(output.content["mode"], "content");
    }

    #[tokio::test]
    async fn test_grep_defaults_to_injected_working_dir() {
        let workspace = tempfile::tempdir().unwrap();
        let file_path = workspace.path().join("__grep_working_dir_unique__.txt");
        std::fs::write(&file_path, "needle_from_injected_workspace").unwrap();

        let tool = GrepTool::new();
        let input = make_input_with_working_dir(
            serde_json::json!({"pattern": "needle_from_injected_workspace"}),
            workspace.path(),
        );
        let output = tool.execute(input).await.unwrap();

        assert!(output.success);
        assert_eq!(output.content["numFiles"], 1);
        assert_eq!(
            output.content["filenames"][0],
            file_path.display().to_string()
        );
    }

    #[tokio::test]
    async fn test_grep_resolves_relative_path_against_working_dir() {
        let workspace = tempfile::tempdir().unwrap();
        let file_path = workspace
            .path()
            .join("website")
            .join("__grep_relative_path_unique__.txt");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        std::fs::write(&file_path, "needle_from_relative_path").unwrap();

        let tool = GrepTool::new();
        let input = make_input_with_working_dir(
            serde_json::json!({
                "pattern": "needle_from_relative_path",
                "path": "website"
            }),
            workspace.path(),
        );
        let output = tool.execute(input).await.unwrap();

        assert!(output.success);
        assert_eq!(output.content["numFiles"], 1);
        assert_eq!(
            output.content["filenames"][0],
            file_path.display().to_string()
        );
    }

    #[tokio::test]
    async fn test_grep_rejects_search_outside_working_dir() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::Builder::new()
            .prefix("outside-")
            .tempdir_in(target_test_dir())
            .unwrap();
        let outside_file = outside.path().join("__grep_outside_unique__.txt");
        std::fs::write(&outside_file, "needle_outside_workspace").unwrap();

        let tool = GrepTool::new();
        let input = make_input_with_working_dir(
            serde_json::json!({
                "pattern": "needle_outside_workspace",
                "path": outside.path().display().to_string()
            }),
            workspace.path(),
        );
        let result = tool.execute(input).await;

        assert!(matches!(
            result,
            Err(ToolError::PermissionDenied { name, .. }) if name == "Grep"
        ));
    }

    #[tokio::test]
    async fn test_grep_missing_pattern_fails() {
        let tool = GrepTool::new();
        let input = make_input(serde_json::json!({}));
        let result = tool.execute(input).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_grep_definition() {
        let def = GrepTool::tool_definition();
        assert_eq!(def.name.as_str(), "Grep");
        assert_eq!(def.category, ToolCategory::Search);
        assert_eq!(def.tool_type, ToolType::BuiltIn);
        assert!(!def.is_dangerous);
        let props = def.parameters["properties"].as_object().unwrap();
        assert!(props.contains_key("pattern"));
        assert!(props.contains_key("path"));
        assert!(props.contains_key("Glob"));
        assert!(props.contains_key("output_mode"));
        assert!(props.contains_key("-B"));
        let required = def.parameters["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("pattern")));
    }

    #[test]
    fn test_build_rg_args_content_with_context() {
        // Verify that context parameters are properly parsed.
        let input = make_input(serde_json::json!({
            "pattern": "test",
            "-B": 3,
            "-A": 5
        }));
        let before = input
            .arguments
            .get("-B")
            .and_then(serde_json::Value::as_u64);
        let after = input
            .arguments
            .get("-A")
            .and_then(serde_json::Value::as_u64);
        assert_eq!(before, Some(3));
        assert_eq!(after, Some(5));
    }
}
