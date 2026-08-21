//! Running compiled queries over a parsed translation unit.

use streaming_iterator::StreamingIterator as _;
use tree_sitter::{Node, Query, QueryCursor, Tree};

use crate::catalog::Rule;
use crate::finding::{Finding, SourceSpan};

/// The capture every rule marks as the span to report.
const HIT_CAPTURE: &str = "hit";

/// Collect the findings one rule produces for one tree.
///
/// A rule that declares no `@hit` capture yields nothing rather than reporting
/// an arbitrary node: the reported span is what the enrichment join uses to
/// attribute a signal to a candidate, so guessing it would silently misattribute
/// the boost.
pub(crate) fn run_rule(
    rule: &'static Rule,
    query: &Query,
    tree: &Tree,
    source: &str,
    out: &mut Vec<Finding>,
) {
    let Some(hit_index) = query.capture_index_for_name(HIT_CAPTURE) else {
        return;
    };
    let mut cursor = QueryCursor::new();
    // `QueryCursor::matches` returns a StreamingIterator, not an Iterator, so a
    // plain `for` loop does not compile here.
    let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
    while let Some(matched) = matches.next() {
        for capture in matched.captures {
            if capture.index == hit_index {
                out.push(Finding {
                    rule_id: rule.id,
                    cwe: rule.cwe,
                    severity: rule.severity,
                    span: span_of(capture.node),
                });
            }
        }
    }
}

/// Convert a node's position into a reportable span.
///
/// tree-sitter rows are zero-based and the enrichment join compares one-based
/// lines, so rows are shifted by one. Columns stay zero-based, matching the
/// range shape already in use.
fn span_of(node: Node) -> SourceSpan {
    let start = node.start_position();
    let end = node.end_position();
    SourceSpan {
        start_line: u32::try_from(start.row)
            .unwrap_or(u32::MAX)
            .saturating_add(1),
        start_col: u32::try_from(start.column).unwrap_or(u32::MAX),
        end_line: u32::try_from(end.row).unwrap_or(u32::MAX).saturating_add(1),
        end_col: u32::try_from(end.column).unwrap_or(u32::MAX),
    }
}
