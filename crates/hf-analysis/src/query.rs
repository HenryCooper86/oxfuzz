//! Running compiled queries over a parsed translation unit.

use streaming_iterator::StreamingIterator as _;
use tree_sitter::{Node, Query, QueryCursor, Tree};

use crate::catalog::{Rule, RuleKind};
use crate::finding::{Finding, SourceSpan};
use crate::sequence::{enclosing_statement, is_killed, statements_between};

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
    match rule.kind {
        RuleKind::Shape => run_shape_rule(rule, query, tree, source, out),
        RuleKind::PairedSites => run_paired_sites_rule(rule, query, tree, source, out),
        RuleKind::AfterEvent => run_after_event_rule(rule, query, tree, source, out),
        RuleKind::TaintedArgument => run_tainted_argument_rule(rule, query, tree, source, out),
    }
}

/// Report `@hit` only where `@var` names a parameter of the enclosing function.
fn run_tainted_argument_rule(
    rule: &'static Rule,
    query: &Query,
    tree: &Tree,
    source: &str,
    out: &mut Vec<Finding>,
) {
    let (Some(hit_index), Some(var_index)) = (
        query.capture_index_for_name(HIT_CAPTURE),
        query.capture_index_for_name(VAR_CAPTURE),
    ) else {
        return;
    };
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
    while let Some(matched) = matches.next() {
        let variable = matched
            .captures
            .iter()
            .find(|capture| capture.index == var_index)
            .and_then(|capture| capture.node.utf8_text(source.as_bytes()).ok());
        let hit = matched
            .captures
            .iter()
            .find(|capture| capture.index == hit_index)
            .map(|capture| capture.node);
        if let (Some(variable), Some(hit)) = (variable, hit) {
            if crate::context::is_attacker_influenced(hit, source, variable) {
                out.push(Finding {
                    rule_id: rule.id,
                    cwe: rule.cwe,
                    severity: rule.severity,
                    span: span_of(hit),
                });
            }
        }
    }
}

/// The capture naming the event a later site is measured against.
const ORIGIN_CAPTURE: &str = "origin";

/// Report the first site that follows an origin binding the same variable.
///
/// A site that is the target of an assignment is skipped: `p = NULL` after a
/// free is the recommended fix, and counting it as a use would fire the rule on
/// exactly the code it should encourage. A site inside the origin itself is
/// skipped too, since the origin necessarily mentions the variable.
fn run_after_event_rule(
    rule: &'static Rule,
    query: &Query,
    tree: &Tree,
    source: &str,
    out: &mut Vec<Finding>,
) {
    let (Some(origin_index), Some(site_index), Some(var_index)) = (
        query.capture_index_for_name(ORIGIN_CAPTURE),
        query.capture_index_for_name(SITE_CAPTURE),
        query.capture_index_for_name(VAR_CAPTURE),
    ) else {
        return;
    };

    let mut origins: std::collections::BTreeMap<String, Vec<Node>> =
        std::collections::BTreeMap::new();
    let mut sites: std::collections::BTreeMap<String, Vec<Node>> =
        std::collections::BTreeMap::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
    while let Some(matched) = matches.next() {
        let variable = matched
            .captures
            .iter()
            .find(|capture| capture.index == var_index)
            .and_then(|capture| capture.node.utf8_text(source.as_bytes()).ok());
        let Some(variable) = variable else { continue };
        for capture in matched.captures {
            if capture.index == origin_index {
                origins
                    .entry(variable.to_owned())
                    .or_default()
                    .push(capture.node);
            } else if capture.index == site_index && !is_assignment_target(capture.node) {
                sites
                    .entry(variable.to_owned())
                    .or_default()
                    .push(capture.node);
            }
        }
    }

    for (variable, mut variable_origins) in origins {
        let Some(variable_sites) = sites.get(&variable) else {
            continue;
        };
        let mut variable_sites = variable_sites.clone();
        variable_origins.sort_by_key(Node::start_byte);
        variable_sites.sort_by_key(Node::start_byte);
        for origin in variable_origins {
            let Some(site) = variable_sites
                .iter()
                .find(|site| site.start_byte() >= origin.end_byte())
            else {
                continue;
            };
            let (Some((origin_block, origin_index)), Some((site_block, site_index))) =
                (enclosing_statement(origin), enclosing_statement(*site))
            else {
                continue;
            };
            if origin_block.id() != site_block.id() {
                continue;
            }
            let between = statements_between(origin_block, origin_index, site_index);
            if !is_killed(&between, source, &variable) {
                out.push(Finding {
                    rule_id: rule.id,
                    cwe: rule.cwe,
                    severity: rule.severity,
                    span: span_of(*site),
                });
            }
        }
    }
}

/// Whether a node is the left-hand side of an assignment.
fn is_assignment_target(node: Node) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "assignment_expression"
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| left.id() == node.id())
    })
}

/// The capture naming the variable two sites must share.
const VAR_CAPTURE: &str = "var";
/// The capture naming a participating site in a paired-site rule.
const SITE_CAPTURE: &str = "site";

/// Report two sites binding the same variable, in one block, with nothing
/// between them that could have changed what the variable refers to.
///
/// The *second* site is reported: it is the defect, and pointing a reader at
/// the first would point them at correct code.
fn run_paired_sites_rule(
    rule: &'static Rule,
    query: &Query,
    tree: &Tree,
    source: &str,
    out: &mut Vec<Finding>,
) {
    let (Some(site_index), Some(var_index)) = (
        query.capture_index_for_name(SITE_CAPTURE),
        query.capture_index_for_name(VAR_CAPTURE),
    ) else {
        return;
    };

    // Sites grouped by the variable text they bind, in source order.
    let mut by_variable: std::collections::BTreeMap<String, Vec<Node>> =
        std::collections::BTreeMap::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
    while let Some(matched) = matches.next() {
        let site = matched
            .captures
            .iter()
            .find(|capture| capture.index == site_index)
            .map(|capture| capture.node);
        let variable = matched
            .captures
            .iter()
            .find(|capture| capture.index == var_index)
            .and_then(|capture| capture.node.utf8_text(source.as_bytes()).ok());
        if let (Some(site), Some(variable)) = (site, variable) {
            by_variable
                .entry(variable.to_owned())
                .or_default()
                .push(site);
        }
    }

    for (variable, mut sites) in by_variable {
        sites.sort_by_key(Node::start_byte);
        for pair in sites.windows(2) {
            let (Some((first_block, first)), Some((second_block, second))) =
                (enclosing_statement(pair[0]), enclosing_statement(pair[1]))
            else {
                continue;
            };
            // Different blocks means the pass cannot judge the ordering, so it
            // stays silent rather than guessing.
            if first_block.id() != second_block.id() {
                continue;
            }
            let between = statements_between(first_block, first, second);
            if !is_killed(&between, source, &variable) {
                out.push(Finding {
                    rule_id: rule.id,
                    cwe: rule.cwe,
                    severity: rule.severity,
                    span: span_of(pair[1]),
                });
            }
        }
    }
}

/// Report every `@hit` capture.
fn run_shape_rule(
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

/// Put findings in a stable, source-order-independent sequence.
///
/// Ordered by position, then rule id, so the same source always yields the same
/// list regardless of which order the rules ran in or which order tree-sitter
/// returned matches. A non-deterministic overlay would make a ranking
/// comparison between two producers unreadable.
///
/// Duplicates are removed after sorting: one rule can match the same node twice
/// when its query admits overlapping bindings, and distinct-rule counting drives
/// the boost, so a repeat must not inflate it. Two different rules at one
/// position are both kept, because that is two distinct rules.
pub(crate) fn order_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        a.span
            .start_line
            .cmp(&b.span.start_line)
            .then(a.span.start_col.cmp(&b.span.start_col))
            .then(a.rule_id.cmp(b.rule_id))
    });
    findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id
            && a.span.start_line == b.span.start_line
            && a.span.start_col == b.span.start_col
    });
}
