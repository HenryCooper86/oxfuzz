#![cfg(feature = "automotive-scapy")]

//! Automotive campaign report rendering, in both label sets.
//!
//! The four fixtures below between them exercise every branch of
//! `render_automotive_report` and its seven helpers, and every field of
//! `AutomotiveLabels` renders in at least one of them:
//!
//! - `populated` -- one done and one failed operation, one promoted state.
//! - `empty` -- no operations, no state corpus, a disabled runtime policy,
//!   empty protocol and mode allowlists, every stage not recorded, all four
//!   `Next,` recommendations, and a project name carrying a backtick and a pipe
//!   so the escape path runs.
//! - `complete` -- every stage done including the virtual-CAN replay, no
//!   failures, every observed state promoted, the bench enabled with a fresh
//!   approval required, dangerous services exceptionally allowed, and the
//!   single-recommendation path.
//! - `mixed` -- the invalid enabled-without-approval bench posture, running,
//!   cancelled, partial and failed operations, an absent protocol, transcript,
//!   result summary and error detail, and the unpromoted-state recommendation.
//!
//! `tests/fixtures/automotive_report/*.en.md` are the renderings this report
//! produced before any localization work began. Comparing against them is the
//! byte-for-byte proof that extracting every literal into `AutomotiveLabels`
//! and adding a second language did not move the English document.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone as _, Utc};
use hf_automotive::{AutomotiveProtocol, StateSignature};
use hf_service::automotive::AutomotiveStateCorpusEntry;
use hf_service::automotive_report::{
    append_ai_interpretation, automotive_report_system_prompt, automotive_report_user_prompt,
    render_automotive_report, validate_ai_interpretation, AutomotiveDangerousServicesPosture,
    AutomotiveLabels, AutomotivePhysicalBenchPosture, AutomotivePolicyPosture,
    AutomotiveReportData, AutomotiveReportOperation, AutomotiveReportSafetyPosture,
};
use hf_service::report::ReportLanguage;
use hf_storage::AutomotiveOperationStatus;
use uuid::Uuid;

const OPERATION_ID: Uuid = Uuid::from_u128(0x11111111_2222_3333_4444_555555555555);
const FAILED_OPERATION_ID: Uuid = Uuid::from_u128(0xaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee);
const STATE_DIGEST: &str = "abababababababababababababababababababababababababababababababab";
const REQUEST_DIGEST: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const TRANSCRIPT_DIGEST: &str = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

fn state_signature() -> StateSignature {
    StateSignature::from_observations(
        AutomotiveProtocol::Uds,
        BTreeMap::from([("session".to_owned(), "extended".to_owned())]),
    )
    .unwrap()
}

fn started() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 16, 8, 0, 0).unwrap()
}

fn report_data() -> AutomotiveReportData {
    let started_at = started();
    AutomotiveReportData {
        generated_at: "2026-07-16T09:00:00Z".to_owned(),
        project_name: "vehicle-gateway".to_owned(),
        tool_version: "0.1.0".to_owned(),
        safety: AutomotiveReportSafetyPosture {
            runtime_policy: AutomotivePolicyPosture::Enabled,
            allowed_protocols: vec!["can".to_owned(), "uds".to_owned()],
            allowed_modes: vec!["offline_pcap".to_owned(), "virtual_can".to_owned()],
            virtual_interface_count: 1,
            physical_bench: AutomotivePhysicalBenchPosture::Disabled,
            physical_interface_count: 0,
            dangerous_services: AutomotiveDangerousServicesPosture::Denied,
            max_packets: 10_000,
            max_duration_secs: 300,
            max_rate_per_second: 100,
        },
        operations: vec![
            AutomotiveReportOperation {
                id: OPERATION_ID,
                operation: "analyze_capture".to_owned(),
                mode: "offline_pcap".to_owned(),
                protocol: Some("uds".to_owned()),
                status: AutomotiveOperationStatus::Done,
                started_at,
                ended_at: Some(started_at + chrono::Duration::seconds(2)),
                request_sha256: REQUEST_DIGEST.to_owned(),
                transcript_sha256: Some(TRANSCRIPT_DIGEST.to_owned()),
                artifact_dir: ".service/automotive/operation-one".to_owned(),
                error: None,
                state_signatures: vec![state_signature()],
                result_summary: Some("42 decoded events; 1 protocol state".to_owned()),
                result_complete: Some(true),
            },
            AutomotiveReportOperation {
                id: FAILED_OPERATION_ID,
                operation: "execute_replay".to_owned(),
                mode: "virtual_can".to_owned(),
                protocol: Some("uds".to_owned()),
                status: AutomotiveOperationStatus::Failed,
                started_at: started_at + chrono::Duration::minutes(5),
                ended_at: Some(started_at + chrono::Duration::minutes(5)),
                request_sha256: "1212".repeat(16),
                transcript_sha256: None,
                artifact_dir: ".service/automotive/operation-two".to_owned(),
                error: Some(
                    "sidecar response failed validation at path=/Users/alice/vehicle/capture.pcap \
                     and \"C:\\private\\frame.bin\""
                        .to_owned(),
                ),
                state_signatures: Vec::new(),
                result_summary: None,
                result_complete: None,
            },
        ],
        state_corpus: vec![AutomotiveStateCorpusEntry {
            project_root: "/private/host/path/vehicle-gateway".to_owned(),
            protocol: AutomotiveProtocol::Uds,
            state_digest: STATE_DIGEST.to_owned(),
            artifact_sha256: "3434".repeat(16),
            source_operation_id: OPERATION_ID,
            artifact_path: "project/.service/automotive/state-corpus/uds/evidence".to_owned(),
            created_at: started_at + chrono::Duration::minutes(3),
        }],
    }
}

/// Empty evidence window, disabled policy, empty allowlists.
fn empty_data() -> AutomotiveReportData {
    AutomotiveReportData {
        generated_at: "2026-07-16T09:00:00Z".to_owned(),
        project_name: "empty|project`name".to_owned(),
        tool_version: "0.1.0".to_owned(),
        safety: AutomotiveReportSafetyPosture {
            runtime_policy: AutomotivePolicyPosture::Disabled,
            allowed_protocols: Vec::new(),
            allowed_modes: Vec::new(),
            virtual_interface_count: 0,
            physical_bench: AutomotivePhysicalBenchPosture::Disabled,
            physical_interface_count: 0,
            dangerous_services: AutomotiveDangerousServicesPosture::Denied,
            max_packets: 1,
            max_duration_secs: 2,
            max_rate_per_second: 3,
        },
        operations: Vec::new(),
        state_corpus: Vec::new(),
    }
}

/// Every stage complete, no failures, every observed state promoted, bench
/// enabled with fresh approval, dangerous services exceptionally allowed.
fn complete_data() -> AutomotiveReportData {
    let started_at = started();
    let signature = state_signature();
    let digest = signature.digest.as_str().to_owned();
    let stage = |index: u8, name: &str, mode: &str, signatures: Vec<StateSignature>| {
        AutomotiveReportOperation {
            id: Uuid::from_u128(u128::from(index)),
            operation: name.to_owned(),
            mode: mode.to_owned(),
            protocol: Some("uds".to_owned()),
            status: AutomotiveOperationStatus::Done,
            started_at: started_at + chrono::Duration::minutes(i64::from(index)),
            ended_at: Some(started_at + chrono::Duration::minutes(i64::from(index))),
            request_sha256: REQUEST_DIGEST.to_owned(),
            transcript_sha256: Some(TRANSCRIPT_DIGEST.to_owned()),
            artifact_dir: format!(".service/automotive/{name}"),
            error: None,
            state_signatures: signatures,
            result_summary: Some("complete".to_owned()),
            result_complete: Some(true),
        }
    };
    AutomotiveReportData {
        generated_at: "2026-07-16T09:00:00Z".to_owned(),
        project_name: "complete".to_owned(),
        tool_version: "0.1.0".to_owned(),
        safety: AutomotiveReportSafetyPosture {
            runtime_policy: AutomotivePolicyPosture::Enabled,
            allowed_protocols: vec!["uds".to_owned()],
            allowed_modes: vec!["virtual_can".to_owned()],
            virtual_interface_count: 2,
            physical_bench: AutomotivePhysicalBenchPosture::EnabledApprovalRequired,
            physical_interface_count: 3,
            dangerous_services: AutomotiveDangerousServicesPosture::ExceptionallyAllowed,
            max_packets: 5,
            max_duration_secs: 6,
            max_rate_per_second: 7,
        },
        operations: vec![
            stage(1, "capabilities", "offline_pcap", Vec::new()),
            stage(2, "analyze_capture", "offline_pcap", vec![signature]),
            stage(3, "generate_mutations", "offline_pcap", Vec::new()),
            stage(4, "build_replay_plan", "offline_pcap", Vec::new()),
            stage(5, "execute_replay", "virtual_can", Vec::new()),
        ],
        state_corpus: vec![AutomotiveStateCorpusEntry {
            project_root: "/private/host/path/complete".to_owned(),
            protocol: AutomotiveProtocol::Uds,
            state_digest: digest,
            artifact_sha256: "5656".repeat(16),
            source_operation_id: Uuid::from_u128(2),
            artifact_path: "project/.service/automotive/state-corpus/uds/evidence".to_owned(),
            created_at: started_at,
        }],
    }
}

/// Invalid bench posture, running/cancelled/partial operations, missing
/// protocol, transcript, result summary and error detail.
fn mixed_data() -> AutomotiveReportData {
    let started_at = started();
    AutomotiveReportData {
        generated_at: "2026-07-16T09:00:00Z".to_owned(),
        project_name: "mixed".to_owned(),
        tool_version: "0.1.0".to_owned(),
        safety: AutomotiveReportSafetyPosture {
            runtime_policy: AutomotivePolicyPosture::Enabled,
            allowed_protocols: vec!["can".to_owned()],
            allowed_modes: vec!["offline_pcap".to_owned()],
            virtual_interface_count: 4,
            physical_bench: AutomotivePhysicalBenchPosture::EnabledApprovalMissing,
            physical_interface_count: 5,
            dangerous_services: AutomotiveDangerousServicesPosture::ExceptionallyAllowed,
            max_packets: 8,
            max_duration_secs: 9,
            max_rate_per_second: 10,
        },
        operations: vec![
            AutomotiveReportOperation {
                id: Uuid::from_u128(11),
                operation: "analyze_capture".to_owned(),
                mode: "offline_pcap".to_owned(),
                protocol: None,
                status: AutomotiveOperationStatus::Running,
                started_at,
                ended_at: None,
                request_sha256: REQUEST_DIGEST.to_owned(),
                transcript_sha256: None,
                artifact_dir: ".service/automotive/running".to_owned(),
                error: None,
                state_signatures: vec![state_signature()],
                result_summary: None,
                result_complete: None,
            },
            AutomotiveReportOperation {
                id: Uuid::from_u128(12),
                operation: "generate_mutations".to_owned(),
                mode: "offline_pcap".to_owned(),
                protocol: Some("can".to_owned()),
                status: AutomotiveOperationStatus::Cancelled,
                started_at: started_at + chrono::Duration::minutes(1),
                ended_at: Some(started_at + chrono::Duration::minutes(1)),
                request_sha256: REQUEST_DIGEST.to_owned(),
                transcript_sha256: Some(TRANSCRIPT_DIGEST.to_owned()),
                artifact_dir: ".service/automotive/cancelled".to_owned(),
                error: None,
                state_signatures: Vec::new(),
                result_summary: None,
                result_complete: None,
            },
            AutomotiveReportOperation {
                id: Uuid::from_u128(13),
                operation: "build_replay_plan".to_owned(),
                mode: "offline_pcap".to_owned(),
                protocol: Some("can".to_owned()),
                status: AutomotiveOperationStatus::Done,
                started_at: started_at + chrono::Duration::minutes(2),
                ended_at: Some(started_at + chrono::Duration::minutes(2)),
                request_sha256: REQUEST_DIGEST.to_owned(),
                transcript_sha256: Some(TRANSCRIPT_DIGEST.to_owned()),
                artifact_dir: ".service/automotive/partial".to_owned(),
                error: None,
                state_signatures: Vec::new(),
                result_summary: None,
                result_complete: Some(false),
            },
            AutomotiveReportOperation {
                id: Uuid::from_u128(14),
                operation: "execute_replay".to_owned(),
                mode: "virtual_can".to_owned(),
                protocol: None,
                status: AutomotiveOperationStatus::Failed,
                started_at: started_at + chrono::Duration::minutes(3),
                ended_at: Some(started_at + chrono::Duration::minutes(3)),
                request_sha256: REQUEST_DIGEST.to_owned(),
                transcript_sha256: None,
                artifact_dir: ".service/automotive/failed".to_owned(),
                error: None,
                state_signatures: Vec::new(),
                result_summary: None,
                result_complete: None,
            },
        ],
        state_corpus: Vec::new(),
    }
}

/// One branch-covering fixture with the two renderings it is pinned to.
struct Fixture {
    name: &'static str,
    data: AutomotiveReportData,
    english: &'static str,
    chinese: &'static str,
}

fn fixtures() -> [Fixture; 4] {
    [
        Fixture {
            name: "populated",
            data: report_data(),
            english: include_str!("fixtures/automotive_report/populated.en.md"),
            chinese: include_str!("fixtures/automotive_report/populated.zh.md"),
        },
        Fixture {
            name: "empty",
            data: empty_data(),
            english: include_str!("fixtures/automotive_report/empty.en.md"),
            chinese: include_str!("fixtures/automotive_report/empty.zh.md"),
        },
        Fixture {
            name: "complete",
            data: complete_data(),
            english: include_str!("fixtures/automotive_report/complete.en.md"),
            chinese: include_str!("fixtures/automotive_report/complete.zh.md"),
        },
        Fixture {
            name: "mixed",
            data: mixed_data(),
            english: include_str!("fixtures/automotive_report/mixed.en.md"),
            chinese: include_str!("fixtures/automotive_report/mixed.zh.md"),
        },
    ]
}

/// Every evidence value that must reach the reader unchanged by the language.
///
/// Derived from the fixture rather than hardcoded, so the guard follows the
/// data if a fixture changes. Each is quoted the way the renderer emits it --
/// a whole citation or a whole backticked token, never a prefix, because a
/// prefix cannot be translated and so proves nothing about what follows it.
fn technical_tokens(data: &AutomotiveReportData) -> Vec<String> {
    let mut tokens = vec![data.generated_at.clone(), data.tool_version.clone()];
    for operation in &data.operations {
        tokens.push(format!("[OP:{}]", operation.id));
        tokens.push(format!("`{}`", operation.operation));
        tokens.push(format!("`{}`", operation.mode));
        tokens.push(format!("`{}`", operation.request_sha256));
        tokens.push(format!("`{}`", operation.artifact_dir));
        if let Some(digest) = operation.transcript_sha256.as_deref() {
            tokens.push(format!("[TRANSCRIPT:{digest}]"));
        }
        if let Some(protocol) = operation.protocol.as_deref() {
            tokens.push(format!("`{protocol}`"));
        }
        if let Some(summary) = operation.result_summary.as_deref() {
            // Matched as a whole manifest cell. The `complete` fixture's
            // summary is the bare word "complete", which occurs inside English
            // prose ("completed", "campaign-completeness") that has no Chinese
            // counterpart; the cell delimiters keep the guard on the datum.
            tokens.push(format!("| {summary} |"));
        }
        for signature in &operation.state_signatures {
            tokens.push(format!("[STATE:{}]", signature.digest.as_str()));
        }
    }
    for entry in &data.state_corpus {
        tokens.push(format!("[STATE:{}]", entry.state_digest));
        tokens.push(format!("[OP:{}]", entry.source_operation_id));
        tokens.push(format!("`{}`", entry.artifact_sha256));
        tokens.push(format!("`{}`", entry.artifact_path));
    }
    for name in data
        .safety
        .allowed_protocols
        .iter()
        .chain(data.safety.allowed_modes.iter())
    {
        tokens.push(format!("`{name}`"));
    }
    tokens
}

#[test]
fn english_output_is_byte_identical_to_the_pre_localization_baseline() {
    for fixture in fixtures() {
        let rendered = render_automotive_report(&fixture.data, &AutomotiveLabels::english());
        assert_eq!(
            rendered, fixture.english,
            "the English {} report moved",
            fixture.name
        );
    }
}

#[test]
fn chinese_output_is_byte_identical_to_its_committed_rendering() {
    for fixture in fixtures() {
        let rendered = render_automotive_report(&fixture.data, &AutomotiveLabels::chinese());
        assert_eq!(
            rendered, fixture.chinese,
            "the Chinese {} report moved",
            fixture.name
        );
    }
}

#[test]
fn chinese_labels_translate_the_scaffolding_in_both_directions() {
    for fixture in fixtures() {
        let zh = render_automotive_report(&fixture.data, &AutomotiveLabels::chinese());
        assert!(
            zh.starts_with("# 汽车协议模糊测试活动报告："),
            "{}: the document title is not translated:\n{zh}",
            fixture.name
        );
        for heading in [
            "## 摘要",
            "## 范围与安全策略",
            "## 测试活动工作流",
            "## 协议状态探索",
            "## 发现项",
            "## 证据清单",
            "## 限制",
            "## 建议",
            "### 解读边界",
        ] {
            assert!(
                zh.contains(heading),
                "{}: {heading} is missing:\n{zh}",
                fixture.name
            );
        }
        for english in [
            "## Executive Summary",
            "## Scope and Safety Posture",
            "## Campaign Workflow",
            "## Protocol-State Exploration",
            "## Findings",
            "## Evidence Manifest",
            "## Limitations",
            "## Recommendations",
            "### Interpretation Boundary",
            "Evidence window",
            "Effective posture",
            "Not recorded",
            "not retained",
            "Next,",
            "This report synthesizes",
            "The bounded snapshot contains",
        ] {
            assert!(
                !zh.contains(english),
                "{}: the English label '{english}' survived into the Chinese render:\n{zh}",
                fixture.name
            );
        }
    }
}

#[test]
fn technical_tokens_are_byte_identical_across_languages() {
    for fixture in fixtures() {
        let en = render_automotive_report(&fixture.data, &AutomotiveLabels::english());
        let zh = render_automotive_report(&fixture.data, &AutomotiveLabels::chinese());
        for token in technical_tokens(&fixture.data) {
            assert!(
                zh.contains(token.as_str()),
                "{}: {token} was translated or dropped from the Chinese render",
                fixture.name
            );
            assert_eq!(
                en.matches(token.as_str()).count(),
                zh.matches(token.as_str()).count(),
                "{}: {token} occurs a different number of times per language",
                fixture.name
            );
        }
    }
}

#[test]
fn a_state_observed_by_two_operations_joins_its_citations_with_the_list_separator() {
    // The only list site with no other guard: every fixture above has zero or
    // one citation on an "observed by" line, so the separator never renders
    // there. Give both operations the same protocol state and it does.
    let signature = state_signature();
    let digest = signature.digest.as_str().to_owned();
    let mut data = report_data();
    data.operations[1].state_signatures = vec![signature];

    let en = render_automotive_report(&data, &AutomotiveLabels::english());
    assert!(
        en.contains(&format!(
            "`[STATE:{digest}]` (`uds`), observed by [OP:{OPERATION_ID}], \
             [OP:{FAILED_OPERATION_ID}]."
        )),
        "{en}"
    );

    let zh = render_automotive_report(&data, &AutomotiveLabels::chinese());
    assert!(
        zh.contains(&format!(
            "`[STATE:{digest}]`（`uds`），观察来源 [OP:{OPERATION_ID}]、\
             [OP:{FAILED_OPERATION_ID}]。"
        )),
        "{zh}"
    );
}

#[test]
fn the_guardrail_text_keeps_its_full_force_in_both_languages() {
    // The Limitations bullets and the three standing notices exist to stop a
    // reader concluding more than the retained evidence supports. They are
    // asserted as exact assembled text, in both languages, because a hedge that
    // reads weaker after translation is a defect here even where it would be
    // cosmetic elsewhere.
    let en = render_automotive_report(&report_data(), &AutomotiveLabels::english());
    assert!(en.contains(
        "\
- The report covers only the bounded retained evidence snapshot and cannot infer events that were not persisted.
- Protocol-state digests are not source-code line, function, region, or edge coverage.
- A completed operation confirms contract-valid execution, not absence of security defects.
- Offline and virtual evidence does not validate a physical ECU, vehicle network, timing behavior, or bench wiring.
- AI-assisted interpretation, when appended, is advisory and cannot authorize execution or establish a finding."
    ), "{en}");
    for notice in [
        "Protocol-state novelty is **not source coverage** and does not by itself prove a \
         vulnerability.",
        "All captured, mutation, planning, and replay evidence remains subject to service \
         validation, sandbox isolation, typed limits, guardrails, and the human-approval boundary.",
        "Physical-bench validation is intentionally excluded from campaign-completeness scoring. \
         It remains a separately approved activity after the exact plan and budgets are known.",
        "Observed states, successful decoding, and completed replay steps are campaign evidence. \
         They do not by themselves prove exploitability, security impact, or unsafe vehicle \
         behavior.",
    ] {
        assert!(en.contains(notice), "{notice} is missing from:\n{en}");
    }

    let zh = render_automotive_report(&report_data(), &AutomotiveLabels::chinese());
    assert!(
        zh.contains(
            "\
- 本报告仅覆盖受限的保留证据快照，无法推断未被持久化的事件。
- 协议状态摘要不是源代码的行覆盖率、函数覆盖率、区域覆盖率或边覆盖率。
- 操作完成只能确认执行符合契约，并不代表不存在安全缺陷。
- 离线证据和虚拟证据不能验证物理 ECU、车辆网络、时序行为或台架接线。
- 附加的 AI 辅助解读仅供参考，既不能授权执行，也不能确立发现项。"
        ),
        "{zh}"
    );
    for notice in [
        "协议状态新颖性**不是源代码覆盖率**，其本身也不能证明存在漏洞。",
        "所有捕获、变异、计划和重放证据均须接受服务校验、沙箱隔离、类型化限额、安全护栏\
         以及人工批准边界的约束。",
        "物理台架验证被有意排除在测试活动完整度评分之外。它仍是一项单独批准的活动，\
         只有在确切的计划和预算明确之后才能进行。",
        "观察到的状态、成功的解码和已完成的重放步骤都属于测试活动证据。\
         它们本身并不能证明可利用性、安全影响或不安全的车辆行为。",
    ] {
        assert!(zh.contains(notice), "{notice} is missing from:\n{zh}");
    }
}

#[test]
fn chinese_punctuation_carries_its_own_spacing() {
    // The enumeration of status counts takes the enumeration mark, the clause
    // break takes the full-width comma, and neither takes a trailing ASCII
    // space -- a full-width mark supplies its own.
    let zh = render_automotive_report(&report_data(), &AutomotiveLabels::chinese());
    assert!(
        zh.contains(
            "**1 个已完成**、**0 个部分完成**、**1 个失败**、**0 个运行中**和**0 个已取消**。"
        ),
        "{zh}"
    );
    for fixture in fixtures() {
        let zh = render_automotive_report(&fixture.data, &AutomotiveLabels::chinese());
        for line in zh.lines() {
            for stray in ["， ", "、 ", "： ", "； ", "。 ", "（ ", " ）"] {
                assert!(
                    !line.contains(stray),
                    "{}: a full-width mark carries a trailing ASCII space:\n{line}",
                    fixture.name
                );
            }
            // The mirror image, which the name of this test also promises.
            // One shape is exempt: a state promoted into the corpus but
            // observed by no retained operation renders an empty citation
            // list, so the template's " {sources}" leaves a space before the
            // stop. English has the identical stray space ("observed by ."),
            // it comes from the template rather than from any label, and
            // closing it would move the English document. The exemption is
            // pinned to that one line shape so it cannot widen: any other line
            // growing a space before a full-width mark is a Chinese label
            // carrying the defect, and fails here.
            let empty_citation_list = line.contains("观察来源 。");
            assert!(
                !empty_citation_list || line.starts_with("- `[STATE:"),
                "{}: the empty-citation exemption escaped its line shape:\n{line}",
                fixture.name
            );
            for stray in [" ，", " 、", " ：", " ；", " （"] {
                assert!(
                    !line.contains(stray),
                    "{}: an ASCII space precedes a full-width mark:\n{line}",
                    fixture.name
                );
            }
            assert!(
                empty_citation_list || !line.contains(" 。"),
                "{}: an ASCII space precedes a full stop:\n{line}",
                fixture.name
            );
        }
    }
}

#[test]
fn the_lifecycle_status_word_does_not_claim_the_summarys_completed() {
    // A Done operation whose typed result did not complete is counted
    // "partial" and never "completed". The manifest's status vocabulary is
    // separate -- English says "done" there -- so the Chinese lifecycle word
    // must not read as the summary's "completed" either, or one page asserts
    // both that zero operations completed and that this one did.
    let data = mixed_data();
    let partial = data.operations[2].id;
    let zh = render_automotive_report(&data, &AutomotiveLabels::chinese());

    assert!(zh.contains("**0 个已完成**、**1 个部分完成**"), "{zh}");
    let row = zh
        .lines()
        .find(|line| line.starts_with(&format!("| [OP:{partial}] |")))
        .unwrap_or_else(|| panic!("no manifest row for the partial operation:\n{zh}"));
    assert!(
        row.contains("| 已结束 |"),
        "the manifest must report the lifecycle status, not a completion claim:\n{row}"
    );
    assert!(
        !row.contains("已完成"),
        "the manifest calls an operation completed that the summary counts as partial:\n{row}"
    );
    assert!(
        zh.contains(&format!("### 部分结果：`{}`", data.operations[2].operation)),
        "{zh}"
    );
}

#[test]
fn for_language_resolves_the_two_label_sets() {
    assert_eq!(
        AutomotiveLabels::for_language(ReportLanguage::En),
        AutomotiveLabels::english()
    );
    assert_eq!(
        AutomotiveLabels::for_language(ReportLanguage::Zh),
        AutomotiveLabels::chinese()
    );
    assert_eq!(
        AutomotiveLabels::for_language(ReportLanguage::default()),
        AutomotiveLabels::english()
    );
}

#[test]
fn deterministic_report_is_a_complete_traceable_campaign_record() {
    let report = render_automotive_report(&report_data(), &AutomotiveLabels::english());

    assert!(report.starts_with("# Automotive Fuzzing Campaign Report"));
    for section in [
        "## Executive Summary",
        "## Scope and Safety Posture",
        "## Campaign Workflow",
        "## Protocol-State Exploration",
        "## Findings",
        "## Evidence Manifest",
        "## Limitations",
        "## Recommendations",
    ] {
        assert!(report.contains(section), "missing {section}");
    }
    assert!(report.contains(&format!("[OP:{OPERATION_ID}]")));
    assert!(report.contains(&format!("[STATE:{STATE_DIGEST}]")));
    assert!(report.contains(&format!("[TRANSCRIPT:{TRANSCRIPT_DIGEST}]")));
    assert!(report.contains("sidecar response failed validation"));
    assert!(!report.contains("/Users/alice"));
    assert!(!report.contains("C:\\private"));
    assert!(report.contains("42 decoded events"));
    assert!(report.contains("1 completed"));
    assert!(report.contains("1 failed"));
    assert!(!report.contains("/private/host/path"));
}

#[test]
fn a_done_but_incomplete_operation_is_reported_as_partial_not_completed() {
    // A Done operation whose result was not complete must be counted as
    // "partial" in the Executive Summary, matching the Campaign Workflow table
    // (which treats it as "Attention") and the Findings section -- not double-
    // counted as "completed".
    let mut data = report_data();
    if let Some(op) = data.operations.first_mut() {
        op.result_complete = Some(false);
    }
    let report = render_automotive_report(&data, &AutomotiveLabels::english());
    assert!(
        report.contains("0 completed"),
        "an incomplete Done op must not be counted as completed"
    );
    assert!(
        report.contains("1 partial"),
        "an incomplete Done op must be counted as partial"
    );
}

#[test]
fn report_does_not_overstate_protocol_state_evidence() {
    let report =
        render_automotive_report(&report_data(), &AutomotiveLabels::english()).to_ascii_lowercase();

    assert!(report.contains("protocol-state"));
    assert!(report.contains("not source coverage"));
    assert!(report.contains("does not by itself prove a vulnerability"));
    assert!(!report.contains("confirmed vulnerability"));
}

#[test]
fn ai_prompt_is_grounded_and_only_known_evidence_citations_are_accepted() {
    let data = report_data();
    let facts = render_automotive_report(&data, &AutomotiveLabels::english());
    let prompt = automotive_report_user_prompt(&facts, &data);

    assert!(automotive_report_system_prompt().contains("NEVER invent"));
    assert!(prompt.contains(&facts));
    assert!(prompt.contains("[OP:<uuid>]"));
    assert!(prompt.contains("Hypotheses"));
    assert!(prompt.contains("cannot authorize"));

    let valid = format!(
        "### Evidence-backed interpretation\nThe failed virtual replay needs review \
         [OP:{FAILED_OPERATION_ID}].\n\n### Hypotheses\nNone.\n\n### Missing evidence\n\
         No successful virtual replay is retained.\n\n### Recommended next actions\nReview the \
         retained failure before another supervised virtual run [OP:{FAILED_OPERATION_ID}]."
    );
    assert!(validate_ai_interpretation(&valid, &data).is_ok());

    let unknown = valid.replace(
        &FAILED_OPERATION_ID.to_string(),
        "00000000-0000-0000-0000-000000000001",
    );
    assert!(validate_ai_interpretation(&unknown, &data)
        .unwrap_err()
        .contains("unknown operation"));

    let uncited = "### Evidence-backed interpretation\nLooks good.\n\n### Hypotheses\nNone.\n\n\
        ### Missing evidence\nNone.\n\n### Recommended next actions\nContinue.";
    assert!(validate_ai_interpretation(uncited, &data)
        .unwrap_err()
        .contains("citation"));
}

#[test]
fn ai_interpretation_is_advisory_and_cannot_replace_the_fact_sheet() {
    let data = report_data();
    let facts = render_automotive_report(&data, &AutomotiveLabels::english());
    let interpretation = format!(
        "### Evidence-backed interpretation\nReview the retained failure [OP:{FAILED_OPERATION_ID}].\n\n\
         ### Hypotheses\nNone.\n\n### Missing evidence\nA completed virtual replay.\n\n\
         ### Recommended next actions\nRepeat only after operator review [OP:{FAILED_OPERATION_ID}]."
    );
    let composed = append_ai_interpretation(&facts, &interpretation, "test-model");

    assert!(composed.starts_with(&facts));
    assert!(composed.contains("## AI-Assisted Interpretation"));
    assert!(composed.contains("advisory"));
    assert!(composed.contains("test-model"));
}
