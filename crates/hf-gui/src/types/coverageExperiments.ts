export type ExperimentKind = "grow_corpus" | "refine_harness";
export interface ExperimentAdvice { kind: ExperimentKind; goal: string }
export interface ExperimentScope { project: string; target_id: string }
export interface ExperimentCursor { created_at: string; id: string }
export interface ExperimentRun {
  run_id: string;
  status: "done" | "failed" | "cancelled";
  duration_secs: number;
  seed: string | null;
  max_mem_mb: string;
  edges: string | null;
  build_inputs: { build_input_sha256: string } | null;
}
export interface CoverageExperiment {
  id: string;
  project_root: string;
  target_id: string;
  target_symbol: string;
  baseline_run_id: string;
  kind: ExperimentKind;
  goal_function: string;
  hypothesis: string;
  hypothesis_origin: "operator_supplied";
  duration_secs: number;
  baseline: ExperimentRun;
  status: "prepared" | "completed" | "cancelled";
  created_at: string;
  result: null | {
    run: ExperimentRun;
    input_change: "no_observed_input_change" | "corpus_changed" | "harness_source_changed";
    build_comparison: "matched" | "unavailable_legacy";
    edge_comparison: { status: "observed"; baseline_edges: string; result_edges: string; delta: string } | { status: "unavailable"; reason_code: string };
    target_entry: { status: "unavailable"; reason_code: "no_exact_run_scoped_function_coverage" };
    limitations: string[];
  };
  cancellation_reason: string | null;
}
export interface ExperimentPage { items: CoverageExperiment[]; next_cursor: ExperimentCursor | null }
