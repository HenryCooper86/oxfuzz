# Tool Call Protocol

Status: **active**. Scope: `hf-tools`, `hf-agent`, `hf-service`.

## 1. Tool Trait

Defined in `hf-core`:

```rust
#[async_trait]
pub trait Tool: Send + Sync {
    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError>;
    fn definition(&self) -> &ToolDefinition;
}
```

## 2. Tool Registry

- A registry starts empty. Its owner registers executable implementations and
  definitions by name; JSON Schema is validated before execution.
- The active agent advertises its complete four-tool inspection surface
  directly and exposes no discovery meta-tool. `ToolIndex` and
  `ToolRegistry::search` remain available for an owner whose registry outgrows
  what one prompt can carry; nothing in the shipped agent calls them.
- There is no runtime API for creating tools. A new tool is added by
  registering an implementation in the active registry -- in code, reviewed --
  which is what keeps the executable surface enumerable.

## 3. Active Agent Inspection Tools

| Tool | Purpose |
| --- | --- |
| `FileRead` | Read a file (project-scoped). |
| `Glob` | List project files matching a glob. |
| `Grep` | Search project files with a regular expression. |
| `KnowledgeSearch` | BM25 search over the active project's source index. |

`FileRead`, `Glob`, and `Grep` are implemented in `hf-tools`.
`KnowledgeSearch` is registered by `hf-agent` with its `AgentBackend`, so all
four advertised tools have executable registry entries. The registry assembly
test in `hf-agent::agent_tools` enforces exact parity between this catalog and
the executable surface.

Discovery, harness generation, harness build, fuzzing, crash triage, corpus
mutation, scheduling, and sub-agent delegation are service-domain actions.
They route through `AgentBackend` to `hf-service`, where qualification,
guardrails, human approval, persistence, and sandbox policy are enforced. They
must not be exposed through a generic `ShellExec`, file-mutation, or signal-only
tool. The former y-agent prototype registrar and its unreachable mutating,
shell, workflow, delegation, and discovery tools were removed rather than
wired around these boundaries.

## 4. Permission Model

- Inspection calls pass through the registry executor for schema validation
  and exact registered-tool dispatch. Service-domain actions independently
  pass through `hf-guardrails` and their operation-specific approval gates.
- The active generic tool registry is read-only. A future mutating or process
  tool requires an explicit service-owned design, sandbox-backed execution,
  risk classification, and human-approval policy before it can be registered.
- Tool results are untrusted prompt data. The registry does not yet provide a
  general secret-redaction guarantee, so executable tools must not return
  credentials or other service secrets.
- File inspection is confined to the exact active project root.
  A project root located under a system temporary directory remains valid, but
  sibling temporary paths are not implicitly trusted. Additional read roots
  must be supplied explicitly and remain subject to canonical symlink-boundary
  validation. The active registry contains no file-mutation tool.
- The active registry contains no shell or general process-execution tool.

The former generic hook executor and standalone MCP client were removed after
dependency-graph and runtime-construction audits found no production consumer.
Keeping those prototypes would have implied interception and remote-tool
capabilities that the active agent did not execute. A future hook or MCP
subsystem requires a service-owned design, an explicit runtime construction
path, and integration tests proving that advertised behavior reaches the live
agent.

## 5. Agent Protocol and Parsing

- The shipped agent uses the model-neutral, prompt-based JSON step contract
  defined by `hf-prompt`, independent of provider-native tool calling. The
  model is instructed to reply with exactly one JSON object
  (`config/prompts/core_tool_protocol.txt`) and the reply is decoded as JSON.
- That contract is the only tool-call syntax this codebase parses. Parsers for
  provider-specific and tagged formats (`<tool_call>` and its dialects) were
  removed on 2026-08-28: they had no caller, and the agent never emits the
  syntax they read. A provider-native integration adds its parser alongside the
  implementation that needs it, so a format this codebase claims to accept is
  always one it exercises.
