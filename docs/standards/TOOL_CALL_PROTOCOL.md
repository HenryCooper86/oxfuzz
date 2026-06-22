# Tool Call Protocol

Status: **active**. Scope: `hf-tools`, `hf-agent`, `hf-service`.

## 1. Tool Trait

Defined in `hf-core`:

```rust
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn schema(&self) -> serde_json::Value; // JSON Schema
    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> Result<ToolOutput>;
}
```

## 2. Tool Registry

- Tools registered by name; JSON Schema validated on call.
- LRU activation for tool subset selection per turn.
- Dynamic tool creation supported (e.g. per-target harness build tools).

## 3. Built-in Tools

| Tool | Purpose |
| --- | --- |
| `ShellExec` | Run a command in sandbox. |
| `FileRead` | Read a file (project-scoped). |
| `FileWrite` | Write to `fuzz_workspace/`. |
| `ProjectScan` | Walk a project for discovery. |
| `HarnessBuild` | Build a harness in sandbox. |
| `FuzzRun` | Launch an engine run. |
| `CrashMinimize` | Minimize a crash input. |
| `KnowledgeSearch` | RAG over project + fuzzer docs. |
| `Task` | Delegate to a sub-agent. |

## 4. Permission Model

- Every tool call passes through `hf-guardrails`.
- Risk-scored: `ShellExec` and `FuzzRun` are High risk -> HITL required
  unless `--auto` mode is explicitly enabled by the user.
- Tool output is redacted of secrets before returning to the LLM.

## 5. Parsing

- Native tool calling when provider supports it.
- Prompt-based (XML-delimited) for OpenAI-compatible / local models.