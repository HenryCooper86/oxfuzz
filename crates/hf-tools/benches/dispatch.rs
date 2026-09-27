//! No-network tool dispatch measurements with retained individual samples.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use hf_core::exec::RuntimeCapability;
use hf_core::tool::{
    Tool, ToolCategory, ToolDefinition, ToolError, ToolInput, ToolOutput, ToolType,
};
use hf_core::types::{SessionId, ToolName};
use hf_tools::config::ToolRegistryConfig;
use hf_tools::error::ToolRegistryError;
use hf_tools::executor::ToolExecutor;
use hf_tools::registry::ToolRegistryImpl;
use serde_json::{json, Value};
use tokio::runtime::Runtime;

const SAMPLES_PER_CASE: usize = 1024;
const CONCURRENCY: [usize; 3] = [1, 8, 32];

struct NoOpTool {
    definition: ToolDefinition,
}

#[async_trait::async_trait]
impl Tool for NoOpTool {
    async fn execute(&self, _input: ToolInput) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            success: true,
            content: Value::Null,
            warnings: Vec::new(),
            metadata: Value::Null,
        })
    }

    fn definition(&self) -> &ToolDefinition {
        &self.definition
    }
}

fn input(valid: bool, name: &ToolName) -> ToolInput {
    ToolInput {
        call_id: "dispatch-sample".into(),
        name: name.clone(),
        arguments: if valid {
            json!({"message": "ok"})
        } else {
            json!({"unexpected": true})
        },
        session_id: SessionId::new(),
        working_dir: None,
        additional_read_dirs: Vec::new(),
        command_runner: None,
    }
}

fn check_result(result: &Result<ToolOutput, ToolRegistryError>, valid: bool) {
    if valid {
        assert!(result.is_ok(), "accepted dispatch failed: {result:?}");
    } else {
        assert!(matches!(
            result,
            Err(ToolRegistryError::ValidationError { .. })
        ));
    }
}

fn registry(runtime: &Runtime) -> Arc<ToolRegistryImpl> {
    runtime.block_on(async {
        let registry = Arc::new(ToolRegistryImpl::new(ToolRegistryConfig::default()));
        let definition = ToolDefinition {
            name: ToolName::from_string("dispatch-noop"),
            description: "No-network dispatch timing tool".into(),
            help: None,
            parameters: json!({
                "type": "object", "properties": {"message": {"type": "string"}},
                "required": ["message"], "additionalProperties": false
            }),
            result_schema: None,
            category: ToolCategory::Custom,
            tool_type: ToolType::BuiltIn,
            capabilities: RuntimeCapability::default(),
            is_dangerous: false,
        };
        registry
            .register_tool(
                Arc::new(NoOpTool {
                    definition: definition.clone(),
                }) as Arc<dyn Tool>,
                definition,
            )
            .await
            .unwrap();
        registry
    })
}

struct Samples {
    dispatch_us: Vec<f64>,
    queue_us: Vec<f64>,
    total_us: Vec<f64>,
}

fn measure(
    runtime: &Runtime,
    registry: &Arc<ToolRegistryImpl>,
    valid: bool,
    concurrency: usize,
) -> Samples {
    runtime.block_on(async {
        let mut workers = Vec::with_capacity(concurrency);
        let mut senders = Vec::with_capacity(concurrency);
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency + 1));
        for _ in 0..concurrency {
            let registry = Arc::clone(registry);
            let barrier = Arc::clone(&barrier);
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            senders.push(tx);
            workers.push(tokio::spawn(async move {
                let mut executor = ToolExecutor::new();
                let name = ToolName::from_string("dispatch-noop");
                check_result(
                    &executor
                        .execute(&registry, &name, input(valid, &name))
                        .await,
                    valid,
                );
                let mut values = Vec::with_capacity(SAMPLES_PER_CASE / concurrency);
                barrier.wait().await;
                while let Some((enqueued, next)) = rx.recv().await {
                    let dequeued = Instant::now();
                    let started = Instant::now();
                    let result = executor.execute(&registry, &name, next).await;
                    values.push((
                        started.elapsed().as_secs_f64() * 1_000_000.0,
                        dequeued.duration_since(enqueued).as_secs_f64() * 1_000_000.0,
                        enqueued.elapsed().as_secs_f64() * 1_000_000.0,
                    ));
                    check_result(&result, valid);
                }
                values
            }));
        }
        barrier.wait().await;
        let name = ToolName::from_string("dispatch-noop");
        for index in 0..SAMPLES_PER_CASE {
            senders[index % concurrency]
                .send((Instant::now(), input(valid, &name)))
                .expect("dispatch worker accepts sample");
        }
        drop(senders);
        let mut samples = Samples {
            dispatch_us: Vec::with_capacity(SAMPLES_PER_CASE),
            queue_us: Vec::with_capacity(SAMPLES_PER_CASE),
            total_us: Vec::with_capacity(SAMPLES_PER_CASE),
        };
        for worker in workers {
            for (dispatch, queue, total) in worker.await.expect("dispatch worker") {
                samples.dispatch_us.push(dispatch);
                samples.queue_us.push(queue);
                samples.total_us.push(total);
            }
        }
        samples
    })
}

fn command_output(program: &str, args: &[&str]) -> String {
    let result = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap();
    assert!(result.status.success(), "{program} identity command failed");
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

fn retain_samples(runtime: &Runtime, registry: &Arc<ToolRegistryImpl>, path: &Path) {
    assert!(path.is_absolute(), "dispatch report path must be absolute");
    let runner = std::env::var("OXFUZZ_PERFORMANCE_RUNNER")
        .expect("name the measurement runner before retaining results");
    assert!(
        !runner.trim().is_empty(),
        "measurement runner must not be empty"
    );
    let mut cases = Vec::new();
    for (valid, decision) in [(true, "accepted"), (false, "denied")] {
        for concurrency in CONCURRENCY {
            let samples = measure(runtime, registry, valid, concurrency);
            cases.push(json!({
                "decision": decision,
                "concurrency": concurrency,
                "dispatch_us": samples.dispatch_us,
                "queue_us": samples.queue_us,
                "total_us": samples.total_us,
            }));
        }
    }
    let report = json!({
        "schema_version": 1,
        "environment": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "rustc": command_output("rustc", &["--version"]),
            "runner": runner,
            "revision": command_output("git", &["rev-parse", "HEAD"]),
            "clean": command_output("git", &["status", "--porcelain"]).is_empty(),
            "profile": "release",
            "runtime_workers": 4,
            "fixture": "noop-schema-v1",
        },
        "cases": cases,
    });
    std::fs::create_dir_all(path.parent().expect("dispatch report parent")).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}

fn bench_dispatch(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let registry = registry(&runtime);
    let name = ToolName::from_string("dispatch-noop");
    let mut group = c.benchmark_group("tool_dispatch");
    for (valid, decision) in [(true, "accepted"), (false, "denied")] {
        let mut executor = ToolExecutor::new();
        runtime.block_on(async {
            check_result(
                &executor
                    .execute(&registry, &name, input(valid, &name))
                    .await,
                valid,
            );
        });
        group.bench_function(decision, |b| {
            b.iter(|| {
                runtime.block_on(async {
                    check_result(
                        &executor
                            .execute(&registry, &name, input(valid, &name))
                            .await,
                        valid,
                    );
                });
            });
        });
    }
    group.finish();
    if let Some(path) = std::env::var_os("OXFUZZ_DISPATCH_REPORT") {
        retain_samples(&runtime, &registry, Path::new(&path));
    }
}

criterion_group!(benches, bench_dispatch);
criterion_main!(benches);
