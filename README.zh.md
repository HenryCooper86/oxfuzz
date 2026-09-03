# oxfuzz（中文）

[English](README.md) &middot; **中文**

[![CI](https://github.com/HenryCooper86/oxfuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/HenryCooper86/oxfuzz/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 1.94](https://img.shields.io/badge/Rust-1.94-orange.svg)](rust-toolchain.toml)

> 一个 AI 模糊测试代理：它发现目标、编写测试桩（harness）、驱动开源模糊测试引擎，并对崩溃进行三查（triage）—— 全程处于人工闭环监督与沙箱化执行之下。

**目标发现** &middot; **测试桩生成** &middot; **引擎集成** &middot; **崩溃三查** &middot; **语料库与覆盖率闭环** &middot; **用户可扩展技能**

<p align="center">
  <img src="docs/screenshots/hero.png" alt="oxfuzz 仪表盘：运营就绪度、测试桩审核、近期运行与崩溃移交" width="900">
</p>

---

## 模糊测试新手？从这里开始

用大白话说：**模糊测试（fuzzing）** 就是自动向一个程序投喂数以百万计的畸形、奇怪的输入，找出会让它崩溃的那些 —— 每一次崩溃都是一个潜在缺陷，往往是安全漏洞。手工做这件事需要专家级的工作：决定测什么、编写测试代码、安全地运行它，并读懂崩溃。

**oxfuzz 用 AI 与确定性工具来协调这套工作流。** 你把它指向一份代码库，它会对候选目标进行排名、起草并资格化测试桩、在强制沙箱内驱动真实的模糊测试引擎，并为发现的崩溃保留证据。人工审批被绑定到被允许进入完整 campaign 的那一个确切的测试桩修订版。

如果你不是模糊测试工程师，请先阅读 **[入门指南](docs/guides/GETTING_STARTED.md)** —— 它从零开始解释一切，带你在桌面应用里走完第一次运行，并附有每个术语的词汇表。

---

## 亮点

| 能力 | 说明 |
| --- | --- |
| **运营仪表盘** | 在一个面向操作员的视图中集中呈现就绪度、测试桩审核状态、近期 campaign、崩溃移交与证据计数。 |
| **目标发现** | 对项目进行语义 + 静态分析扫描，产出排名后的目标清单（契合度评分、输入面、复杂度、调用图可达性）。 |
| **可选 Semgrep 增强** | 显式的、仅限 C/C++ 的增强，从固定的离线规则快照中加入有上限的、仅供参考的静态分析信号，且不改变常规发现流程。 |
| **测试桩生成** | 由 LLM 编写、经编译校验、经冒烟模糊的按目标测试桩。 |
| **引擎集成** | AFL++、honggfuzz、libFuzzer 和 syzkaller，统一收敛到一个 `EngineAdapter` trait 之后。 |
| **崩溃三查** | 按栈签名去重、以 CASR 判定严重度/可利用性、最小化，以及在人工审核下由 LLM 起草的缺陷报告。 |
| **语料库与覆盖率** | 播种、扩展、修剪与合并语料库；跟踪覆盖率增量；把崩溃回喂到语料库。 |
| **AI 助手** | 面向同一套服务托管工作流的对话式控制界面，工具活动可见，并有策略强制的人工审批门。 |
| **多提供方 LLM 池** | 基于标签的路由、自动故障转移，以及跨 OpenAI、Anthropic、Gemini 及 OpenAI 兼容后端的提供方冻结/解冻。 |
| **沙箱化执行** | 每一次测试桩构建与模糊运行都经过强制的、以 Docker 为后盾的 `hf-runtime`；不存在生产环境的主机执行回退。 |
| **计划化 campaign** | 无头、预算受限的模糊测试，按间隔/cron/一次性计划运行，在项目已提升的目标间轮换。 |
| **问题与漏洞跟踪** | 将崩溃作为 GitHub/GitLab issue 提交，或作为 finding 推送到 DefectDojo；导出 SARIF 供代码扫描。 |
| **保留的证据** | 运行历史、策略决策、报告、崩溃复现器、语料库、覆盖率与可导出的项目证据均保留可审。 |
| **桌面、CLI 与 Web** | 原生 macOS 应用（Tauri v2 + React），内置帮助指南；完整的 CLI/TUI；以及 REST + SSE API —— 全部构建在同一套服务核心之上。 |

---

## 快速开始

**[入门指南](docs/guides/GETTING_STARTED.md)** 会带你走完桌面应用；**[CLI 参考](docs/guides/CLI_REFERENCE.md)** 覆盖每一个子命令。简短版本：

```bash
git clone <your-oxfuzz-remote> && cd oxfuzz
cargo build --release                 # 二进制：target/release/oxfuzz
./scripts/build-sandbox.sh            # 构建并验证模糊测试沙箱镜像

oxfuzz init                           # 生成 config/*.toml + .env
# 然后至少配置一个 LLM 提供方：config/providers.toml + HF_PROVIDER_API_KEY

oxfuzz discover <project> --lang c --rank
oxfuzz harness  <project> --target <symbol> --engine libfuzzer
oxfuzz run      <project> --target <symbol> --engine libfuzzer --duration 60m
oxfuzz triage   <project> --target <symbol>
```

Docker 必须已安装并正在运行，且至少配置一个 LLM 提供方。完整搭建见
**[安装与构建](docs/guides/INSTALL.md)** 与 **[配置](docs/guides/CONFIGURATION.md)**。

## 90 秒演示

完成上面的快速开始后，观看 oxfuzz 端到端地重新发现一个植入的、CVE 级别的缺陷——
其中包括人工晋升门禁，这正是关键所在：

```bash
./scripts/demo-cve-rediscovery.sh            # 完整运行；晋升前会征询确认
./scripts/demo-cve-rediscovery.sh --preflight-only   # 无副作用的就绪检查
```

默认目标（`examples/aflpp_persistent`）信任声明的长度字节而非实际存在的载荷——
这是众多真实解析器 CVE 背后的"长度字段信任"模式。发现阶段找到入口点，模型编写
的 harness 必须通过 lint、沙箱编译、独立评审和冒烟运行，然后**脚本会停下来等待
你的批准**，才会开始任何完整模糊测试。一次有界的运行与缺陷分诊（triage）收尾。
其他示例隔离其他缺陷类别；见 **[examples/README.md](examples/README.md)**。

---

## 文档

新手请从 **[入门指南](docs/guides/GETTING_STARTED.md)** 开始 —— 面向非专家的大白话介绍。

> 说明：详细的参考文档目前为英文。

**指南**

- [安装与构建](docs/guides/INSTALL.md) —— 先决条件、CLI 与桌面构建、预构建应用，以及可选的 DefectDojo。
- [桌面应用](docs/guides/DESKTOP_APP.md) —— 主界面：一次完整的 campaign、AI 助手与设置。
- [CLI 参考](docs/guides/CLI_REFERENCE.md) —— 每个子命令、快速开始流程、可选 Semgrep 增强与汽车协议工作流。
- [配置](docs/guides/CONFIGURATION.md) —— 配置树、提供方与环境。
- [安全模型](docs/guides/SAFETY_MODEL.md) —— 沙箱、护栏与人工闭环审批。
- [Syzkaller 搭建](docs/guides/SYZKALLER_SETUP.md) &middot; [发布检查清单](docs/guides/RELEASE_CHECKLIST.md) &middot; [持续集成](docs/guides/CI.md)

**参考**

- [架构](docs/ARCHITECTURE.md) —— 分层、`hf-service` 主干与 crate 映射。
- [文档地图](docs/README.md) —— 按受众与任务为读者导航。
- [设计文档](docs/design/) &middot; [工程标准](docs/standards/)

**项目**

- [贡献指南](CONTRIBUTING.md) &middot; [安全策略](SECURITY.md) &middot; [愿景](VISION.md) &middot; [工程协议](AGENTS.md)

---

## 致谢

oxfuzz 受到 [Gorgias (gorgiaxx)](https://github.com/gorgiaxx) 的 **[y-agent](https://github.com/gorgiaxx/y-agent)** 的启发并以之为基础 —— 这是一个模型无关的 Rust 代理框架，能把目标转化为受控、可恢复、可观测的工作。它的设计（代理编排、技能、知识检索、恢复，以及 CLI/TUI/REST/桌面多界面呈现）塑造了本项目的根基。欢迎访问并使用他这个出色的项目。

可选的增强沙箱把
[`Semgrep CE 1.169.0`](https://github.com/semgrep/semgrep/tree/v1.169.0)
作为一个独立的 LGPL-2.1 进程运行，并捆绑 MIT 许可的
[`0xdea/semgrep-rules` C/C++ 快照](https://github.com/0xdea/semgrep-rules/tree/4d66ecf30bfb1809a984085f2c86a8c3915bfc71)。
分发声明与确切来源保留在
[`third_party/semgrep`](third_party/semgrep) 与
[`third_party/semgrep-rules`](third_party/semgrep-rules)。

---

## 许可证

[MIT](LICENSE)
