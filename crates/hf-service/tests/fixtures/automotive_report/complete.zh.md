# 汽车协议模糊测试活动报告：`complete`

| | |
|---|---|
| 项目 | `complete` |
| 生成时间 | 2026-07-16T09:00:00Z |
| 工具 | oxfuzz 0.1.0 |
| 证据窗口 | 5 个保留的操作 |

## 摘要

本报告汇总 **5 个保留的汽车协议操作**：**5 个已完成**、**0 个部分完成**、**0 个失败**、**0 个运行中**和**0 个已取消**。受限快照包含 **1 个唯一协议状态摘要** 和 **1 个已提升的状态语料库产物** 共涉及 **1 个观察到的协议**。

此保留证据窗口中不存在终态操作失败。

协议状态新颖性**不是源代码覆盖率**，其本身也不能证明存在漏洞。

## 范围与安全策略

| 控制项 | 生效状态 |
|---|---|
| 运行时汽车协议策略 | 已启用 |
| 允许的协议 | `uds` |
| 允许的模式 | `virtual_can` |
| 虚拟接口 | 2 个在允许列表中 |
| 物理台架 | 已启用；需要新的人工批准；3 个允许列表接口 |
| 危险诊断服务 | 按策略例外允许 |
| 单次操作上限 | 5 个事件；6 秒；7 个发送事件/秒 |

所有捕获、变异、计划和重放证据均须接受服务校验、沙箱隔离、类型化限额、安全护栏以及人工批准边界的约束。

## 测试活动工作流

| 阶段 | 状态 | 完成数 | 失败数 |
|---|---|---:|---:|
| 适配器能力检查 | 已完成 | 1 | 0 |
| 不可变捕获文件分析 | 已完成 | 1 | 0 |
| 确定性变异生成 | 已完成 | 1 | 0 |
| 类型化重放计划构建 | 已完成 | 1 | 0 |
| 受监督的虚拟重放 | 已完成 | 1 | 0 |

物理台架验证被有意排除在测试活动完整度评分之外。它仍是一项单独批准的活动，只有在确切的计划和预算明确之后才能进行。

## 协议状态探索

| 协议 | 唯一状态 | 已提升产物 |
|---|---:|---:|
| `uds` | 1 | 1 |

### 状态证据

- `[STATE:2fe325136b771614edd4ace673a81b7297ae1665e20ab9040b876c1c947e52de]`（`uds`），观察来源 [OP:00000000-0000-0000-0000-000000000002]。
- 已提升 `[STATE:2fe325136b771614edd4ace673a81b7297ae1665e20ab9040b876c1c947e52de]` 来自 [OP:00000000-0000-0000-0000-000000000002]，产物摘要 `5656565656565656565656565656565656565656565656565656565656565656` 位于 `project/.service/automotive/state-corpus/uds/evidence`。

## 发现项

此证据窗口中没有需要分类定级的保留终态操作失败。
### 解读边界

观察到的状态、成功的解码和已完成的重放步骤都属于测试活动证据。它们本身并不能证明可利用性、安全影响或不安全的车辆行为。

## 证据清单

| 操作证据 | 阶段 | 模式 / 协议 | 状态 | 已验证结果 | 请求摘要 | 记录证据 | 产物目录 |
|---|---|---|---|---|---|---|---|
| [OP:00000000-0000-0000-0000-000000000001] | `capabilities` | `offline_pcap` / `uds` | 已结束 | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/capabilities` |
| [OP:00000000-0000-0000-0000-000000000002] | `analyze_capture` | `offline_pcap` / `uds` | 已结束 | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/analyze_capture` |
| [OP:00000000-0000-0000-0000-000000000003] | `generate_mutations` | `offline_pcap` / `uds` | 已结束 | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/generate_mutations` |
| [OP:00000000-0000-0000-0000-000000000004] | `build_replay_plan` | `offline_pcap` / `uds` | 已结束 | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/build_replay_plan` |
| [OP:00000000-0000-0000-0000-000000000005] | `execute_replay` | `virtual_can` / `uds` | 已结束 | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/execute_replay` |

## 限制

- 本报告仅覆盖受限的保留证据快照，无法推断未被持久化的事件。
- 协议状态摘要不是源代码的行覆盖率、函数覆盖率、区域覆盖率或边覆盖率。
- 操作完成只能确认执行符合契约，并不代表不存在安全缺陷。
- 离线证据和虚拟证据不能验证物理 ECU、车辆网络、时序行为或台架接线。
- 附加的 AI 辅助解读仅供参考，既不能授权执行，也不能确立发现项。

## 建议

1. 保留当前操作证据，并与未来的测试活动快照比对以发现回归。
---

_确定性证据报告由 oxfuzz 生成，版本 0.1.0 于 2026-07-16T09:00:00Z。_
