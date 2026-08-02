# 汽车协议模糊测试活动报告：`vehicle-gateway`

| | |
|---|---|
| 项目 | `vehicle-gateway` |
| 生成时间 | 2026-07-16T09:00:00Z |
| 工具 | oxfuzz 0.1.0 |
| 证据窗口 | 2 个保留的操作 |

## 摘要

本报告汇总 **2 个保留的汽车协议操作**：**1 个已完成**、**0 个部分完成**、**1 个失败**、**0 个运行中**和**0 个已取消**。受限快照包含 **2 个唯一协议状态摘要** 和 **1 个已提升的状态语料库产物** 共涉及 **1 个观察到的协议**。

保留的失败会作为操作证据予以报告，应在重复相应工作流阶段之前解决。

协议状态新颖性**不是源代码覆盖率**，其本身也不能证明存在漏洞。

## 范围与安全策略

| 控制项 | 生效状态 |
|---|---|
| 运行时汽车协议策略 | 已启用 |
| 允许的协议 | `can`、`uds` |
| 允许的模式 | `offline_pcap`、`virtual_can` |
| 虚拟接口 | 1 个在允许列表中 |
| 物理台架 | 已禁用；0 个允许列表接口 |
| 危险诊断服务 | 已拒绝 |
| 单次操作上限 | 10000 个事件；300 秒；100 个发送事件/秒 |

所有捕获、变异、计划和重放证据均须接受服务校验、沙箱隔离、类型化限额、安全护栏以及人工批准边界的约束。

## 测试活动工作流

| 阶段 | 状态 | 完成数 | 失败数 |
|---|---|---:|---:|
| 适配器能力检查 | 无记录 | 0 | 0 |
| 不可变捕获文件分析 | 已完成 | 1 | 0 |
| 确定性变异生成 | 无记录 | 0 | 0 |
| 类型化重放计划构建 | 无记录 | 0 | 0 |
| 受监督的虚拟重放 | 需关注 | 0 | 1 |

物理台架验证被有意排除在测试活动完整度评分之外。它仍是一项单独批准的活动，只有在确切的计划和预算明确之后才能进行。

## 协议状态探索

| 协议 | 唯一状态 | 已提升产物 |
|---|---:|---:|
| `uds` | 2 | 1 |

### 状态证据

- `[STATE:2fe325136b771614edd4ace673a81b7297ae1665e20ab9040b876c1c947e52de]`（`uds`），观察来源 [OP:11111111-2222-3333-4444-555555555555]。
- `[STATE:abababababababababababababababababababababababababababababababab]`（`uds`），观察来源 。
- 已提升 `[STATE:abababababababababababababababababababababababababababababababab]` 来自 [OP:11111111-2222-3333-4444-555555555555]，产物摘要 `3434343434343434343434343434343434343434343434343434343434343434` 位于 `project/.service/automotive/state-corpus/uds/evidence`。

## 发现项

### 操作失败：`execute_replay`

- 证据：[OP:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee]
- 模式：`virtual_can`
- 协议：`uds`
- 保留的错误：（系统原文）sidecar response failed validation at [redacted-path] and [redacted-path]

### 解读边界

观察到的状态、成功的解码和已完成的重放步骤都属于测试活动证据。它们本身并不能证明可利用性、安全影响或不安全的车辆行为。

## 证据清单

| 操作证据 | 阶段 | 模式 / 协议 | 状态 | 已验证结果 | 请求摘要 | 记录证据 | 产物目录 |
|---|---|---|---|---|---|---|---|
| [OP:11111111-2222-3333-4444-555555555555] | `analyze_capture` | `offline_pcap` / `uds` | 已结束 | 42 decoded events; 1 protocol state | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/operation-one` |
| [OP:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee] | `execute_replay` | `virtual_can` / `uds` | 失败 | 未保留 | `1212121212121212121212121212121212121212121212121212121212121212` | 未保留 | `.service/automotive/operation-two` |

## 限制

- 本报告仅覆盖受限的保留证据快照，无法推断未被持久化的事件。
- 协议状态摘要不是源代码的行覆盖率、函数覆盖率、区域覆盖率或边覆盖率。
- 操作完成只能确认执行符合契约，并不代表不存在安全缺陷。
- 离线证据和虚拟证据不能验证物理 ECU、车辆网络、时序行为或台架接线。
- 附加的 AI 辅助解读仅供参考，既不能授权执行，也不能确立发现项。

## 建议

1. 请对 1 个保留的操作失败按操作 id 进行分类定级，然后再重复相应阶段。
2. 下一步，检查固定版本适配器声明的能力。
3. 下一步，生成一组确定性且可审阅的变异。
4. 下一步，在不接触任何接口的前提下构建并审阅类型化重放计划。
5. 请为 1 个尚无保留语料库证据的观察状态审阅并提升合适的产物。
6. 如果策略和运行时就绪状态允许，请执行一次单独确认的受监督 virtual-CAN 重放。
---

_确定性证据报告由 oxfuzz 生成，版本 0.1.0 于 2026-07-16T09:00:00Z。_
