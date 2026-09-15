# QuickRelay

基于 Rust 的超高性能 STUN/TURN 服务器，对标 [coturn](https://github.com/coturn/coturn)，主要面向 WebRTC 场景。

需求总览见 Multica issue [YEJ-128](https://api.multica.ai)。

## 需求要点

1. 实现类似 coturn 的超高性能 STUN/TURN 服务器
2. 主要支持 WebRTC
3. 使用 stun-rs / turn-rs 等 Rust 库
4. 参考 coturn 实现，通过所有 coturn 用例（如果有的话）
5. 超高性能

## 已确认需求（需求方 2026-09-15）

### 规模与性能指标

- **单机支持 500 路用户视频**。
- WebRTC 视频按 1080p30 ≈ 1.5 Mbps 计，每路 TURN 分配双向各 1.5 Mbps，合计 3 Mbps：
  `500 路 × 3 Mbps = 1.5 Gbps`，叠加 STUN/TURN 控制流与 TLS 握手开销，**按 2 Gbps 双向吞吐容量设计**。
- 分配类消息（Allocate/Refresh/Stop）P99 < 1 ms。
- 上述数字是**容量下限，不是目标上限**：架构与转发路径按「远超 500 路」的方式设计（无锁内核、零拷贝转发、按 CPU 核分片的分配表），压测阶段实测后向上校准。

### 协议矩阵

| 协议 | 必需性 |
| --- | --- |
| STUN over UDP（RFC 5389 / 8489） | 必须 |
| TURN over UDP（RFC 6051） | 必须 |
| TURN over TCP | **必须** |
| TURN over TLS | **必须** |
| ICE-TCP 协商 | 必须 |

### 配置模型

- **静态配置**：用于初始化，配置文件 + CLI（对齐 coturn 常用参数）。
- **REST 动态变更**：支持，但变更**临时**——仅在本次运行内生效，重启回落到静态配置。不引入外部数据库存储动态值。

### 明确不做（本轮）

- Licensing 不做专门处理：coturn 为 GPL-2.0，QuickRelay **不复用其代码**；复用其测试资产仅限「读取其行为规格并转写」，不 vendor 其脚本与代码。

## 当前状态

Stage 1 架构设计已定稿，文档落在 `docs/architecture/`：

- `docs/architecture/tech-stack.md` — 技术选型定稿（协议栈 / I/O / 认证 / 配置 / 可观测性 + 被否决方案）
- `docs/architecture/protocol-matrix.md` — STUN/TURN 消息类型与 attribute 全量矩阵（RFC 5389 / 8489 / 6051 / 6062 / 5245，含 coturn 默认行为对齐清单）
- `docs/architecture/architecture.md` — 整体架构：进程线程模型、UDP/Allocate 数据路径、数据结构、内存预算、超时回收、拥塞限速、TLS 组合、REST 端点、issue 依赖图

## 技术选型（Stage 1 已定稿，详见 docs/architecture/tech-stack.md）

- 语言：Rust（edition 2021，stable toolchain）
- 协议栈：**自研**（仅以 RFC 为行为来源），不采用 `sippusher/turn`（已停更）与 `stun-rs` 系 crate
- 网络 I/O：数据面 `socket2` + `mio`（每核 `Poll`，`SO_REUSEPORT`），Linux `io_uring` 为可选 feature；控制面 `tokio` 1.x
- 认证：`hmac` + `sha1` / `sha2`，long-term / ephemeral / 静态分配 key，nonce 含时间戳 + 熵 + salt
- 配置：`clap` 4.x + `toml` 0.8 + `serde`；REST 动态变更仅本次运行内生效
- 可观测性：`metrics` + `metrics-exporter-prometheus` + `axum`
- 协议：STUN RFC 5389 / 8489、TURN RFC 6051、ChannelData RFC 6062、UDP-over-TLS RFC 7635、TLS over TCP RFC 8326、ICE-TCP（见 protocol-matrix.md）
- 性能对标：coturn 官方数据；本机验收口径为单机 500 路视频 / 2 Gbps 双向 / 分配类 P99 < 1 ms
