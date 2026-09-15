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
- 分配类消息（Allocate/Refresh/Stop）**P99 < 1 ms（UDP 路径）**。
- TLS over TCP 路径含 TLS 记录层 + TCP 拷贝，不适用 1 ms 承诺；架构口径 **P99 < 5 ms**。
- 上述数字是**容量下限，不是目标上限**：架构与转发路径按「远超 500 路」的方式设计（无锁内核、零拷贝转发、按 CPU 核分片的分配表），压测阶段实测后向上校准。

### 协议矩阵

| 协议 | 必需性 |
| --- | --- |
| STUN over UDP（RFC 5389 / 8489） | 必须 |
| TURN over UDP（RFC 6051） | 必须 |
| TURN over TCP | **必须** |
| TURN over TLS —— UDP-over-TLS（RFC 7635） | **必须** |
| TURN over TLS —— TLS over TCP（RFC 8326） | **必须** |
| TURN over TLS over UDP（RFC 6061） | 仅接收兼容，不作为主路径（已被 RFC 9263 标记 obsoleted） |
| ICE-TCP 协商 | 必须 |

### 配置模型

- **静态配置**：用于初始化，配置文件 + CLI（对齐 coturn 常用参数）。
- **REST 动态变更**：支持，但变更**临时**——仅在本次运行内生效，重启回落到静态配置。不引入外部数据库存储动态值。
- **REST 鉴权双支持**：Bearer token 与 HMAC 请求签名两种都要实现，可各自开关、可同时启用。

### 明确不做（本轮）

- 不做计费系统 / 租户模型 / 多租户 / 账户体系。
- 不做完整 REST 管理面，只覆盖「临时动态变更」这一个场景。
- Licensing 不做专门处理：coturn 为 GPL-2.0，QuickRelay **不复用其代码**；复用其测试资产仅限「读取其行为规格并转写」，不 vendor 其脚本与代码。

## 当前状态

仓库已初始化，具体 issue 拆解与实现计划由 Multica 看板管理。技术选型（自研 vs `turn` 库）在 Stage 1 架构设计中定稿。

## 技术选型（待 Stage 1 定稿）

- 语言：Rust 2021+，稳定版 toolchain
- 协议：STUN RFC 5389 / 8489、TURN RFC 6051、RFC 6062（ChannelData）、RFC 7635、RFC 8326、ICE RFC 8445
- 性能对标：coturn 官方 benchmark 数据；本机验收目标见上方「规模与性能指标」

## 变更记录

- 2026-09-15：录入需求方 5 项拍板结论（仓库地址、500 路 / 2 Gbps、TURN over TLS/TCP、配置模型、licensing）。
- 2026-09-15：TLS 组合定稿为**全量支持**（UDP-over-TLS / RFC 7635 与 TLS over TCP / RFC 8326 均必须，RFC 6061 仅接收兼容）；补记 REST 鉴权双支持、TLS over TCP 的 P99 < 5 ms 时延口径。
