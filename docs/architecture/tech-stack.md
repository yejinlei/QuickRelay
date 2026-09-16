# 技术选型定稿（Stage 1）

状态：定稿。本文档每一处都给出**结论**，不保留「二选一待定」。所有开放项均在下文列出**建议默认值**，需求方可否决。

权威容量口径引用 [YEJ-135](https://github.com/yejinlei/QuickRelay)：单机 **500 路用户视频**、**2 Gbps 双向吞吐容量**、分配类消息 **P99 < 1 ms**。架构按「远超 500 路」设计（转发内核无锁、零拷贝、按核分片状态表），压测后向上校准。

---

## 1. STUN/TURN 协议栈：自研 vs 复用第三方 crate

### 1.1 结论

**结论：STUN/TURN 协议栈全部自研，仅以 RFC（5389 / 8489 / 6051 / 6062 / 7635 / 8326 / 8445）为行为定义来源；不引入任何 TURN 引擎 crate，也不引入 sippusher/turn。**

落到模块上：

| 层次 | 决策 | 依据的 RFC |
| --- | --- | --- |
| 消息头 / attribute 编解码 | 自研（`quickrelay-protocol`），**零外部依赖**（仅 `bytes`） | RFC 5389 §6/§13/§20、RFC 6051 §13 |
| Message Integrity / HMAC | 复用 rust-crypto 生态（`hmac` + `sha1` + `sha2`），语义自研 | RFC 5389 §11、RFC 6051 §12 |
| TURN 会话状态机、allocation 表、转发路径 | **完全自研** | RFC 6051 §6、RFC 6062、RFC 7635 |
| ChannelData 打包 | 自研 | RFC 6062 |
| 认证（long-term / ephemeral / 静态分配 key、nonce 生命周期） | 自研 | RFC 6051 §12 |

「引用 RFC」的含义：以规范文本为唯一行为来源，不复制 coturn 的 C 代码或任何 GPL 覆盖的脚本（与需求方已确认的 licensing 口径一致）。

### 1.2 逐项评估

#### A. `sippusher/turn` — 结论：不采用

- **维护风险（必须注明）**：该 crate 最后发版于 2018 年前后，长期无提交；后续维护者把它以 `turn-rust` 名义接管后仍然处于低频维护。对本项目的直接后果：
  1. 依赖树锁定 2016–2018 年代的 `async-std` / `nom` / `tokio` 旧大版本，与我们选定的 tokio 1.x 生态产生版本冲突，需要长期维护 yanked/过时依赖。
  2. RFC 6062 / RFC 7635（UDP-over-TLS，2015 年发布）覆盖不完整；**而本项目的协议矩阵要求 RFC 7635 必须支持**。
  3. 该库定位为「实现 RFC 6051 的完整服务器」，其内部线程模型、内存模型与我们要做的 SO_REUSEPORT + 每核分片状态表冲突，复用等于背上整套我们不需要的运行时，而不是复用一部分。
  4. 长期停更意味着安全修复（尤其是 HMAC/nonce 相关）不再可期待。
- **结论理由**：协议栈是本项目唯一的护城河代码，也是 coturn 兼容性的验收面。背一个停更的第三方引擎，等于把「通过所有 coturn 用例」这一核心验收标准外包给一个无人维护的中间层，且该中间层自身对 RFC 7635/6062 的覆盖不足以支撑本项目的必须项。**否决 `turn` crate。**

#### B. `stun-rs` 系 crate（`stun-rs` / `turn-rs` / `stun`）— 结论：不采用（协议栈），仅保留为交叉校验参考

- `stun-rs`：2019 年发版后停更，且其设计目标是「作为 TURN 服务器的客户端库」，即它实现的是客户端侧逻辑（探测、候选收集），不是服务器侧的状态机与 allocation 管理。能提供的只有消息编解码这一小块，而这一小块是 RFC 5389 §20 附录里的字节样例可以直接验证的确定性代码。
- `turn-rs`（`turn-rs` / `turn-server`）：功能更窄，同样停更。
- 对编解码这种「输入是字节、输出是结构」的层，**依赖第三方 crate 的收益（节省 ~1.5k 行）低于代价（不可控的 API 漂移 + 版本锁死 + 无法自由优化热路径与错误模型）**。自研编解码的验收手段是逐字节 golden vector 测试（RFC 附录 + coturn 观测到的实际报文），成本可控且可完全自动化。
- **否决。** 但 `stun-rs` 的 attribute 定义表可以用作**实现时的第二参考源**（不是行为来源，只用于发现是否漏项）。

#### C. 「自研 + 仅引用 RFC 定义」— 结论：**采用**

理由：
1. 协议栈层代码量可控（编解码 ~2k 行、状态机 ~3k 行），而它是本项目与 coturn 行为对齐的唯一落点。自研让「对齐 coturn 默认行为」变成可控的逐条矩阵工作，而不是对第三方实现的黑盒跟随。
2. 协议层热路径（每包解析）需要零堆分配、固定错误预算、可控的 attribute 遍历策略（未知 attribute 需按 RFC 5389 §13.4 收集进 `UNKNOWN-ATTRIBUTES`）。自研才能把这些约束写进代码结构里。
3. 合规：完全规避 GPL 传染风险，与需求方确认的「不复用 coturn 代码」口径一致。
4. 唯一被保留的第三方是 rust-crypto 生态（`hmac`/`sha1`/`sha2`/`rand`）——这是成熟、活跃、安全审计过的基础设施，不属于「协议栈」，没有理由自研。

### 1.3 依赖清单（最终）

| crate | 版本约束 | 用途 | 热路径 |
| --- | --- | --- | --- |
| `tokio` | 1.x，feature `rt-multi-thread,net,uds,signal,macros,process` | 运行时、TCP 监听、控制面 | 否（仅控制面/管理面） |
| `tokio-udp` | 0.x（与 tokio 同系列维护者） | 零拷贝 UDP 收发、per-worker socket | 否（库本身轻量，我们持有裸 fd） |
| `mio` | 1.x | UDP 事件循环（`mio` 直接持有 `Socket`，避免每包 Arc） | 是 |
| `socket2` | 0.5.x | `SO_REUSEPORT` / `SO_REUSEADDR` / `SO_RCVBUF` / `IP_PMTUDISC` / 多监听绑定 | 否 |
| `bytes` | 1.x | `Bytes` 零拷贝缓冲 | 是 |
| `io-uring` | 0.7.x，**`--features transport-uring` 可选** | Linux io_uring 收发路径（SPOLLING + provided buffers） | 是（仅启用时） |
| `hmac` | 0.12.x | Message Integrity / long-term key 派生 | 是 |
| `sha1` | 0.10.x | RFC 6051 §12.2.1 long-term key、RFC 5389 §11 默认校验 | 是 |
| `sha2` | 0.10.x | HMAC-SHA256 扩展（`--alt-hmac-sha1` 等价，RFC 7635/8326 场景常用） | 是 |
| `rustls` | 0.23.x | TURN over TLS（RFC 8326，TCP）与 UDP-over-TLS（RFC 7635） | 是（TLS 路径） |
| `quinn` | 不采用 | — | — |
| `rand` / `rand_core` | 0.8.x / `getrandom` | transaction id、nonce 熵源（`getrandom` + CSPRNG） | 否 |
| `clap` | 4.x，`derive` | CLI | 否（启动期） |
| `serde` / `serde_derive` | 1.x | 配置结构 | 否（启动期） |
| `toml` | 0.8.x | 配置文件解析 | 否（启动期） |
| `metrics` | 0.23.x | 数据面计数器（`AtomicU64`，热路径零格式开销） | 是 |
| `metrics-exporter-prometheus` | 0.16.x | Prometheus 文本格式拉取 | 否 |
| `prometheus` | 0.14.x | 仅用于 lazy 采样的高基数指标（如按错误码分桶的 gauge） | 否 |
| `tracing` + `tracing-subscriber` | 0.1.x / 0.3.x | 结构化日志 | 否（事件级） |
| `axum` | 0.7.x | `/metrics`、`/healthz`、`/readyz`、REST 动态变更端点 | 否 |
| `tower` | 0.5.x | REST 端限流（防误用/误配导致的 DoS） | 否 |
| `sysinfo` / 手写 `proc` 读取 | — | worker 存活探测（`/readyz`） | 否 |

明确不采用：`quinn`（QUIC，不在范围内）、`async-std`/`smol`（见 §2）、`mio + std`（理由见 §2）、`tokio-postgres`/任何 DB 客户端（配置与凭证不落库，见需求方确认的配置模型）、`tonic`（无 gRPC 管理面需求）。

---

## 2. 网络 I/O：`tokio` / `smol` / `mio` + `io_uring` / `socket2` 裸 UDP

### 2.1 结论

**结论：数据面用 `socket2`（socket 属性与多监听）+ `mio`（每核事件循环）；控制面/管理面用 `tokio` 1.x 多核运行时。二者共存，且通过 `transport-uring` 编译期 feature 提供 Linux io_uring 收发后端（可选，默认关闭，`cargo build --features transport-uring` 启用）。**

即：**UDP 不走 tokio 的 `UdpSocket` 抽象**，而走每核一个 `mio::Poll` + 裸 UDP socket 的固定线程模型。

### 2.2 与性能目标的一致性论证

目标：2 Gbps 双向、500 路视频、分配类 P99 < 1 ms。按 1200 字节平均 UDP 包，2 Gbps ≈ 210k pps 总入流量（双向合计），单机目标按 8 核设计即每核 ~26k pps——单核预算非常宽松，**真正的瓶颈不是 pps，而是 P99 尾延迟与 TLS 路径的 CPU 成本**。选型据此排序：

1. **尾延迟优先于峰值吞吐**：tokio 1.x 的 UDP 路径（`mio` reactor + task 调度）在正常负载下表现良好，但它的成本模型是「每包一次 `Poll` 就绪 → 唤醒 task → 调度器排队 → 执行」。在多 task 竞争下，就绪到执行的排队延迟是**不可预测的**（P99/P999 抖动来源）。每核绑定一个独立事件循环 + 该核上的状态表分片（shard），把「调度排队」这一项彻底消除：分配类消息的 P99 只由 syscall + 解析 + 发送构成，可静态论证 < 1 ms（实测预算见 §6.3）。
2. **锁竞争**：tokio 共享任务队列对「每包都要更新 allocation 状态」的工作负载不利。本设计把 allocation 表按 **`(client_addr_hash % shard_count)` 分片**，且 UDP 五元组的 client 地址稳定地映射到同一 shard，因此 **99%+ 的包在同核完成，无需跨核同步**。若走 tokio task 抽象，task 与 shard 的绑定关系不可控。
3. **为何不 `smol`**：`smol` 生态（`async-net` 等）活跃度与维护深度弱于 tokio，且它同样受共享调度器排队影响——它解决不了第 1 条的问题，却让我们失去 tokio 的 `axum`/`rustls`/`signal` 生态（管理面、TLS、优雅退出都在这条线上）。**否决。**
4. **为何不 `mio + io_uring` 作为默认**：`io_uring`（SPOLLING + provided buffers）在 Linux 上确实能进一步消除 UDP 收发的 syscall，是吞吐上限最高的选择。但三点使其不能成为默认：
   - **跨平台**：io_uring 仅 Linux 5.6+；本项目的 CI/开发环境明确包含 Windows（Stage 5 已要求 Windows 矩阵项），默认后端必须跨平台。
   - **成熟度**：`io-uring` crate 仍在快速变动 API，把它放在默认路径上等于把项目的编译稳定性挂在一条还在演进的路上。
   - **收益位置**：2 Gbps 的 pps 预算下，epoll 路径已经够用；io_uring 的收益在 10 Gbps+ 或 CPU 受限场景。
   - 因此定为 **feature 可选后端**：接口层 `Transport` trait 隔离，后端实现可替换（`EpollTransport` / `IouringTransport` / `IocpTransport`）。这满足「高内聚低耦合」，且未来升级路径已预留。
5. **为何不纯 `socket2` 裸 UDP + 手写轮询**：`mio` 就是「裸 UDP + epoll」的薄封装（< 200 行关键路径），没有抽象税；手写 epoll 循环是纯负收益（自己维护 WEPOLL/IOCP 分支）。

### 2.3 关键实现约束（写给 Stage 2/3 实现 issue）

1. 每 worker 持有：**1 个 UDP listening socket（`SO_REUSEPORT`）+ 1 个 UDP sending socket + 1 个 relay 源 socket**，全部绑定到该 worker 的核（`pthread_setaffinity_np` / Windows `SetThreadAffinityMask`）。
2. 接收缓冲：per-worker 栈上/`thread_local` 的 `Box<[u8; 65535]>`，**零每包堆分配**；`mio` 的 `read_buf` 直接写入。
3. Linux 上开启 `GRO`（`udp_recvmsg` offload）+ `SO_RCVBUFFORCE` 调优 `net.core.rmem_max`；发送侧 `MSG_MORE` 聚合小包。
4. `SO_REUSEPORT` 的 hash 由内核按四元组完成，天然把同一条 client 五元组固定到一个 worker —— 这是「同核完成」的前提，也是本设计不引入用户态一致性哈希的原因。

---

## 3. 认证与加密

### 3.1 结论

| 项 | 结论 |
| --- | --- |
| STUN Message Integrity（RFC 5389 §11） | **HMAC-SHA1**（`hmac` + `sha1`）。SHA1 在此处仅用于 HMAC，不构成弱哈希风险（HMAC-SHA1 未被有效攻破）。 |
| TURN long-term key（RFC 6051 §12.2.1） | **HMAC-SHA1(key = MD5(password))**。注意：key 派生本身用 MD5 是 RFC 强制要求，必须逐字节实现，不可替换成 SHA1。 |
| TURN ephemeral key | 进程内随机（`getrandom` + ChaCha12），随 nonce 绑定；重启即失效（与 coturn 一致）。 |
| 静态分配 key（RFC 6051 §12.2.2） | `HMAC-SHA1(key = HMAC-SHA1(0x00, user@realm), static_secret)`，逐字节按 RFC。 |
| SHA-256 扩展 | **提供并默认关闭**：`--hmac-sha256` 启用 `MESSAGE-INTEGRITY-256` 作为 Message Integrity 变体（RFC 5769 §3.14 引入，RFC 6051 未采纳）。**coturn 不实现 `MESSAGE-INTEGRITY-256`**（其 `--alt-hmac-sha1` 的含义是「用 HMAC-SHA1 派生 nonce」，与 Message Integrity 算法选择无关），因此本项是 QuickRelay 的**超集能力**，默认关闭以保证与 coturn 及主流客户端的兼容。RFC 7635/8326（TURN over TLS）场景下建议在双端都启用的部署中开启。 |
| nonce 设计 | `base64(timestamp ‖ random) ‖ salt`；包含**时间戳 + 随机熵 + 服务端实例 salt**，用于重放检测与多实例部署；过期窗口 60 s（coturn `--min-nonce-age`/`--max-nonce-age` 对齐，默认 60）。 |
| 常量时间比较 | 所有 MAC / 凭证比较走 `constant_time_eq`（`hmac::Mac::verify` 已保证），自定义处用 `subtle` crate。 |
| 随机数 | `getrandom`（OS CSPRNG）；nonce/transaction id 每包分配走 `ChaCha12`（per-worker 本地 key，避免 per-packet CSPRNG syscall 抖动）。 |

### 3.2 与性能目标的一致性

- SHA1/HMAC-SHA1 的 CPU 成本 ~10 ns/次（SIMD 路径），相对每包 5–20 µs 的处理预算，占比 < 0.5%，不是瓶颈。
- **真正影响 P99 的是 nonce 校验路径上的状态写入**：nonce 时间戳校验走 per-worker 单调时钟（`clock_gettime(CLOCK_MONOTONIC)`，vDSO，无 syscall），不查询全局状态；随机熵部分用 worker 本地 ChaCha12 流，避免 `getrandom` 每 nonce 一次 syscall。

---

## 4. 配置与 CLI

### 4.1 结论

- **CLI**：`clap` 4.x（`derive`），参数集对齐 coturn 常用项（完整映射表由 Stage 4 配置 issue 交付，本设计只锁定清单与命名风格：沿用 coturn 的 kebab-case，如 `--listening-ip`、`--relay-range`、`--use-auth`、`--static-auth-secret`）。
- **配置文件**：**TOML**（`toml` 0.8 + `serde`），文件名 `config.toml`，`--config -` 读 stdin（对齐 coturn 语义）。选 TOML 而不是 INI：coturn 的 `turnserver.conf` 是「每行一个 flag」的伪 INI，键值语义不统一（大量布尔开关无值），迁到 TOML 后类型明确、可被 `serde` 强校验；INI 无法表达 `[relay]` 下的 range 列表与嵌套 TLS 配置。
- **优先级**：`CLI > 环境变量 > 配置文件 > 内置默认`。冲突时以 CLI 为准，且在启动日志中打印「哪些值来自 CLI 覆盖了配置」，便于运维定位。
- **启动即校验**：所有参数在 `Config::validate()` 一次性校验（端口越界、`--no-peer` 与 peer 相关项互斥、`relay-range` CIDR 合法性、证书是否存在/过期），校验失败直接 `process::exit(2)`，绝不降级运行。
- **REST 动态变更**：需求方已确认必须支持，且**仅本次运行内生效，重启回落静态配置，不落外部数据库**。设计为 `ConfigController`（详见架构文档 §5.4），变更对象仅限：限速值、最大 lifetime、临时凭证（`user:pass` 追加）、日志级别。**不可通过 REST 修改**：监听地址、relay-range、TLS 证书、认证模式——这些变更必须重启，避免运行中破坏状态表不变式。

---

## 5. 可观测性

### 5.1 结论

- **指标**：数据面用 `metrics` crate 的 `Counter`/`Gauge`（底层 `AtomicU64`，热路径零格式化、零锁、零堆分配）；由 `metrics-exporter-prometheus` 定时聚合并暴露于 `/metrics`。
- **高基数例外**：按错误码分桶的计数（`437 ALLOCATION MISCONFIGURED` 等约 20 个取值）用 `prometheus::HistogramVec` 直接注册——基数有界（< 32），直接注册可接受。
- **Prometheus 命名**：与 coturn 的 turnadmin/stats 语义对齐但采用 Prometheus 命名规范（`quickrelay_*` 前缀），映射表由 Stage 4 可观测性 issue 交付。关键指标（本设计锁定）：
  - `quickrelay_allocations_active`（gauge，按 shard 上报）
  - `quickrelay_packets_total{direction,kind}`（binding_request / allocate / relayed / peer / data / channel / 未知）
  - `quickrelay_bytes_total{direction,kind}`
  - `quickrelay_responses_total{error_code}`
  - `quickrelay_auth_failures_total{reason}`（bad_username / bad_realm / bad_nonce / bad_integrity / replay）
  - `quickrelay_tls_connections_total`、`quickrelay_tls_handshake_seconds`（histogram）
  - `quickrelay_worker_poll_lag_seconds`（histogram，事件循环延迟，判断尾延迟的来源）
  - `quickrelay_timeout_reclaims_total{kind}`（allocation / permission / channel）
  - `quickrelay_udp_rmem_drops_total`（Linux `UDP_MIB_RCVbufErrors` 差分读取）
- **日志**：`tracing` + `tracing-subscriber`，支持 JSON / 文本两种 format，stdout / file / syslog 目标可配。**硬约束：每包路径不得打日志**（日志只记录事件：连接建立、allocation 创建/回收、错误率突增、TLS 握手失败、认证失败原因聚合）。PII：默认不打印完整 nonce 与口令，用户名可打（但可配 `--mask-username`）。
- **健康检查**：`/healthz`（进程存活）、`/readyz`（全部 worker 事件循环 lag < 100 ms 且监听端口可绑）。

---

## 6. 被否决方案汇总（每条至少一条反驳）

| 方案 | 结论 | 主要反驳 |
| --- | --- | --- |
| 复用 `sippusher/turn` 作协议栈/引擎 | 否决 | 2018 年后停更；`async-std` 依赖树与 tokio 1.x 冲突；RFC 7635/6062 覆盖不全而本项目要求必须支持；把核心验收面外包给无人维护的中间层 |
| 复用 `stun-rs` 系 crate 作编解码 | 否决 | 客户端定位而非服务器定位；协议层热路径需要零分配与可控错误预算，第三方 API 是障碍；编解码可用 RFC 附录逐字节测试自验 |
| `smol` 运行时 | 否决 | 共享调度器仍引入就绪→执行的排队抖动，不能解决 P99；生态（axum/rustls/signal）深度不足 |
| `io_uring` 作默认后端 | 否决（作为可选 feature 保留） | Linux-only，与 Windows CI 矩阵冲突；crate API 尚在演进；2 Gbps 下 epoll 预算已足够 |
| 纯 tokio `UdpSocket` 承载数据面 | 否决 | 调度排队延迟不可控；task↔shard 绑定不可控，破坏「同核完成」不变式 |
| INI 配置文件 | 否决 | 无法表达嵌套 TLS/range 配置；键值语义不统一；`serde` 强类型校验只支持 TOML 路线 |
| gRPC 管理面 | 否决 | 需求方只要求 REST；无双向流需求，gRPC 收益为负 |
| 消息体走堆分配 `Vec<u8>` | 否决 | 每包堆分配在 2 Gbps 下意味着每秒百万级 malloc/free；用 `thread_local` 栈缓冲 + `Bytes` |
| 全局大锁状态表 | 否决 | 与 20 万级分片容量目标直接冲突；改为按核分片 + 分片内无锁 |
