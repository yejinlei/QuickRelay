# QuickRelay 整体架构设计

状态：定稿（**v2，2026-09-16 修订**）。本文档是 Stage 2–5 全部实现 issue 的唯一设计依据。

v2 修订内容（由 [YEJ-167] 交付，口径来源为需求方 2026-09-15 15:19「按默认走」的六项拍板）：

| 变更点 | v1 表述 | v2 表述 |
| --- | --- | --- |
| 设计余量（§0 / §4.1 / §5.2 / §6.1 / §7.1 / §11） | 状态表按 200,000 allocation 设计（~160 MB） | allocation 上限 **~5,000**（10× 抗突发），状态表常驻 **~16 MB** |
| REST 可变更范围（§9.1） | 只此两个变更端点，明确拒绝扩张 | 限速 / 流开关 / 认证 / 可观测性 **4 类**，逐键列全并标注生效粒度 |
| 回滚语义（§9.4） | 无 DELETE，临时凭证只增不减 | `DELETE` 单键回滚到启动值；凭证类键删除返回 **409** |
| REST 鉴权（§9.5） | 仅 `--api-token` 静态令牌 | Bearer token + HMAC 请求签名**双支持**，可各自开关、可同时启用 |
| 横向扩容（§7.4 新增） | 未定义 | 多实例 + relay-range 端口段划分 + 认证 key 命名空间隔离 |
| 压测 / 验收引用（§11 / §12） | 目标 200,000 allocation 稳态 | 以 [YEJ-135] 的 500 路 / 2 Gbps / P99 < 1 ms（UDP）为准；[YEJ-137] 的 200k 压测项**不得作为验收目标** |

> 一致性提示：[YEJ-137]（性能基线）中 P1 / P11 / P12 / P17 的 200,000 allocation 数字是 Stage 1 定稿前的暂定值，**已被 [YEJ-135] 与本次拍板取代**。本架构不以 200,000 为容量承诺；那些压测项在 [YEJ-151] 执行时按 5,000 allocation 实测重跑并记录拐点（见 §7.1 与 §12）。

---

## 0. 设计目标与硬约束

| 项 | 值 | 来源 |
| --- | --- | --- |
| 并发规模 | 单机 **500 路用户视频**（容量下限，非上限） | [YEJ-135] 权威口径 |
| 吞吐容量 | **2 Gbps 双向**（含 STUN/TURN 控制流与 TLS 握手开销） | 同上 |
| 分配类时延 | Allocate / Refresh / Stop **P99 < 1 ms**（**UDP 路径**） | [YEJ-135] 权威口径 |
| TLS over TCP 分配类时延 | **P99 < 5 ms**——含 TLS 记录层 + TCP 拷贝，**不适用** 1 ms 承诺 | 同上 |
| 单实例设计余量 | allocation 上限 **~5,000**（≈ 10× 500 路的抗突发余量），状态表常驻 **~16 MB** | 需求方 2026-09-15 15:19 拍板「按默认走」（C 项）；压测后可上调，拐点由 [YEJ-151] 记录（§7.1） |
| 横向扩容 | **多实例 + relay-range 端口段划分 + 认证 key 命名空间隔离**；扩容粒度是整实例 | 同上；详见 §7.4 |
| 协议矩阵 | STUN over UDP、TURN over UDP、TURN over TCP、TURN over TLS（RFC 7635 必须 / RFC 8326 必须 / RFC 6061 仅接收兼容）、ICE-TCP **全部必须** | 需求方确认（2026-09-15「两者都做」） |
| 配置 | 静态配置（文件 + CLI）+ REST 动态变更（**仅本次运行内生效**，重启回落静态配置，不落外部 DB、无持久化审计库）；可临时变更项 4 类，`DELETE` 单键回滚（凭证类键 409） | 需求方确认；详见 §9 |
| REST 鉴权 | Bearer token 与 HMAC 请求签名**双支持**，可各自开关、可同时启用 | 需求方确认（2026-09-15）；详见 §9.5 |
| 合规 | 不复用 coturn 代码；测试资产仅「读取行为规格并转写」，不 vendor 脚本或代码 | 需求方确认 |

### 0.1 issue 文本勘误（架构侧必须记录）

任务文本写「TURN over TLS（RFC 6061 / DTLS over UDP）」。技术事实是：

- **RFC 6061（TURN over TLS over UDP，2010）已被 RFC 9263 标记为 obsoleted**——其威胁模型依赖的「每包 TLS 记录加密」在实践中被证明容易被中间盒破坏，且主流 WebRTC 客户端栈（libwebrtc、ORTC 实现）**不实现 RFC 6061**。
- WebRTC 客户端实际使用的「TURN over TLS」是 **RFC 7635（UDP-over-TLS）**：STUN/TURN 消息作为 UDP 数据报封装进 TLS 1.3 记录，UDP-over-TLS 协商靠 TLS 的 ALPN/SNI 扩展识别。这是 **coturn `--use-tls` 的实际语义**，也是 libwebrtc 唯一支持的路径。
- 因此本设计的「TURN over TLS = **必须支持**」落地为：
  1. **UDP-over-TLS（RFC 7635）——必须实现**（WebRTC 客户端的必需路径，对齐 coturn `--use-tls`）；
  2. **TLS over TCP（RFC 8326）——必须实现**（TURN over TCP + TLS，WebRTC TURN over TCP 的默认协商）；
  3. **RFC 6061（TURN over TLS over UDP）——仅实现接收兼容，不作为主要路径**，且在文档中明确标注「RFC 9263 已 obsoleted，客户端普遍不支持」。**这是本设计与 issue 文本的唯一偏差，理由如上；如需求方要求以 RFC 6061 为主路径，需重新评估客户端兼容性。**

### 0.2 术语

- **allocation**：一次 `Allocate Success` 建立的转发关系，含 relay 地址、生命周期、权限集合、channel 集合。
- **shard**：状态表按核分片，每个 shard 独占一个 worker 线程，**跨 shard 永不共享可变数据**。
- **worker**：单线程事件循环，绑定单核。

---

## 1. 组件图

```
                        ┌────────────────────────────────────────────────────────────┐
                        │                    quickrelay（单进程）                      │
                        │                                                            │
  STUN/TURN 客户端 ─────┤  UDP listening socket  ┐  SO_REUSEPORT（内核按四元组分发）    │
  (WebRTC / ICE)       │  ┌─────────────────────┴───────────────────────┐            │
  TCP/TLS 客户端 ──────┤  │   Worker 0 (affinity core0)                │              │
                        │  │   mio::Poll + EpollTransport (或 Iouring) │              │
                        │  │   ├── BindingHandler                     │              │
                        │  │   ├── TurnHandler ──► AllocShard[0] ────┐│              │
                        │  │   └── Forwarder ────► PeerShard[0]     ─┤│              │
                        │  └─────────────────────────────────────────┘│              │
                        │  ┌─────────────────────────────────────────┐│              │
  ICE-TCP / TLS-over-   │  │   TCP Listener (tokio)                  ││              │
  TLS 客户端 ───────────┤  │   ├── rustls acceptor (RFC 8326)       ││              │
                        │  │   └── TcpTurnHandler ──► 同 AllocShard ││              │
                        │  └─────────────────────────────────────────┘│              │
                        │  ┌─────────────────────────────────────────┐│              │
  监控 / REST 客户端 ────┤  │   axum 控制面 (tokio, 独立核组)         ││              │
                        │  │   /metrics /healthz /readyz /api/v1/*   ││              │
                        │  │   ├── ConfigController (热变更)         ││              │
                        │  │   └── CredentialProvider trait ──┐      ││              │
                        │  └──────────────────────────────────┼──────┘│              │
                        │                                     ▼      │              │
                        │  ┌─────────────────────────────────────────┐│              │
                        │  │   quickrelay-protocol（无锁、无 I/O）      ││              │
  ──────────────────────┤  │   msg codec / integrity / attributes      ││              │
                        │  └─────────────────────────────────────────┘│              │
                        │                                             │              │
                        └─────────────────────────────────────────────┴──────────────┘
                                             │
                          转发数据面（同一进程内，无 IPC）
                                             ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  Relay 源 socket (bind 到 relay-ip)  ─►  relayed 字节流      │
   │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐    │
   │  │ Relayed path │   │  Peer path   │   │ Data/Channel │    │
   │  │ client→peer  │   │ peer→client  │   │ path         │    │
   │  └──────────────┘   └──────────────┘   └──────────────┘    │
   └─────────────────────────────────────────────────────────────┘
```

### 1.1 crate 划分（workspace）

```
quickrelay/
├── Cargo.toml                 # workspace
├── crates/
│   ├── quickrelay-protocol/   # 纯协议层：STUN/TURN 编解码、integrity、attribute 表
│   │                          #   依赖：bytes, hmac, sha1, sha2
│   │                          #   无 I/O、无锁、无 tokio —— 可独立单测与 fuzz
│   ├── quickrelay-core/       # 状态层：AllocShard、PeerShard、状态机、time wheel、
│   │                          #   限速桶。依赖 quickrelay-protocol；无 I/O
│   ├── quickrelay-transport/  # I/O 层：EpollTransport / IouringTransport / IocpTransport、
│   │                          #   socket2 封装、TLS 记录层（RFC 7635 / 8326）
│   ├── quickrelay-auth/       # 认证：nonce、long-term/ephemeral/static key、
│   │                          #   CredentialProvider trait
│   ├── quickrelay-config/     # 配置：clap + serde + toml、ConfigController 热变更
│   ├── quickrelay-metrics/    # 指标 + 健康检查 + REST 端点（axum）
│   └── quickrelay-server/     # 组合层：worker 启动、装配、信号处理（最终二进制）
├── docs/
├── scripts/
└── config.example.toml
```

**依赖方向（单向，禁止反向）**：

```
quickrelay-server ──► core ──► protocol
              │        │
              ├──► transport ──► protocol
              ├──► auth ──► protocol
              ├──► config
              └──► metrics
```

- `protocol` 与 `core` 禁止依赖 `tokio` / `mio` —— 保证它们可以在无异步环境下 100% 单测 + fuzz。
- `transport` 只通过 `Transport` trait 与 `core` 交互，不直接持有 `AllocShard`。
- `server` 是唯一允许做依赖装配的 crate。

---

## 2. 进程与线程模型

### 2.1 结论

**单进程 + 「worker 线程组 + 控制面线程池」双区模型；worker 严格绑核、线程内无锁；数据面不经过 tokio task 调度。**

| 区 | 线程数 | 运行时 | 职责 |
| --- | --- | --- | --- |
| Worker 区 | `n_workers`（默认 = 物理核数，可通过 `--n-workers` 限制） | 裸 `std::thread` + `mio::Poll` | UDP 收发、STUN/TURN 处理、转发、状态表分片 |
| Relay 发送区 | 1（复用 worker 线程） | 裸线程 | 同一 worker 的 relay 源 socket 发送（零拷贝出站） |
| TCP 区 | 1 | `tokio::rt::Builder::new_current_thread().enable_all()` | TURN over TCP / TLS over TCP 的 accept 与流式收发 |
| 控制面区 | 4（默认，`--n-control-threads`） | `tokio` 多核运行时 | axum 路由：`/metrics`、`/healthz`、`/readyz`、REST 动态变更 |
| 回收区 | 0 | —— | 无独立回收线程；超时回收由 worker 在事件循环内按 tick 完成 |
| 统计聚合区 | 1 | `tokio` spawn | 每 10s 把 `metrics` Registry 聚合进 Prometheus 导出器 |

### 2.2 为何不用 `SO_REUSEPORT` + 每核 worker vs io_uring 之外的第三种模型

| 候选模型 | 结论 | 理由 |
| --- | --- | --- |
| **A. SO_REUSEPORT + 每核 worker**（采纳） | 默认 | 内核按四元组 hash 分发，天然把同一条 client 五元组固定到一个 worker → **同核完成状态更新，零跨核同步**；每 worker 独占一个 `Poll` 实例，就绪→执行无调度排队，P99 可控；`SO_RCVBUFFORCE` + 每 worker 独立 rcvbuf，无全局丢包点；Windows 上 `SO_REUSEPORT` 可用（Windows 10 1709+），跨平台成立 |
| B. 单 socket + `fork`/多进程 + `SO_REUSEADDR` | 否决 | 进程间状态同步必须走共享内存 + 原子操作，等于自己实现一遍无锁分片；且 crash 恢复与信号处理复杂度高一个量级 |
| C. `io_uring` 单线程（SPOLLING） | 否决为默认，保留为 feature | 见技术选型 §2.2；Linux-only，与 Windows CI 矩阵冲突 |
| D. tokio 全局 task + 全局锁状态表 | 否决 | 调度排队抖动破坏 P99；全局锁破坏分片不变式 |

### 2.3 worker 内部结构

每个 worker 是一次 `loop { poll + drain }`，**无 channel、无 spawn**：

```
Worker::run(self) -> !
  loop:
    ready = poll.poll(timeout=1ms)          // mio::Poll, 无 task
    for event in ready:
      match event:
        udp_listening.read(buf) -> handle_udp_packet(buf, from)
        udp_relay.read(buf)     -> handle_relay_packet(buf, from)
        tcp_stream.ready        -> handle_tcp_turn(...)
    tick:                                    // 每 poll 周期执行一次，O(活跃事件数)
      time_wheel.advance(now)               // 触发 allocation/permission/channel 到期
      for expiring in time_wheel.drain_deadline(now):
        core.shard.reclaim(expiring)
      poll_lag.observe(elapsed_since(last_iteration))
```

关键点：
1. **`poll(timeout=1ms)`**：1 ms 上限保证超时回收的延迟抖动 ≤ 1 ms，同时避免空转。
2. **同一 UDP 五元组在同一 worker 处理**：`SO_REUSEPORT` 保证，无需用户态哈希。
3. **状态表按 worker 索引分片**：`shard_idx = worker_idx`，无跨 shard 路由。
4. **`SO_RCVBUF` 每 worker 独立**：`--udp-rbuf-size`（默认 4 MB，Linux 建议 32 MB + `SO_RCVBUFFORCE`）。

---

## 3. UDP 收发路径与 Allocate 时序

### 3.1 接收路径（`client → server`，以 Allocate Request 为例）

```
① 内核 UDP 协议栈
     └──► ② SO_REUSEPORT hash(四元组) ──► 选中 Worker N 的 listening socket
              └──► ③ epoll 就绪（EpollTransport）
                     └──► ④ recvmsg 直写 worker 线程栈上 buf: [u8; 65535]
                            （Linux: recvmsg + MSG_DONTWAIT；io_uring feature: provided buffer）
                            └──► ⑤ quickrelay-protocol::Message::parse(buf)
                                   零拷贝 Bytes，校验：
                                     - 长度 ≥ 20、长度 4 对齐、长度 ≤ 65535
                                     - magic cookie == 0x2112A442
                                     - message type 已知
                                     - FINGERPRINT / MESSAGE-INTEGRITY 顺序（§6.1）
                                      └──► ⑥ IntegrityChecker::verify(msg, key)
                                              HMAC-SHA1 校验（常量时间）
                                              └──► ⑦ ShardRouter: shard_idx = worker_idx
                                                     （SO_REUSEPORT 已保证）
                                                     └──► ⑧ TurnHandler::on_allocate(&mut AllocShard, msg)
                                                            - 查现有 allocation（按 (user, relay_addr)）
                                                            - 校验 USERNAME/REALM/NONCE
                                                            - 分配 relay 地址（从 RelayPool，O(1)）
                                                            - 写 AllocEntry + 插入 TimeWheel
                                                            - 构造 Allocate Success
                                                              （XOR-RELAYED-ADDRESS / LIFETIME /
                                                                XOR-MAPPED-ADDRESS / XOR-PEER-ADDRESS /
                                                                SOFTWARE / D4-LIMIT /
                                                                FIVE-TUPLE-LIMIT）
                                                            └──► ⑨ 组帧 + 追加 MESSAGE-INTEGRITY
                                                                   （+ UNKNOWN-ATTRIBUTES，+ FINGERPRINT）
                                                                    └──► ⑩ sendmsg from worker 的 sending socket
                                                                           到 (client_ip, 0)
                                                                           —— 见 §4.3「端口 0」语义
```

### 3.2 转发路径（Relayed 流，稳态）

```
client ──UDP──► server:relayed_port
  └──► ① SO_REUSEPORT → Worker N
        └──► ② recvmsg → buf（零分配）
              └──► ③ AllocShard::lookup_relayed(from)     ← O(1) 开放寻址哈希
                     （key = (client_ip, client_port)，来自五元组，不解析 STUN 报文）
                     └──► ④ 命中：返回 AllocEntry（含 peer_addr、限速桶、expiry）
                     │    未命中：DROP + 计数（不进错误响应路径，避免响应风暴）
                     └──► ⑤ RateLimiter::try_consume(bytes)  ← 每 allocation 令牌桶，O(1)
                     │    超限：DROP + 计数（D4-LIMIT 已在 Allocate 应答中告知上限）
                     └──► ⑥ RelayPool::send(peer_addr, buf)  ← 直接 sendmsg，无拷贝
                          （buf 是同一块栈缓冲，零拷贝）
```

**Peer 流**（`peer → client`）走 `PeerShard::lookup_peer((peer_addr, relayed_addr))` 反向索引，语义对称。

**Data 流**：与 Relayed 流相同的接收，但目标地址是 relay 自身；出方向需**重写源地址为 `XOR-MAPPED-ADDRESS`**——这是唯一需要修改载荷的转发路径。

**Channel 流**：`CHANNEL-NUMBER + DATA` 解包（`core` 内 `ChannelTable` O(1) 查），然后走 Peer 流；出方向需打包一次（**唯一的每包拷贝点**，量化见 §7.2）。

### 3.3 关键性能不变式

| 不变式 | 保证 |
| --- | --- |
| 单包处理无堆分配 | `thread_local` 栈缓冲 + `Bytes` 零拷贝；唯一例外是 ChannelData 解包（见 §7.2） |
| 单包不跨核 | `SO_REUSEPORT` 四元组 hash + shard 按 worker 索引 |
| 单包路径上无线程同步 | 无 mutex、无 channel、无 atomics（除 `metrics` 计数器） |
| 超时回收非 O(N) | 分层 time wheel，O(1) 插入 / O(k) 触发（k = 本 tick 到期数） |
| 错误响应不产生网络放大 | 未知/畸形包只计数不响应；仅对**已认证且 transaction id 匹配**的 STUN 请求产生错误响应 |

---

## 4. 数据结构

### 4.1 Allocation 表（`AllocShard`）

**按 worker 分片，每 shard 独立。主索引开放寻址哈希，key = `(user_hash, realm_hash, relay_addr)`。**

```rust
// quickrelay-core/src/allocation.rs（伪代码，字段布局按内存对齐设计）
pub struct AllocShard {
    entries:     Vec<AllocEntry>,           // 桶数组，容量 = 目标 allocation 数 / load_factor
    occupied:    Vec<u8>,                   // 状态位：EMPTY/OCCUPIED/DELETED
    free_list:   Vec<usize>,                // 空闲桶栈，O(1) 分配/回收
    by_relayed:  HashMap<SocketAddr, usize>,// relayed_addr → entry index（relayed 流反查）
    stats:       ShardStats,                // 本 shard 计数（无锁，worker 私有）
    next_id:     u64,
}

pub struct AllocEntry {
    // —— 身份（32 字节内固定）
    pub client:      SocketAddrV4Mapped,     // 16 字节，统一 16 字节表示 IPv4/IPv6
    pub relay_addr:  SocketAddrV4Mapped,     // 16 字节
    pub id:          u64,
    pub user_hash:   u64,                    // FNV-1a(username)
    pub realm_hash:  u32,
    pub user_len:    u8,
    pub user_buf:    [u8; 64],               // 定长，避免每 allocation 堆分配
    // —— 状态
    pub state:       AllocationState,        // NONE / ALLOCATED / SENT / BOUND（4 状态）
    pub peer:        Option<SocketAddr>,      // BOUND 后设置
    pub lifetime:    Duration,
    pub expires_at:  Tick,                   // time wheel 用的绝对 tick
    // —— 权限与通道（内嵌小数组，溢出才走堆）
    pub permissions: SmallVec<PermEntry, 4>, // 内联 4 个，WebRTC 通常 1-2 个
    pub five_tuple:  [FiveTupleEntry; 4],
    pub channels:    [ChannelEntry; 8],      // RFC 6062 建议服务端限制数量
    // —— 限速
    pub rate:        RateLimiter,            // 字节桶 + 包桶（各 24 字节）
    // —— 统计
    pub bytes_up:    u64,
    pub bytes_down:  u64,
    pub pkts_up:     u32,
    pub pkts_down:   u32,
}
```

**容量与内存预算**：`AllocEntry` 布局后约 **512 字节**（含 8 字节对齐 padding）。按 **~5,000 allocation 上限**：状态表本体 5,000 × 512 B ≈ **2.5 MB**，开放寻址表 32 字节/槽 × 6,250 槽 ≈ **0.2 MB**，`free_list` ≈ 0.04 MB。Peer 反查表 5,000 × 2 条 × 104 B ≈ **1 MB**。**每 allocation 约 550 字节常驻**（含 Peer 反查摊算）。全部状态表常驻合计 **~4 MB**，含 time wheel / 栈缓冲 / TCP 句柄的进程级常驻预算见 §7.1（合计 **~16 MB**）。

### 4.2 Peer 反查表（`PeerShard`）

**Peer 流（`peer → client`）的反查索引，独立于 allocation 表，因为它的 key 是 `(peer_addr, relayed_addr)`，与 allocation 表的主键不同。**

```rust
pub struct PeerShard {
    // 开放寻址，key = (peer_addr, relayed_addr) 组合哈希（22+22=44 字节）
    entries: Vec<PeerEntry>,
    occupied: Vec<u8>,
}

pub struct PeerEntry {
    pub peer:       SocketAddr,       // 22
    pub relay_addr: SocketAddr,       // 22
    pub client:     SocketAddr,       // 22
    pub expiry:     Tick,             // 8
    pub shard_worker: u32,            // 4 —— 允许跨 worker 反查（见下）
    // 共 104 字节，8 字节对齐 → 104
}
```

**跨 worker 说明**：peer 发来的包经 `SO_REUSEPORT` 后落到**任意 worker**（因为 key 含 relayed 端口，hash 不一定等于原 allocation 的 worker）。此时：
- 若 `shard_worker == current_worker`：**同核直接处理**（绝大多数情况，因为 peer 与 relay 端口的四元组是稳定的）。
- 否则：查本 worker 的**共享只读缓存** `PeerRouteCache`（`RwLock` 保护的 `HashMap`，只在 allocation 创建/销毁时写入，读多写极少），拿到目标 worker 索引，然后通过 **worker 间无锁队列**（`crossbeam::flume` 无锁 MPSC，每对 worker 一条）投递转发。

**这是本设计中唯一引入跨核同步的地方**，且只在 peer 流冷路径触发。WebRTC 场景下绝大多数 relayed 流不需要它（client→peer 方向的转发在同核完成）。

### 4.3 地址池（`RelayPool`）

- **按地址段 + 端口 range 切块**：`relay-range = 192.0.2.0/24,3478-3487` 表示 256 IP × 10 port = 2560 地址槽。
- 每 worker 持有**独立子池**（把地址槽按 worker 数切分），O(1) 分配（预分配数组 + 位图），无锁。
- **端口 0 语义**：STUN/TURN 请求若源端口为 0，服务端用**同一源端口**回应（coturn 行为，避免 NAT 映射被破坏）。实现为：worker 的 sending socket 对源端口 0 的目标使用 `SO_REUSEADDR` 绑定到 0 端口的专用 socket（Linux 上 `UDP bind to port 0 with SO_REUSEADDR`），或用 `sendmsg` 的 `IP_PKTINFO`/`SO_BINDTODEVICE` + `GRND` 回环路径。**明确结论：使用 Linux `bind(0)` + `SO_REUSEADDR` 的多 socket 池（每 worker 预建 1024 个源端口 0 发送 socket），Windows 上降级为「源端口为 0 的包改用 sending socket 的正常源端口发送 + 记录告警」**，因为 Windows UDP 不支持 bind-to-port-0 的语义。此差异写入文档与运维手册。
- 地址耗尽 → `508 Insufficient Capacity`（RFC 6051 §12.1.17），且**不重试、不回收**（回收入 queue）。

### 4.4 会话/连接表（TCP 与 TLS 路径）

TURN over TCP / TLS over TCP 的连接由 `tokio` 的 `TcpTurnHandler` 管理，但**状态与 UDP 路径共享同一份 `AllocShard`**——`Allocate` 在 TCP 上建立时，`client` 字段填的是 TCP peer 地址，转发出口走同一个 `RelayPool`。因此**没有单独的「TCP 会话表」**，只有 allocation 表；TCP 侧只额外持有「连接句柄 → allocation id」的 `HashMap`（每连接 32 字节，500 路场景下 16 KB 量级）。

---

## 5. 超时与回收策略

### 5.1 回收对象与时钟

| 对象 | 默认值 | 依据 |
| --- | --- | --- |
| Allocation lifetime | 默认 300 s，`--max-alloc-lifetime` 上限，`--min-timeout`/`--max-timeout` 裁剪 | RFC 6051 §13.3 |
| Refresh 后的剩余 lifetime | 每次 `Refresh` 重置为配置值，上限裁剪 | RFC 6051 §6.8 |
| 5-tuple permission | 600 s（`--max-timeout`） | coturn 默认 |
| Permission（peer 地址，无限速） | 2 h（`--permission-lifetime`） | coturn 默认 |
| Channel（`CHANNEL-NUMBER` 绑定） | 跟随 permission 过期 | RFC 6062 |
| Nonce | 60 s（`--max-nonce-age` 默认 60，可调至 coturn 默认 3600） | 见协议矩阵 §5 |
| 空闲 allocation 检测 | 无独立空闲超时；lifetime 到期即回收 | 简化 |
| STUN 事务（服务端不缓存事务，只回包） | N/A | 无状态 |

### 5.2 回收实现：分层 time wheel

**否决全局扫描**：即使只有 ~5,000 allocation，每 1 s 全表扫描也会把「回收」变成与 allocation 总数线性相关的固定成本，污染 P99；分片 time wheel 把每 tick 成本压到 O(1 + 到期数)，使回收延迟与规模解耦。改为：

```
三层 time wheel：
  第 1 层：64 tick × 100 ms = 6.4 s 分辨率（channel/permission 短期项）
  第 2 层：64 tick × 2 s   = 128 s 分辨率（allocation 300 s 以内）
  第 3 层：64 tick × 64 s  = 64 min 分辨率（permission 2 h）

  插入：O(1)，写入对应 tick 的链表
  到期：每 poll 周期 advance(now)，只处理本轮 tick 到期的链表，O(k)
  回调：AllocShard::reclaim(id) → free_list.push(id) + PeerShard::remove + metrics
```

- 每 worker **独立 time wheel**（与 shard 对齐），无锁。
- 回收与状态更新在同一 poll 周期内完成，**不存在「已到期但状态未清」的窗口**（唯一可见副作用是回收前最后几毫秒的转发，与 coturn 行为一致）。
- 复杂度声明（写进测试）：`time_wheel.advance` 的每 tick 成本是 O(1 + 到期数)，不随 allocation 总数增长。

### 5.3 回收与「分配地址复用」的间隔

回收后立即把 relay 地址放回 `RelayPool`。为避免 **NAT/中间盒 用旧地址误命中**，地址复用间隔设为 **30 s 最小冷却**（写入回收队列后延迟 30 s 再入池）。这是 coturn 的 `--min-alloc-lifetime` 语义之一。

---

## 6. 拥塞与限速策略

### 6.1 分层限速

| 层 | 机制 | 默认 | 超限行为 |
| --- | --- | --- | --- |
| 全局 allocation 数 | 硬上限（`--max-alloc`，默认 **5,000**） | 5,000 | 拒绝新 Allocate，返回 `487` |
| 全局端口池 | 地址槽耗尽即 `508` | 池容量决定 | `508 Insufficient Capacity` |
| 每 allocation 字节速率 | 令牌桶（`--max-bps` / `--max-bw`） | 不限速 | 丢包 + 计数；上限值经 `D4-LIMIT` 在 Allocate 应答中告知 |
| 每 allocation 包速率 | 令牌桶（`--max-rate`） | 不限速 | 丢包 |
| 每 allocation 5-tuple 数 | 上限（`--five-tuple-limit`，默认 300） | 300 | `487` + 拒绝新 5-tuple |
| 每 client STUN Binding 速率 | 令牌桶（`--stun-rate-limit`，默认 100 pps） | 100 | **静默丢弃**（不响应，防 STUN 洪水） |
| 每 client allocation 数 | 上限（`--max-allocations-per-client`，默认 8） | 8 | `487` |
| 未知/畸形包 | 速率上限（`--unknown-rate-limit`，默认 1000 pps） | 1k | 超限时直接不处理，只计数 |

### 6.2 拥塞信号与背压

- **`udp_rcvbuf_drops`**：Linux 定期读 `/proc/net/udp` 的 `RcvbufErrors`，Prometheus 指标暴露；超过阈值时**自动提升该 worker 的 `SO_RCVBUF`**（`--auto-rcvbuf`，默认开启，上限 64 MB）。
- **worker poll lag**：`quickrelay_worker_poll_lag_seconds` 的 P99 超过 10 ms 时，控制面记录告警事件（不自动降级——降级会破坏 P99 承诺的一致性）。
- **TCP/TLS 连接数**：硬上限 `--max-tcp-connections`（默认 50,000），超限拒绝新连接（不产生错误响应，直接 RST）。

### 6.3 时延预算（分配类 P99 < 1 ms 的静态论证）

| 环节 | 预算 |
| --- | --- |
| 内核 UDP 入站 + epoll 唤醒 | 100–500 µs（取决于 rcvbuf 与 GRO） |
| `recvmsg` | 20 µs |
| 消息解析（20–300 字节，零拷贝） | 5 µs |
| HMAC-SHA1 校验 | 10 µs |
| allocation 查表 + 地址池分配 | 3 µs |
| 组帧 + 追加 integrity | 5 µs |
| `sendmsg` | 20 µs |
| **合计** | **~170–560 µs，P99 < 1 ms 有 2× 以上余量** |

**注意**：以上预算不含 TLS 路径（TLS 握手与加密是独立的 CPU 成本，见 §8.2）。

### 6.4 错误处理与日志规范

#### 错误模型

- `quickrelay-protocol::DecodeError`：枚举，含 `Malformed` / `WrongMagic` / `UnknownType` / `IntegrityFailed` / `MissingAttribute` / `LengthMismatch`，**不含 panic**。
- 传输层错误（`sendmsg` 失败、socket 关闭）→ `TransportError`，worker 记录计数并**重试一次**，第二次失败计入 `quickrelay_transport_errors_total` 并继续处理后续包（**绝不让单包失败终止 worker**）。
- 状态机非法迁移 → 返回 RFC 6051 规定的错误码（见协议矩阵 §4），并**不改变当前状态**（幂等）。
- 内部不可恢复错误（如 `RelayPool` 结构损坏）→ `fatal!` + 优雅退出（`/readyz` 先返回 503，5 s 后进程退出，PID 1 环境由 systemd 重启）。**这是唯一允许 panic 的路径**。

#### 日志规范

- 框架：`tracing`，`tracing-subscriber` 输出 JSON 或文本。
- **每包路径禁止日志**（硬约束，Stage 2/3 代码评审项）；只在事件级打点：
  - `allocation_created` / `allocation_reclaimed`（**采样**：默认每 1000 次一条，`--log-sample-rate`）
  - `tls_handshake_failed`（含对端地址、错误原因，不含证书内容）
  - `auth_failed`（含 USERNAME + 原因分类，**不含 nonce 全文**）
  - `worker_poll_lag_warning`（P99 > 10 ms）
  - `rcvbuf_drop_detected`
  - `config_changed`（REST 变更，含变更前后值）
- PII：默认不打印完整 nonce、不打印口令；用户名可打但可配 `--mask-username`。
- 日志级别：`trace` / `debug` / `info` / `warn` / `error`，**热路径日志一律 `trace`**（默认关闭）。
- 错误码计数**必须**走 Prometheus（结构化），日志只承担「上下文」职责。

---

## 7. 内存模型

### 7.1 常驻内存预算（500 路视频，单实例上限 ~5,000 allocation）

| 项 | 500 路实际 | ~5,000 上限 | 计算 |
| --- | --- | --- | --- |
| AllocEntry | 256 KB | 2.5 MB | 500 × 512 B / 5,000 × 512 B |
| 开放寻址表 | 32 KB | 0.2 MB | 1.25× 负载因子，32 B/槽 |
| PeerEntry 反查 | 128 KB | 1 MB | 假设 2 条/alloc，104 B/条 |
| TimeWheel | 64 KB | 64 KB | 与总量无关 |
| 栈缓冲（per worker） | 64 KB（8 worker） | 64 KB | 65,535 B + 控制 |
| TCP/TLS 句柄 | 32 KB | 0.2 MB | 32 B/连接，按 5,000 连接上限 |
| ConfigController / REST 控制面 | — | 16 MB | 运行态配置副本、鉴权态、指标注册表、RwLock 与 axum 路由（控制面主导项） |
| **合计** | **~0.7 MB** | **~16 MB** | |

**结论**：单实例状态表本体 ~4 MB，进程常驻预算 **~16 MB**（控制面是主要占位）。这是 [YEJ-135] 500 路视频的 **10× 抗突发余量**，不是目标上限。

**时延承诺的适用范围（重申，防止口径混淆）**：

- Allocate / Refresh / Stop **P99 < 1 ms 仅承诺 UDP 路径**（静态论证见 §6.3，合计 ~170–560 µs）。
- **TLS over TCP 路径不适用 1 ms 承诺**，架构口径 **P99 < 5 ms**（TLS 记录层 + TCP 拷贝成本见 §8.2）。
- UDP-over-TLS（RFC 7635）路径的分配类时延在 1 ms 承诺内评估，握手成本摊销在启动期。

**10× 是压测后可上调项**：本设计的状态表分片、开放寻址桶数组与 time wheel 都是容量无界的线性结构，上调 `--max-alloc` 不需要改架构。上调前的前置条件是 [YEJ-151] 记录到的拐点：

1. 端口上限——§4.3 的 relay 地址槽与 §6.1 的端口池必须先证明可支撑（这是更大量级能否成立的唯一硬前置，不是内存）；
2. worker poll lag 在目标并发下的 P99 仍 < 1 ms；
3. [YEJ-151] 必须给出「并发 allocation 数 → 拐点」的实测曲线，拐点数值回填本节。

在 [YEJ-151] 完成回填前，**任何文档与验收口径都不得使用 200,000 allocation 作为设计目标或验收目标**（见 §7.4 与 §11 的 OQ-1）。

### 7.2 每包内存分配

| 路径 | 每包堆分配 | 说明 |
| --- | --- | --- |
| STUN Binding | **0** | 栈缓冲解析 + 组帧到栈缓冲 |
| TURN Allocate/Refresh/Stop | **0** | 同上 |
| Relayed 转发 | **0** | 直接 `sendmsg(buf)` |
| Peer 转发 | **0** | 同核路径零拷贝；跨 worker 路径一次 `flume` 投递（无堆，环形缓冲预分配） |
| Data 转发 | **0** | 只重写源地址字段（就地） |
| ChannelData 解包 | **1** | 打包/解包需要一次拷贝到连续缓冲；可优化为 `BytesMut` 复用池，**Stage 3 实现时以 profile 数据决定是否引入**（记录在 issue 描述） |

### 7.3 内存上限保护

- 每 allocation 的 `permissions` / `channels` 溢出后走堆分配（`SmallVec` 溢出），上限由配置约束：`--max-permissions-per-allocation`（默认 16）、`--max-channels-per-allocation`（默认 8）。超出即拒绝（`443` / `441`）。
- `--max-memory`（默认 4 GB）：进程 RSS 超过该值时拒绝新 allocation 并返回 `508`，防止配置错误（如把 relay-range 配成 /8）导致的 OOM。该值是一个**安全上限**，远大于 §7.1 的 16 MB 常驻预算，不承担容量规划职责。

### 7.4 横向扩容（多实例）

**本节补记原始需求第 6 项「通过新增实例支持视频路数扩容」的技术口径**（[YEJ-167] 新增）：配置侧由 [YEJ-147] 落地（新增参数、启动自检），容量规划侧由 [YEJ-152] 落地（多实例 compose / systemd 示例）。

**口径定义**：横向扩容 = **新增实例 + relay-range 端口段划分 + 认证 key 命名空间隔离**。单实例是**状态持有者**——allocation / permission / channel / nonce 全部在内存态。扩容靠新增实例，**不靠单实例把 allocation 上限调大**。

| 维度 | 口径 |
| --- | --- |
| 扩容单元 | **整实例**（一个进程 + 它的 relay 端口段 + 它的认证命名空间）。不支持「向现有实例追加容量」 |
| 容量叠加 | 线性：`总容量 = 实例数 × 单实例实测容量`。单实例的 500 路 / 2 Gbps / P99 < 1 ms（UDP）**逐实例**成立，不因扩容放宽 |
| relay 端口段 | 每实例显式声明自己的 `--relay-range` 子段，**段间不重叠**；[YEJ-147] 的启动自检新增「端口段冲突检测」，与本实例已知配置重叠即**拒绝启动** |
| 认证 key 命名空间 | 每实例声明 `--auth-namespace`（或 `--instance-id`）；静态密钥、realm、`user:pass` 按命名空间隔离，使不同实例的凭证可区分、可独立轮换 |
| nonce 隔离 | nonce 含实例 salt（tech-stack §3.1），跨实例不可重放；同一客户端可同时在多个实例上持有 allocation，各自独立生命周期 |
| 状态共享 | **无**。实例之间不共享、不同步任何 TURN 状态（见下方「不支持」） |
| 前端选择 | 客户端经配置下发 / ICE candidate 选择实例；本架构**不提供**实例发现、负载均衡协调或健康聚合协议 |

**明确不支持（三条，[YEJ-152] 的容量规划章节须逐条写入）**：

1. **实例间不同步 TURN allocation 状态**——不同步 allocation / permission / channel / 限速桶 / nonce 表。理由：这是另一个量级的功能（跨进程无锁状态复制或共享存储），会直接破坏 §3.3 的「单包路径上无线程同步」不变式与 §2 的单进程假设。本轮不做。
2. **不支持实例级连接迁移**——实例 A 上的 allocation 不能迁移到实例 B。实例故障时该实例持有的 allocation 全部失效，客户端需重新做 ICE / TURN 协商（与 coturn 的实例故障行为一致）。
3. **不支持多实例共享 relay 端口段**——端口段重叠会让同一 `(relay_ip, relay_port)` 在两个实例上指向不同 allocation，破坏 §4.3 的分配唯一性。段划分必须在配置期完成，运行期不合并。

**两个量级的区分（防止口径混淆）**：

| 量级 | 含义 | 数值 |
| --- | --- | --- |
| 单实例余量 | 单实例的**抗突发**余量（§7.1），压测后可上调 | ~5,000 allocation / ~16 MB 状态表（≈ 10× 500 路） |
| 多实例叠加 | 横向扩容后的总容量 | 实例数 × 单实例实测容量 |

举例：100 路 → 1 实例；500 路 → 1 实例；2,500 路 → 5 实例（每实例 500 路，各自保留 10× 抗突发余量）。

**禁止在任何文档或验收口径中使用「单机 20 万并发分配」**：单实例设计余量与多实例横向叠加是两个量级——前者是 10× 抗突发（~5,000），后者由部署规模决定。该数字是 Stage 1 定稿前的暂定值，已被需求方 2026-09-15 15:19 的拍板取代（见 §11 的 OQ-1）。

**与状态表不变式的关系**：横向扩容不引入跨实例的可变数据共享，因此 §3.3 的「单包不跨核 / 单包路径上无线程同步」不变式在扩容后仍成立。扩容的唯一新增面是**每实例的端口段与认证命名空间在配置期互斥**，由启动自检保证。

---

## 8. TLS 支持组合

### 8.1 结论（协议矩阵的 TLS 范围定稿）

| 组合 | 支持 | RFC | 对齐 coturn |
| --- | --- | --- | --- |
| **STUN/TURN over UDP-over-TLS** | **必须**（默认开启） | 7635 | `--use-tls` 的等价路径，WebRTC 必需 |
| **STUN/TURN over TLS over TCP** | **必须**（默认开启） | 8326 | `--use-tls` + TCP |
| **ICE-TCP with TLS** | **必须** | 6062 + 8326 | `--use-tls` + `--no-quic-relaying` |
| RFC 6061（TURN over TLS over UDP） | **仅接收兼容**，不作为主路径 | 6061（已被 9263 obsoleted） | 见 §0.1 勘误 |

### 8.2 TLS 性能预算

- TLS 1.3 握手：~1 RTT，单次握手 ~2 ms（rustls，含 RSA/ECDH），CPU ~0.5 ms/握手。
- **500 路视频场景下 TLS 握手是启动期一次性成本，不在稳态数据面路径上**。
- 稳态下 UDP-over-TLS 每包加密成本 ~5 µs（AES-GCM），相对纯 UDP 增加 ~3 µs/包 —— 2 Gbps 下占 CPU 约 0.5%，可接受。
- **TLS over TCP 的每包成本更高**（TLS 记录层 + TCP 拷贝），设计上通过 `tokio` 的 `read_buf`/`write_all_buf` 复用缓冲降低，但**明确不把 P99 < 1 ms 的分配类时延承诺施加于 TLS over TCP 路径**（该路径的时延预算在运维手册中标注为 P99 < 5 ms）。

### 8.3 证书与安全基线

- 证书：`--cert` / `--pkey` / `--cert-list`（多证书，按 SNI 选择），支持 OCSP stapling 与证书链。
- TLS 版本：**只启用 TLS 1.3**（可配 `--tls-min-version` 降至 1.2，但默认 1.3）。
- cipher：rustls 默认套件（仅支持 TLS 1.3 套件）。
- 证书续期：启动时校验过期时间，`< 30 天` 告警，`< 0 天` **拒绝启动**。
- **不做证书自动签发/续期**（非目标，需求方未要求）。

---

## 9. REST 动态变更端点

需求方已确认：必须支持，但变更**仅本次运行内生效**——重启回落静态配置（文件 + CLI），**不落盘、不写外部数据库、不建持久化审计库**。

v2 修订（[YEJ-167]，2026-09-16）：v1 的「端点清单（只此五个，明确拒绝扩张）」已撤销。可临时变更项扩为 **4 类**，与 [YEJ-153] 的端点集、生效语义、鉴权与错误码逐条对齐。**本节与 [YEJ-153] 是同一份口径的两个视角**：本节定义架构不变式（生效粒度、不变式保护、鉴权判定顺序），[YEJ-153] 定义实现与测试。

### 9.1 端点形态

框架 `axum`，控制面 tokio 运行时（§2.1）。路径前缀分两类：

| 路径 | 用途 | 归属 issue |
| --- | --- | --- |
| `/metrics`、`/healthz`、`/readyz` | 只读可观测性（不属变更类） | [YEJ-149] |
| `/api/v1/...` | 变更类（本节的对象） | [YEJ-153] |

变更类端点：

| 端点 | 方法 | 语义 |
| --- | --- | --- |
| `GET /api/v1/config` | GET | 返回当前**运行态**配置（启动值 + 已应用的临时变更），供运维读取实际生效值 |
| `PATCH /api/v1/config` | PATCH | 覆盖一个或多个配置键（键级粒度） |
| `PUT /api/v1/rate` | PUT | 限速与容量组的便捷聚合入口，语义等价于对这些键的 PATCH |
| `PUT /api/v1/credentials` | PUT | 认证组中「追加临时 `user:pass`」的便捷聚合入口（只增不减，见 §9.4） |
| `DELETE /api/v1/config/{key}` | DELETE | **单键回滚**到启动值（例外见 §9.4） |

### 9.2 可临时变更项（4 类，逐项列全）

| 类 | 配置键 | 生效粒度 | 说明 |
| --- | --- | --- | --- |
| **限速与容量** | `max-bps` | **新分配生效** | 既有 allocation 保持旧限速（§9.4 第 3 条硬性语义） |
| | `max-bw` | **新分配生效** | 同上 |
| | `max-rate` | **新分配生效** | 同上（每 allocation 包速率桶，§6.1） |
| | `min-timeout` | **立即** | 只影响后续 Refresh 的裁剪计算；已生效 lifetime 不回缩 |
| | `max-timeout` | **下一轮超时扫描生效** | 由 time wheel 的 tick 边界应用（§5.2） |
| | `max-alloc-lifetime` | **下一轮超时扫描生效** | 同上；已创建 allocation 的 lifetime 不回缩 |
| | `max-alloc` | **立即** | 调大立即生效；调小时不销毁既有 allocation，只对新建生效 |
| **流开关** | `no-peer` | **立即** | 拒绝新的 peer 方向转发与 `CreatePermission`；已存在关系按已建状态运行到过期 |
| | `no-data` | **立即** | 同上，作用于 Data 方向 |
| | `no-channel` | **立即** | 同上，拒绝新的 `ChannelBind`，已绑定 channel 存活到过期 |
| **认证** | `realm` | **立即**（对**新**认证） | 不重算既有 allocation；既有 allocation 沿用建立时的 realm |
| | `static-secret` | **立即**（对**新**认证） | 新 nonce 用新密钥派生；已签发 nonce 在过期窗口内按旧密钥继续有效 |
| | `use-ephemeral-keys` | **立即**（对**新**认证） | 开关只影响新 nonce 的生成方式 |
| | `users`（追加临时 `user:pass`） | **立即** | **只增不减**；见 §9.4 的 DELETE 例外 |
| **可观测性** | `log-level` | **立即** | 走 `tracing-subscriber` 的动态 filter；热路径仍遵守「每包不打日志」的硬约束（§6.4） |
| | `metrics-enable` | **立即** | 关闭后 `/metrics` 停止导出（503），计数器仍在内存中累计，重新开启后恢复导出 |

**生效粒度的三档定义**：

1. **立即**：写锁提交后对所有新进入该判定分支的请求生效，无等待。
2. **下一轮超时扫描生效**：变更已提交，但在 worker 的下一个 time wheel `advance()` 才作用于待到期项（§5.2）——最多 1 个 poll 周期（≤ 1 ms）的可见延迟。
3. **新分配生效**：仅作用于变更提交后新建的 allocation；既有 allocation 保持旧值直到其生命周期结束。

**流开关的「立即」语义**特指「拒绝新增」，不指「中断既有」——立即销毁已建立的 relayed / peer / channel 关系会造成客户端不可优雅降级的连接断裂，与 WebRTC 语义冲突。这一点必须在 [YEJ-153] 的测试中断言。

### 9.3 不可临时变更项（必须重启）

| 配置键 | 需重启的理由 |
| --- | --- |
| 监听地址与端口 | socket 在启动期绑定，`SO_REUSEPORT` 的 worker 分发建立在绑定之上；运行中重绑需要新建 socket 并重新分配五元组到 worker，等价于重启 |
| `relay-range` / `relay-ip` | 已分配的 relay 地址与新 range 冲突，会**破坏 §4.3 状态表不变式**（relay 地址是 allocation 主键的一部分，改 range 等于使既有主键失效）。这是「不可热加载」论证的核心 |
| 证书路径（`--cert` / `--pkey` / `--cert-list`） | TLS 会话绑定在 acceptor 的证书链上；证书热替换等价于新建 acceptor，与 TLS 路径的连接归属重新分配耦合 |
| 认证**模式**（`--use-auth` / `--no-auth` 的开关本身） | 认证模式是请求校验分支的选择点，运行中切换会让「已认证」的既有 allocation 的凭证语义不再可判定 |
| REST 自身监听配置（监听地址 / 端口 / TLS 封装） | 自指变更：正在处理该请求的监听器被替换，语义无定义 |

上表项在 [YEJ-153] 中必须返回 **409**（键不支持运行时变更），且不得改变运行态。

### 9.4 实现约束、不变式与回滚语义

`ConfigController` 是一个 `Arc<RwLock<RuntimeConfig>>`。以下三条是硬性不变式：

1. **读路径不进包级转发热路径**：包级转发路径（§3.2）不读取 `RuntimeConfig`。限速与流开关的生效点在**分配 / 建权 / 建 channel 时**（读一次 `RwLockReadGuard`，~500 ns），不在每包循环里。不缓存到 `thread_local`——缓存会导致配置漂移不可预测。
2. **写锁持有 < 1 ms**：写路径只在控制面线程执行，写锁内只允许内存赋值与事件发布，禁止 I/O、禁止格式化日志、禁止网络调用。
3. **限速变更的硬性语义**：**已存在的 allocation 保持旧限速，只对新建 allocation 生效**。理由：Allocate 应答中已通过 `D4-LIMIT`（§3.1 步骤 ⑧）向客户端承诺了上限，运行中收紧会破坏已协商的承诺并导致客户端误判带宽。这条语义必须有测试（[YEJ-153] 验收标准 #6）。

**回滚语义**：

- `DELETE /api/v1/config/{key}` = **将该键回滚到启动值**（不是清空运行态）。启动值来自文件 + CLI 的最终合成结果，启动时快照到 `RuntimeConfig::baseline`。
- **例外：凭证类键返回 409**。凭证类键 = `users`（临时 `user:pass`）、`static-secret`、`realm`。对这三项的 DELETE 返回 **409**，响应体说明原因：
  - `users` 的**只增不减**是运维可预期的安全方向，删除会破坏已建立 allocation 的认证状态（已签发 nonce 与既有连接的凭证语义）；
  - `static-secret` / `realm` 回滚到启动值会让**已签发 nonce 全部失效**，等价于强制所有客户端重新认证，破坏面远大于收益。
  - 运维若必须撤销临时凭证，唯一支持的路径是**重启**（回落到静态配置，临时凭证清空）。
- **不落盘**：DELETE 只改内存态，不回写配置文件。`GET /api/v1/config` 在重启后必须返回启动值（[YEJ-153] 验收标准 #2、#3 有测试）。

### 9.5 鉴权（双支持，可各自开关、可同时启用）

两种鉴权方式**都实现**，各自有独立开关，可同时启用：

| 方式 | 请求头 | 密钥来源 | 默认状态 |
| --- | --- | --- | --- |
| **Bearer token** | `Authorization: Bearer <token>` | `--api-token`（静态令牌） | 默认**启用** |
| **HMAC 请求签名** | `X-QuickRelay-Date`（RFC3339 或 Unix 秒）+ `X-QuickRelay-Signature`（`HMAC-SHA256`，复用 [YEJ-146] 的 HMAC 工具） | `--rest-secret` | 默认关闭，显式开启 |

HMAC 签名带**时间戳防重放**与可配置的时钟偏移容忍窗口。头名与算法**独立实现**，仅与 coturn REST API 的请求签名惯例做对照说明，不复用其代码（§0 合规口径）。

**同时启用时的判定顺序**（必须写进 README 与 OpenAPI，[YEJ-153] 有测试）：

1. 请求**携带** `Authorization` 头 → 走 Bearer 校验。Bearer **优先**：校验失败直接拒绝，**不再**降级尝试签名校验（避免双路径下的歧义与重放面扩大）。
2. 请求**不携带** `Authorization` 头 → 若 HMAC 已启用，走签名校验（`X-QuickRelay-Date` 先做时钟窗口校验，再做 `X-QuickRelay-Signature` 校验）。
3. 两者都失败或都不满足 → 按错误码表返回 **401 / 403**。

错误码与输入校验口径：

| HTTP | 含义 |
| --- | --- |
| `401` | 无凭证 |
| `403` | 凭证错误 / 签名不匹配 / 重放（时间戳超窗） |
| `400` | 类型错误 / 值越界 |
| `404` | 未知配置键 |
| `409` | 键不支持运行时变更（§9.3 的项）；凭证类键的 DELETE（§9.4） |

并发变更的原子性：单次 PATCH / PUT 在**一把写锁**内提交（§9.4 第 2 条），键间无部分成功的中间态。

### 9.6 明确拒绝的范围

- **不做**账户体系、计费、多租户（需求方明确禁止）。
- **不做**完整 REST 管理面（对标 coturn REST API 的全部 CRUD）——只覆盖「临时动态变更」这一个场景；只读可观测性端点归 [YEJ-149]。
- **不做**OAuth / JWT：REST 鉴权只限 Bearer token + HMAC 请求签名两种。
- **不做**持久化审计库或变更历史存储：变更记录走结构化日志（`config_changed` 事件，§6.4）供 [YEJ-149] 采集。
- **不做**REST 监听地址的临时变更（§9.3）。
- **REST 传输保护**：REST 端点可选 TLS 封装（`--rest-tls`），**默认关闭**；默认监听地址 `127.0.0.1`，端口默认关闭（显式开启才监听）。该能力不在 v1 架构文档中，v2 按「可选、默认关闭」回填，实现口径见 [YEJ-153]。

### 9.7 与日志 / 指标的对接

- 每次变更产生一条 `config_changed` 结构化日志：`key`、`old_value`、`new_value`（凭证类键的 `new_value` 脱敏为 `<redacted>`）、`source`（`rest`）、`actor`（鉴权方式与令牌标识，不含令牌本身）。
- 指标：`quickrelay_config_changes_total{key, kind}`（kind = `patch` / `put` / `delete`）。
- 变更不产生任何包级热路径的额外成本（§9.4 第 1 条）。

---

## 10. issue 依赖图与模块切分

### 10.1 Stage 2–5 模块边界（对应 crate）

| 阶段 | 交付 crate | 依赖 |
| --- | --- | --- |
| Stage 2 — 核心协议 | `quickrelay-protocol` + `quickrelay-transport`（UDP 部分） | — |
| Stage 3 — 完整 TURN 转发 | `quickrelay-core`（状态机）+ `quickrelay-auth` + `transport`（TCP 部分） | Stage 2 |
| Stage 4 — 传输层加密与运维 | `quickrelay-transport`（TLS）+ `quickrelay-config` + `quickrelay-metrics` | Stage 2, 3 |
| Stage 5 — 测试与发布 | `quickrelay-server`（装配）+ `docs/` + `scripts/` | Stage 2, 3, 4 |

### 10.2 issue 依赖图（与现有 issue 对齐）

```
                    Stage 1
        ┌────────────┼────────────┐
    YEJ-136      YEJ-137      YEJ-138 ← 本文档
    测试资产      性能基线      架构设计
        │            │            │
        └────────────┴────────────┤
                                  ▼
                    ┌──────── Stage 2 ────────┐
                    │                          │
                YEJ-140 ──────────────► YEJ-141 ──► YEJ-142
              消息编解码                UDP 传输层    ICE 候选/ICE-TCP
                    │                          │
                    └──────────┬───────────────┘
                               ▼
                    ┌──────── Stage 3 ────────┐
                    │                          │
                    └──────────┬───────────────┘
                               ▼
                    ┌──────── Stage 4 ────────┐
                    │                          │
                    └──────────┬───────────────┘
                               ▼
                    ┌──────── Stage 5 ────────┐
                    │                          │
                    └──────────┬───────────────┘
                               ▼
                         YEJ-150, YEJ-151, YEJ-152
```

**可并行组**（每个组内独立，组间有依赖）：

| 组 | issue | 依赖前置 |
| --- | --- | --- |
| G0 | YEJ-136, YEJ-137, YEJ-138, YEJ-139 | 无 |
| G1 | YEJ-140 | G0 |
| G2 | YEJ-141 | G1 |
| G3 | YEJ-142, YEJ-143, YEJ-146 | G2（YEJ-143/146 可并行） |
| G4 | YEJ-144, YEJ-145 | G3 |
| G5 | YEJ-147, YEJ-148, YEJ-149 | G4 |
| G6 | YEJ-150, YEJ-151, YEJ-152 | G5 |

### 10.3 建议的派发顺序（供主调度引用）

| 顺序 | issue | 说明 |
| --- | --- | --- |
| 1 | YEJ-140（消息编解码） | `quickrelay-protocol` crate 建立，后续全部 issue 的基础 |
| 2 | YEJ-141（UDP 传输层） | `quickrelay-transport` 建立，验证 `SO_REUSEPORT` + 每核 worker 模型 |
| 3 | YEJ-142（ICE 候选） | 与 143 可并行 |
| 3 | YEJ-143（状态机） | `quickrelay-core` 建立，YEJ-146 的 trait 桩在此定义 |
| 3 | YEJ-146（认证） | 依赖 143 的 trait 桩 |
| 4 | YEJ-144（Relayed/Peer） | 依赖 143 |
| 4 | YEJ-145（Data/Channel） | 依赖 144 |
| 5 | YEJ-147（配置 CLI） | 依赖架构定稿的参数集 |
| 5 | YEJ-148（TLS） | 依赖 141、146 |
| 5 | YEJ-149（可观测性） | 依赖 143、144、147 的埋点 |
| 6 | YEJ-150（测试） | 依赖 136 + 全部实现 |
| 6 | YEJ-151（压测） | 依赖 137 + 全部实现 |
| 6 | YEJ-152（部署文档） | 依赖 147、149 |

---

## 11. 开放项清单与决策台账

本节是 Stage 1 遗留开放项的**当前状态台账**。需求方已在 [YEJ-128] / [YEJ-135] 拍板的项不再列为开放问题；v2（2026-09-16）关闭的三项见下表与 §11.2。

### 11.1 已关闭（v2，2026-09-16）

| # | 项 | 结论 | 决策来源与日期 | 落点 |
| --- | --- | --- | --- | --- |
| OQ-1 | 并发 / 设计余量目标 | **Closed**：单实例 allocation 上限 **~5,000**（≈ 10× 500 路抗突发余量），状态表常驻 **~16 MB**。撤销「按 20 万 allocation 设计（400× 余量 / ~160 MB）」。10× 是压测后可上调项，拐点由 [YEJ-151] 记录 | 需求方 2026-09-15 15:19「按默认走」（拍板项 C）；[YEJ-135] 权威性能口径 | §0、§4.1、§6.1、§7.1、§7.4、§12 |
| OQ-3 | REST 可变更范围 | **Closed**：扩到 **4 类**（限速与容量 / 流开关 / 认证 / 可观测性），逐键列全并标注生效粒度；撤销「只支持两个变更端点」的表述。仍**不做**完整账户 / 计费 / 多租户 | 同上（拍板项 A2）；与 [YEJ-153] 端点集对齐 | §9.1、§9.2、§9.3 |
| OQ-3a | REST 回滚语义 | **Closed**：`DELETE /api/v1/config/{key}` 单键回滚到启动值；**凭证类键（`users` / `static-secret` / `realm`）DELETE 返回 409** 并说明原因；不落盘、无持久化审计库 | 同上（拍板项 B） | §9.4 |
| OQ-3b | REST 鉴权方式 | **Closed**：Bearer token + HMAC 请求签名**双支持**，可各自开关、可同时启用；Bearer 优先的判定顺序写进 README 与 OpenAPI | 需求方 2026-09-15 拍板「都支持」；[YEJ-135] 决策记录 | §9.5 |
| OQ-6a | 横向扩容口径 | **Closed**：多实例 + relay-range 端口段划分 + 认证 key 命名空间隔离；扩容粒度是整实例；三条不支持项写入 | 需求方 2026-09-15 15:19（原始需求第 6 项的技术口径，本轮补记） | §7.4 |

### 11.2 仍开放（架构给出建议默认值，需求方可否决）

| # | 开放项 | 建议默认 | 否决后果 |
| --- | --- | --- | --- |
| OQ-2 | 是否需要 TURN over TLS（RFC 6061 / DTLS over UDP）？ | **是**，但按 **RFC 7635（UDP-over-TLS）+ RFC 8326（TLS over TCP）** 实现，RFC 6061 仅接收兼容。**此项已由需求方 2026-09-15「两者都做」确认，仅保留 §0.1 的 RFC 6061 勘误说明** | 见 §0.1 勘误。若需求方强制 RFC 6061 为主路径，需重新评估 WebRTC 客户端兼容性 |
| OQ-2a | SHA-256 Message Integrity（`MESSAGE-INTEGRITY-256`）是否启用？ | **提供但默认关闭**。理由：RFC 5389/6051 的标准 Message Integrity 只定义 SHA-1；`MESSAGE-INTEGRITY-256` 由 RFC 5769 §3.14 引入但 RFC 6051 未采纳，且 **coturn 不实现**——默认开启会导致与 coturn 及主流客户端不互操作。在 TURN over TLS 的双端受控部署中可通过 `--hmac-sha256` 启用 | 若默认开启，需先在客户端侧确认可用 `MESSAGE-INTEGRITY-256` |
| OQ-4 | Licensing 边界 | **是**，全栈自研，不 vendor 任何 coturn 脚本/代码/测试 | 需求方已确认本轮不做专门处理（2026-09-15 15:19 的 D3 项按最严格解释执行；边界不依赖上游实际许可证的具体名称，避免与台账侧口径分歧耦合） |
| OQ-5 | 是否需要 QUIC 支持？ | **否**，不实现。QUIC 不在需求矩阵内，WebRTC 客户端仍用 TCP/UDP/TLS 协商 TURN | 需求方未要求 |
| OQ-6 | 是否需要 DPDK？ | **否**，不引入 DPDK 依赖。理由：内核 UDP 路径在 2 Gbps 预算下足够，DPDK 会破坏跨平台性与运维友好度。若 Stage 5 压测发现单核 UDP 入站成为瓶颈（> 5 Gbps 且 `udp_rcvbuf_drops` 持续增长），**另开 issue 评估 io_uring 或 eBPF-XDP 后端**（不在本轮） | 需求方未要求，且破坏跨平台 |
| OQ-7 | 是否需要 TURN 数据面的 QUIC relay（RFC 8836）？ | **否**，本轮不做 | 需求方未要求 |
| OQ-8 | 是否需要 TURN 数据面的 DTLS 封装（RFC 8833）？ | **否**，本轮不做 | 需求方未要求 |
| OQ-9 | 是否需要 TURN 的 `--use-auth` 之外的凭证来源（LDAP / 外部服务）？ | **否**，`CredentialProvider` trait 预留接口但不实现具体后端 | 需求方未要求 |
| OQ-10 | 是否需要 TURN 的 NAT64 / NAT1to1 支持？ | **是**，按 coturn 默认实现（`--nat64-prefix`、`--nathash`） | 需求方未明确排除，coturn 默认支持 |
| OQ-11 | 是否需要 TURN 的 `--via` 白名单？ | **是**，按 coturn 默认实现 | 需求方未明确排除 |
| OQ-12 | 是否需要 TURN 的 multicast peer？ | **否**，默认禁用（对齐 coturn 默认），可配置启用但不实现 | 需求方未要求 |
| OQ-13 | REST 端点的 TLS 封装（`--rest-tls`） | **可选、默认关闭**（v2 新增，见 §9.6）；默认监听 `127.0.0.1`、端口默认关闭 | 需求方未明确要求；与 [YEJ-153] 范围 #5 一致 |

---

## 12. 与现有 issue 的对应与回填

### 12.1 本节是各实现 issue 的引用锚点

- **YEJ-136（测试资产清单，已交付）**：本设计的协议矩阵（`protocol-matrix.md`）是「RFC 一致性用例」的对齐基准。测试侧按矩阵逐行产出自动化断言。v2 补记三条口径（拍板项 D1–D3）：
  - **验收面按上游真实可用面**：15 个 `examples/run_tests*.sh` + 14 组 RFC 5769 向量。**上游无 `share/scripts/`、无 `utils/`**，文档与验收标准中不得引用这两个路径（[YEJ-136] §2 已用三种方式交叉验证）。
  - **断言锚点用 QuickRelay 自己的日志 / 输出**，coturn 脚本里的关键字只作**语义参考**，不作断言字符串——直接复用上游关键字会把断言绑定到上游文案，上游改文案就断。
  - **许可边界按最严格解释执行**：不拷贝、不 vendor 任何 coturn 脚本 / 代码 / 测试文件；只读取其行为规格并转写为 QuickRelay 自己的测试。该边界是 QuickRelay 的自约束，**不依赖上游实际许可证的具体名称**，因此不受台账侧对上游许可证的记法分歧影响。
- **YEJ-137（性能基线，已交付）**：本设计的内存预算（§7.1）与时延预算（§6.3）是基线 issue 的输入。**校准说明（v2）**：[YEJ-137] 的 P1 / P11 / P12 / P17 以 200,000 allocation 为目标，那是 Stage 1 定稿前的暂定值，**已被需求方 2026-09-15 15:19 的拍板取代**。这些压测项在 [YEJ-151] 执行时**按 5,000 allocation 重跑**，并在报告中给出「并发 allocation 数 → 拐点」的实测曲线；拐点数值回填 §7.1。**禁止在任何文档或验收口径中使用「单机 20 万并发分配」**（见 §7.4）。验收口径以 [YEJ-135] 为准：500 路视频 / 2 Gbps / Allocate 类 P99 < 1 ms（UDP 路径；TLS over TCP 路径 P99 < 5 ms）。
- **YEJ-138（架构设计，本文件）**：v2 由 [YEJ-167] 修订，回填六项拍板结论。Stage 2 起以 v2 为准，v1 不再有效。
- **YEJ-139（里程碑）**：§10.2 的 issue 依赖图应回填到里程碑台账。
- **YEJ-140 / YEJ-141 / YEJ-143 / YEJ-146**：直接引用本设计对应章节作为开工依据（编解码 → 协议矩阵；UDP 传输层 → §2.3；状态机 → §4.1；认证 → tech-stack §3）。
- **YEJ-147（配置 CLI）**：参数集以本设计 §0 / §4.3 / §5.1 / §6.1 / §9 为准，其中 `--max-alloc` 默认 **5,000**。横向扩容的三个配置参数（`--relay-range` 显式子段、`--auth-namespace` / `--instance-id`、`--max-alloc`）与「端口段冲突检测」的启动自检见 §7.4；新增参数须在 `config.example.toml` 标注 coturn 对应项。
- **YEJ-148（TLS）**：范围按 §8.1 定稿（RFC 7635 必须 / RFC 8326 必须 / RFC 6061 仅接收兼容）；issue 文本里的「RFC 6061」按 §0.1 勘误执行。证书路径不可通过 REST 临时变更（§9.3）。
- **YEJ-149（可观测性）**：`/metrics`、`/healthz`、`/readyz` 归本 issue；`quickrelay_config_changes_total` 指标与 `config_changed` 结构化日志的字段集见 §9.7。`log-level` 与 `metrics-enable` 的临时变更语义见 §9.2 可观测性组。
- **YEJ-150（测试）**：RFC 一致性用例按协议矩阵逐行断言；断言锚点口径见 §12.1 的 [YEJ-136] 条目。
- **YEJ-151（压测与交付）**：验收口径按 §12.1 的 [YEJ-137] 校准说明执行；**必须记录拐点**（§7.1 第 1 项前置条件）——这是单实例上限能否从 5,000 上调的唯一依据。端口池与 relay 地址槽的容量曲线是拐点的第一决定因素。
- **YEJ-152（部署文档 / 运维手册）**：容量规划表按 §7.1（单实例 ~5,000 / ~16 MB）与 §7.4（多实例叠加，三条不支持项）单列「横向扩容」小节，给出 ≥ 2 实例与 ≥ 3 实例两组示例；REST 操作说明（含 Bearer + HMAC 双鉴权、`DELETE` 回滚与凭证类 409、判定顺序）以 §9 为唯一来源逐项对齐 [YEJ-153] 的实现；TLS 两种组合的启用与证书轮换以 §8 为准对齐 [YEJ-148]。
- **YEJ-153（REST 端点）**：端点集、可变更项、生效粒度、回滚语义、鉴权与错误码以 **§9 为架构锚点**逐项对齐（§9 与 [YEJ-153] 是同一口径的两个视角，见 §9 开头说明）。硬性语义三条（读路径不进包级转发热路径 / 写锁 < 1 ms / 既有 allocation 保持旧限速）见 §9.4，须有测试。
