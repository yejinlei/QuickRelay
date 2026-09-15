# QuickRelay 整体架构设计

状态：定稿。本文档是 Stage 2–5 全部实现 issue 的唯一设计依据。

---

## 0. 设计目标与硬约束

| 项 | 值 | 来源 |
| --- | --- | --- |
| 并发规模 | 单机 **500 路用户视频**（容量下限，非上限） | [YEJ-135] 权威口径 |
| 吞吐容量 | **2 Gbps 双向**（含 STUN/TURN 控制流与 TLS 握手开销） | 同上 |
| 分配类时延 | Allocate / Refresh / Stop **P99 < 1 ms** | 同上 |
| 设计余量 | 状态表与转发路径按 **≥ 200,000 allocation** 设计（远超 500 路） | 需求方「架构按远超 500 路设计」的指示 |
| 协议矩阵 | STUN over UDP、TURN over UDP、TURN over TCP、TURN over TLS、ICE-TCP **全部必须** | 需求方确认 |
| 配置 | 静态配置（文件 + CLI）+ REST 动态变更（**仅本次运行内生效**，重启回落静态配置，不落外部 DB） | 需求方确认 |
| 合规 | 不复用 coturn 代码；测试资产仅「读取行为规格并转写」 | 需求方确认 |

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

**容量与内存预算**：`AllocEntry` 布局后约 **512 字节**（含 8 字节对齐 padding）。200,000 allocation → 状态表本体 **~102 MB**，开放寻址表 32 字节/槽 × 256k 槽 ≈ 8 MB，`free_list` ≈ 2 MB。**每 allocation 约 550 字节常驻**。

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

**否决全局扫描**：200k allocation 每 60 s 全表扫描 = 200k 次比较，摊到每秒 ~3.4k，CPU 可接受但延迟不可控且不可扩展。改为：

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
| 全局 allocation 数 | 硬上限（`--max-allocations`，默认 200,000） | 200k | 拒绝新 Allocate，返回 `487` |
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

### 7.1 常驻内存预算（500 路视频，200k allocation 设计上限）

| 项 | 500 路实际 | 200k 设计上限 | 计算 |
| --- | --- | --- | --- |
| AllocEntry | 256 KB | 102 MB | 500 × 512 B / 200k × 512 B |
| 开放寻址表 | 32 KB | 8 MB | 1.25× 负载因子，32 B/槽 |
| PeerEntry 反查 | 128 KB | 42 MB | 假设 2 条/alloc，104 B/条 |
| TimeWheel | 64 KB | 64 KB | 与总量无关 |
| 栈缓冲（per worker） | 64 KB（8 worker） | 64 KB | 65535 B + 控制 |
| TCP/TLS 句柄 | 32 KB | 6.4 MB | 32 B/连接 |
| **合计** | **~0.7 MB** | **~161 MB** | |

**结论**：200k allocation 的常驻状态 ≈ 160 MB，**8 GB 内存的机器可承载 100 万 allocation 量级**（线性外推）。设计余量充足，500 路视频的实际内存占用 < 1 MB。

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
- `--max-memory`（默认 4 GB）：进程 RSS 超过该值时拒绝新 allocation 并返回 `508`，防止配置错误（如把 relay-range 配成 /8）导致的 OOM。

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

需求方已确认「必须支持，但仅本次运行内生效，重启回落静态配置，不落外部 DB」。

### 9.1 端点清单（只此五个，明确拒绝扩张）

| 端点 | 方法 | 变更对象 | 是否可热加载 |
| --- | --- | --- | --- |
| `GET /metrics` | GET | — | — |
| `GET /healthz` | GET | — | — |
| `GET /readyz` | GET | — | — |
| `PUT /api/v1/rate` | PUT | 每 allocation 限速、全局 allocation 上限 | **可热加载** |
| `PUT /api/v1/credentials` | PUT | 追加 `user:pass` 临时凭证（**只增不减**，重启清空） | **可热加载** |

**明确不可热加载**（必须重启）：监听地址、relay-range、TLS 证书、认证模式、日志级别以外的运行时参数。理由：这些变更会破坏状态表不变式（如已分配的 relay 地址与新 range 冲突）。

### 9.2 实现约束

- `ConfigController` 是一个 `Arc<RwLock<RuntimeConfig>>`，**只读热路径**通过 `RwLockReadGuard` 拿一次（每次 500 ns），不缓存到 `thread_local`（缓存会导致配置漂移不可预测）。
- 写路径只在控制面线程，写锁持有时间 < 1 ms。
- 热加载后**已存在的 allocation 保持旧限速**，只对新建 allocation 生效（避免运行中破坏已协商的 `D4-LIMIT` 承诺）。**这是硬性语义**，写进运维手册。
- 临时凭证只增不减，重启清空；不提供删除端点（需求方未要求，且删除会破坏已建立的 allocation 的认证状态）。

### 9.3 明确拒绝的范围

- **不做**账户体系、计费、多租户（需求方明确禁止）。
- **不做**用户 CRUD 的完整管理面（只支持「追加临时凭证」）。
- **不做**REST API 认证以外的鉴权（端点默认绑定本机回环地址 + 可配 `--api-token` 静态令牌；**不引入 OAuth/JWT**）。

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

## 11. 开放问题与建议默认值

需求方已在 [YEJ-128] 拍板的项（仓库地址、500 路视频容量、TURN over TLS/TCP 必须、REST 动态变更必须、licensing 不做专门处理）**不再列为开放问题**。以下为**本设计新增**的开放项，每项给出建议默认值，需求方可否决：

| # | 开放项 | 建议默认 | 否决后果 |
| --- | --- | --- | --- |
| OQ-1 | 并发目标是否按 20 万 allocation 设计？ | **是**。500 路视频是容量下限，需求方明确指示「按远超 500 路设计」。20 万是 400× 余量，状态表内存 ~160 MB 可承受 | 若改为 5000 路（10 倍余量），状态表内存降到 ~16 MB，架构不变；若改为 200 万，需引入分片合并（跨 worker 锁），**不建议** |
| OQ-2 | 是否需要 TURN over TLS（RFC 6061 / DTLS over UDP）？ | **是**，但按 **RFC 7635（UDP-over-TLS）+ RFC 8326（TLS over TCP）** 实现，RFC 6061 仅接收兼容 | 见 §0.1 勘误。若需求方强制 RFC 6061 为主路径，需重新评估 WebRTC 客户端兼容性（大概率需要回退到 RFC 7635） |
| OQ-2a | SHA-256 Message Integrity（`MESSAGE-INTEGRITY-256`）是否启用？ | **提供但默认关闭**。理由：RFC 5389/6051 的标准 Message Integrity 只定义 SHA-1；`MESSAGE-INTEGRITY-256` 由 RFC 5769 §3.14 引入但 RFC 6051 未采纳，且 **coturn 不实现**——默认开启会导致与 coturn 及主流客户端不互操作。在 TURN over TLS 的双端受控部署中可通过 `--hmac-sha256` 启用 | 若默认开启，需先在客户端侧确认可用 `MESSAGE-INTEGRITY-256` |
| OQ-3 | 是否需要 REST / HTTP 管理面？ | **是**，但只支持两个变更端点（限速 + 临时凭证），**不做**完整账户/计费/多租户 | 需求方已确认此范围 |
| OQ-4 | Licensing 是否接受「不拷贝 coturn GPL 代码、只引用行为」的边界？ | **是**，全栈自研，不 vendor 任何 coturn 脚本/代码/测试 | 需求方已确认本轮不做专门处理 |
| OQ-5 | 是否需要 QUIC 支持？ | **否**，Stage 1 不实现。QUIC 不在需求矩阵内，WebRTC 客户端仍用 TCP/UDP/TLS 协商 TURN | 需求方未要求 |
| OQ-6 | 是否需要 DPDK？ | **否**，不引入 DPDK 依赖。理由：内核 UDP 路径在 2 Gbps 预算下足够，DPDK 会破坏跨平台性与运维友好度。若 Stage 5 压测发现单核 UDP 入站成为瓶颈（> 5 Gbps 且 `udp_rcvbuf_drops` 持续增长），**另开 issue 评估 io_uring 或 eBPF-XDP 后端**（不在本轮） | 需求方未要求，且破坏跨平台 |
| OQ-7 | 是否需要 TURN 数据面的 QUIC relay（RFC 8836）？ | **否**，本轮不做 | 需求方未要求 |
| OQ-8 | 是否需要 TURN 数据面的 DTLS 封装（RFC 8833）？ | **否**，本轮不做 | 需求方未要求 |
| OQ-9 | 是否需要支持 TURN 的 `--use-auth` 之外的凭证来源（LDAP / 外部服务）？ | **否**，`CredentialProvider` trait 预留接口但不实现具体后端 | 需求方未要求 |
| OQ-10 | 是否需要 TURN 的 NAT64 / NAT1to1 支持？ | **是**，按 coturn 默认实现（`--nat64-prefix`、`--nathash`） | 需求方未明确排除，coturn 默认支持 |
| OQ-11 | 是否需要 TURN 的 `--via` 白名单？ | **是**，按 coturn 默认实现 | 需求方未明确排除 |
| OQ-12 | 是否需要 TURN 的 multicast peer？ | **否**，默认禁用（对齐 coturn 默认），可配置启用但不实现 | 需求方未要求 |

---

## 12. 与现有 issue 的对应与回填

- **YEJ-136（测试资产清单）**：本设计的协议矩阵（§协议与消息格式）是「RFC 一致性用例」的对齐基准。测试侧应基于矩阵逐行产出自动化断言，本设计不重复清单。
- **YEJ-137（性能基线）**：本设计的内存预算（§7.1）与时延预算（§6.3）是基线 issue 的输入。若基线 issue 给出与 20 万 allocation 不一致的目标，**以需求方 [YEJ-135] 的 500 路视频为准**，本设计的 OQ-1 需要重新评估。
- **YEJ-139（里程碑）**：§10.2 的 issue 依赖图应回填到里程碑台账。若后续派发调整了依赖，本设计需要同步更新。
- **YEJ-140 / YEJ-141 / YEJ-143 / YEJ-146**：直接引用本设计对应章节作为开工依据（编解码 → 协议矩阵；UDP 传输层 → §2.3；状态机 → §4.1；认证 → 技术选型 §3）。
- **YEJ-148（TLS）**：范围按 §8.1 定稿；issue 文本里的「RFC 6061」应更新为「RFC 7635 + RFC 8326」，由主调度按 §0.1 勘误执行。
- **YEJ-152（部署文档）**：§7.1 的内存预算、§9 的 REST 端点、§10.3 的派发顺序都应回填到运维手册。
