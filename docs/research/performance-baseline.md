# 调研：coturn 性能基线数据与 QuickRelay 性能目标定稿

- Issue：YEJ-137
- 调研日期：2026-09-15
- 角色：系统架构师（前置审核 / 技术把关；本文档只做约束与目标定稿，**不做线程模型与内核实现方案**——那属于 YEJ-138）
- 结论状态：可供 YEJ-151（Stage 5 压测 issue）直接作为验收基线

---

## 0. 一句话结论

**coturn 官方仓库（含 master / wiki / `share/scripts`）没有任何一条「官方发布」的吞吐或并发数字；
仓库里唯一带来源、带硬件、带版本的实测数据全部集中在 `docs/PerformanceIterationLog.md`
（贡献者 2026-05 的 A/B 实验笔记）。** 因此本项目「性能基线」的实际构成是：

1. coturn 公开实测数据（DigitalOcean `c-4`，`turnutils_uclient -Y packet` 工作负载）→ 作为**方法学与数量级参照**；
2. coturn 架构上限（relay 端口区间 → 单机 ~16 000 allocation；kernel `udp_sendmsg` 主导成本；`SO_REUSEPORT` 单流钉死单核）→ 作为 **QuickRelay 的硬约束**；
3. QuickRelay 自己的目标表（本文第 5 节）→ **以「可测量」为唯一判据**，不复用 coturn 数字直接对标。

另外：验收标准第 3 条与 README 已确认需求对齐（20 万并发 = 20 路 1080p30 视频的 10 倍容量下限；分配类 P99 < 1 ms 保留），两处目标全部保留、**不做下调**，但补上了原缺失的测量条件（见 5.3）。

---

## 1. 调研对象与核验方法

| 项 | 值 |
| --- | --- |
| 仓库 | `https://github.com/coturn/coturn`（GPL-2.0） |
| 调研 commit | `1986df21e4b4152b5e0216989f649e20ff76aced`，`master`，2026-09-08 13:15:43 +0200 |
| 版本 | `ChangeLog` 首部 = `Release 4.18.0`；git tag `docker/4.18.0-r0` |
| 核验方式 | 本地 `git clone --depth 1` 全量 grep（`Performance\|throughput\|concurrent\|cups\|dpdk\|io_uring\|recvmmsg\|sendmmsg\|gso\|multiplex-peer`），逐条比对源码与文档 |
| 网络限制 | 本次运行的环境无法访问 `github.com` 的 wiki/raw 页面与 crates.io 网页（仅 crates.io **sparse index** 可达）。凡是本次未能打开的页面，本文只按「仓库中存在的引用路径」记录，不推断其内容 |

### 1.1 需要下游 issue 修正的条目（重要）

| 出处 | 说法 | 核验结果 |
| --- | --- | --- |
| YEJ-137 本 issue 范围第 1 条 | coturn 有 `docs/user/performance-test`，含「测试机规格、`turnperf` 参数、**每代测试报告**」 | **不存在。** 当前 `master` 无 `docs/user/` 目录，`docs/` 下只有 `Performance.md`（4 行，仅指向 wiki）与 `PerformanceIterationLog.md`；**无 `share/` 目录**，故 `share/scripts/turnperf.sh`、`share/scripts/daily-run.sh`、`share/scripts/nat64_*.sh` 全部不存在（这些是历史版本路径，已从当前树移除） |
| YEJ-137 本 issue 范围第 4 条 | 用 `turnutils_stun --test` 压测 | **当前树无 `turnutils_stun` 二进制。** 现在的工具是 `turnutils_stunclient`（`README.turnutils`，`-c` 连续模式打印 min/avg/max RTT 与丢包，`-i` 间隔默认 1000 ms，`-t` 超时默认 3000 ms）。RFC 一致性检查是 `examples/scripts/rfc5769.sh` → `turnutils_rfc5769check`（`docs/Testing.md`）。另：`turnutils_turn` **存在**（`README.turnutils`，`-t/-T` TCP、`-s` Send、`-S` TLS 等） |
| coturn `docs/Performance.md` | 「This topic is covered in the wiki page」→ `coturn/coturn/wiki/TURN-Performance-and-Load-Balance` | 引用路径存在但本次环境无法打开页面内容，**本文档不引用其中任何数字**。Stage 1 需二次核实该 wiki 页是否仍是官方性能页，并把它加入 YEJ-136 的资产清单 |
| coturn `README.md` | 「the project focuses on performance, scalability and simplicity」「the aim is to provide an enterprise-grade TURN solution」 | 纯声明，无数字，不可引用 |

---

## 2. coturn 可引用性能数据（每条：来源 + 硬件 + 版本 + 方法）

以下 5 组数据**全部**来自同一个文件（同一个作者、同一套 DO `c-4` droplet 方法），不是「官方世代报告」。引用时请整组引用，不要摘单点当结论。

### 2.1 来源与硬件

| 项 | 值 |
| --- | --- |
| 文件 | `docs/PerformanceIterationLog.md`（coturn 仓库，commit `1986df21`；文件内含 2026-05-03 / 05-09 三段记录） |
| 服务端/负载机 | 两台 DigitalOcean `c-4`（CPU-optimized，**4 vCPU**）Ubuntu 24.04，同 VPC；`nyc1` 一组（turn `10.116.0.2` / loadgen `10.116.0.3`），`sfo3` 一组（`10.124.0.2` / `.3`），`nyc1` 又一组（`.4` / `.5`） |
| 内核 | Linux 6.8 + virtio-net，`gso_max_segs=65535` |
| 版本 | 实验在分支 `claude/beautiful-black-c3b741` 上相对 `master`（`727ec2ab`「loadgen」→ `321a2d18`）逐 commit A/B；GSO 实验对应 `--udp-gso` 分支。**注意：这些不是已发布 tag 的构建** |
| 负载命令 | `timeout -s INT 30s turnutils_uclient -Y packet -m 1 -l 120 -e <peer> -r 3480 -X -g -u user -W secret <server>`（`-Y packet` = 建立**一条** TURN allocation 后无 pacing 洪泛；`-l 120` = 120 B 载荷；`-X` = 显式指定 IPv4 relay；`-g` = DONT-FRAGMENT） |
| 主指标 | 日志最后一行 `start_mclient:` 的 `tot_recv_msgs` / 30 s（往返 relay 的包数）。**明确禁用 `send_pps`** —— 文档原文：loadgen 发送速率在任何 relay 能力下都饱和在 ~262 K pps，是 loadgen 内核 UDP send buffer 的上限，不能当 relay 吞吐代理 |
| 测量纪律 | 每个 round **交替** A/B（先跑 5×B 再 5×I 会被环境漂移污染）；丢弃 turnserver 重启后的第一轮（慢 30–80 %）；单次 round 方差 ~5–10 %，声称 <10 % 的增益需要 6–8 轮 |
| 系统调优 | `sysctl net.core.rmem_max=134217728 net.core.wmem_max=134217728 net.core.netdev_max_backlog=250000`；`ulimit -n 1048576` |

### 2.2 内核 CPU 占比与热点（perf record -F 99 -g）

| 项 | 数据 |
| --- | --- |
| coturn 用户态总开销 | 占 relay 线程 **5–7 %**；「the relay is kernel-bound」 |
| kernel 占比（子函数聚合） | `udp_sendmsg` **36 %**、`udp_recvmsg` 14 %、`ip_finish_output / ip_output / __dev_queue_xmit` **17 %**、syscall 进出机制（`sysret` / `SYSRETQ` / `SYSCALL_64*`）**~23 %** |
| GSO 后（对比） | `__x64_sys_sendto` 子函数 43.6 % → **0.0 %**，`__x64_sys_sendmsg` 变为 38.1 %；`skb_segment`（egress 分段）2.2 %；`syscall_return_via_sysret` self 7.2 % → 2.4 % |

### 2.3 C 微优化累计收益

| 对比 | 数据 |
| --- | --- |
| clean `master` 二进制 | 146,984 round-trips / 30 s |
| 5 个微优化 commit 累计 | 155,468 round-trips / 30 s |
| 增益 | **+5.8 %**；单 commit 增益在 5–10 % 噪声带内不可见 |

### 2.4 UDP recvmmsg（接收侧批量化）

`-Y packet -m 1 -l 120`，同二进制 A/B 交替 3 轮 × 30 s：

| 配置 | 均值 | 中位数 | 相对基线 |
| --- | --- | --- | --- |
| `--udp-recvmmsg` 关 | 153,133 | 153,608 | — |
| `--udp-recvmmsg` 开 | 148,452 | 149,711 | **−3.1 % / −2.5 %（无收益）** |

批处理占用率（开时）：1,129,427 次 `recvmmsg` 调用返回 17,660,300 包，**平均 batch 15.64**，98.1 % 落在 `hist_9_16` 桶。结论原文：「The remaining bottleneck is after receive: per-packet callbacks, TURN processing, and especially one `sendto` per relayed packet.」

### 2.5 UDP-GSO（发送侧批量化，最大单点增益）

`-Y packet -m 1 -l 120`，30 s 交替 A/B，服务端 `sar -n DEV eth1`：

| 变体 | eth1 RX pps | eth1 TX pps | sys CPU | idle CPU |
| --- | --- | --- | --- | --- |
| baseline_r1 | 322,091 | 127,445 | 22.9 % | 67.5 % |
| `--udp-recvmmsg --udp-sendmmsg --udp-gso` | 266,068 | **257,996** | 15.0 % | 78.7 % |
| baseline_r2 | 309,475 | 125,573 | 20.9 % | 70.7 % |
| gso_r2 | 275,992 | **225,366** | 14.9 % | 74.3 % |

| 结论 | 值 |
| --- | --- |
| 平均转发速率（eth1 TX） | 126,509 → 241,681 pps = **+91 %（1.91×）** |
| 每 % CPU 效率 | sys CPU 21.9 % → 14.9 % ≈ **2.8×** |
| 载荷 | 120 B `-l` + STUN/TURN 头 ≈ 160–170 B 以太帧 ⇒ eth1 TX 吞吐 ≈ **~37–41 Mbps（单核 relay 线程，4 vCPU 机器，sys CPU 仅 15 %）** |

**关键推论**：coturn 在 `m=1`（单条 allocation，`SO_REUSEPORT` 把该 5 元组钉死在 1 个 relay 线程）下**单线程**转发 ≈ 240 k pps。若 relay 线程池线性扩展，8 线程 × 240 k ≈ 1.9 M pps——**这正是 QuickRelay 2 Gbps 目标（见 5.3 换算）的数量级**。但注意 GSO 收益的前提是「同目的、同长度批量」，只有 `--multiplex-peer` 模式才有跨 session 的批量（`docs/multiplex-peer.md`），传统模式每 session 独占 relay socket，下行情形批量退化为单包。

### 2.6 `sendmmsg`（被否证的方案）

`sfo3` `c-4`（turn `10.124.0.2`），4 轮：

| 轮次 | 配置 | Generator avg pps | Server RX avg pps | Server TX avg pps | Server TX peak pps | CPU avg |
| --- | --- | --- | --- | --- | --- | --- |
| iter0 | baseline + `--udp-recvmmsg` | 286,721 | 360,900 | 257,357 | 323,488 | 97.8 % |
| iter1 | `--udp-sendmmsg` 双向 | 312,662 | 428,184 | **197,300** | 260,453 | 99.8 % |
| iter2 | sendmmsg 仅 batch ≥ 4 | 315,393 | 398,121 | **163,626** | 215,068 | 98.9 % |
| iter3 | 仅 listener 侧批处理 | 286,038 | 376,444 | **210,050** | 332,417 | 97.4 % |

结论原文：`sendmmsg()` 减少 syscall 入口次数，但每个 datagram 仍要走一遍 `udp_sendmsg` + IP 输出路径，`mmsghdr` 拷贝/循环开销抵消了 syscall 节省，**平均 TX 反而低于基线**，保持 opt-in。

### 2.7 负载生成器自身的天花板（必须进测试方法学）

| 现象 | 证据 |
| --- | --- |
| `turnutils_uclient` 单进程 send 饱和 | ~262 K pps（loadgen 内核 UDP send buffer 上限）；iter0–3 的 generator max 已到 393 K–425 K |
| 反射端单线程上限 | GSO 下「240 k → 90 k `tot_recv_msgs`/30 s 的差距由单线程 `turnutils_peer` 反射主导，而非 TURN 服务端」 |
| 多进程方案（coturn 自己在用） | 8 个 `turnutils_peer -L 10.116.0.4 -p 3480..3487` + 8 个 `turnutils_uclient -m 1 -n 50000000 -l 120 -c --no-even-port --listener-threads 1 --sender-threads 4 -e 10.116.0.4 -r <port>`，每流指向**不同 peer port**，以便 `--multiplex-peer` 的 per-thread `mp_table` 不冲突 |
| 客户端计数器的正确性坑 | `uclient.c` 原文：早期 bench 中「每个 listener 核心的 per-packet `__atomic_fetch_add` 打到全局计数器，吞吐崩了约 **19×**」，改用 per-listener slab 解决。**任何自研压测器都必须避免共享计数器跨核写** |
| loadgen 线程池 | `--listener-threads N` / `--sender-threads N`，各上限 4；`-m >= 4` 时自动 1 listener + 2 sender；`-m < 4` 时单线程 |
| 单流只压满 1 核 | 「one client → one tuple → one worker thread. The other 3 cores sit idle.」要压满 4 个 relay 线程需 `m≥4` 且**源端口不同**（coturn 的 loadgen 复用端口，所以做不到，只能用多进程绕开） |

### 2.8 并发 allocation 的硬上限（架构性约束，非调优项）

| 项 | 值 |
| --- | --- |
| 默认 relay 端口区间 | `--min-port` 49152 / `--max-port` 65535 ⇒ 16,383 端口 |
| 每 session 占用 | **1 个（或 2 个，RTCP 用 port+1）bound UDP socket**（`handle_turn_allocate_request → create_relay_connection → turnipports_allocate`） |
| 硬上限 | 文档原文：「a single server is hard-capped at **≈16 000** simultaneous relay sessions even when CPU, RAM, and bandwidth are plentiful」；耗尽后 Allocate 返回 `508 Insufficient Capacity` |
| 突破方式 | `--multiplex-peer`：每个 relay 线程一对共享 IPv4/IPv6 socket，按 peer IP:port 精确解复用，4 线程只占 2×4=8 个端口；「Lifts the ~16 k allocation cap」 |
| multiplex-peer 的代价 | ① EVEN-PORT allocate 一律 400/508 拒绝（现代 WebRTC 用 rtcp-mux，不需要）；② 要求保留源 IP（DSR 或 PROXY 协议，SNAT 的 LB 会破坏不变式）；③ 每 allocation 最多 256 个 peer endpoint（`--multiplex-peer-max-peers`）；④ 两客户端声明同一 peer IP:port 时第二个注册被拒；⑤ TCP relay 不受影响（RFC 6062 每 peer 一条 TCP） |
| relay 线程上限 | 「max number of relay threads is 128」（`mainrelay.c` 警告） |
| 并发分配速率工具 | `turnutils_uclient -Y alloc -m <n> -n <ops> -c --no-even-port`：`start_allocation_flood()` 逐次 allocate → refresh → 删除，用唯一 synthetic peer、唯一 client local port，指标 `total_allocations` 与 `Total allocation flood time` |

### 2.9 未纳入 / 不适用的数据源

| 项 | 核验 |
| --- | --- |
| DPDK | 当前 `master` **全树 grep 无 `dpdk` / `DPDK`**（`src/ docs/ README* scripts/`）。coturn 走内核 UDP 路径，无 kernel-bypass 选项 |
| CUPS（RFC 5766 §17.2.3 多机负载均衡） | 无 `--cups`。等价实现是 `--udp-self-balance`（文档标注「recommended for older Linuxes only」）+ `--alternate-server` / `--udp-alternate-server`（ALTERNATE-SERVER 300 重定向，多值时**按值出现次数加权均分**，文档原文给了 4 台各 25 % 的例子）。coturn 因此**没有官方「多机扩展」性能数据** |
| `io_uring` | 全树仅出现在 `docs/PerformanceIterationLog.md`，作为**未做的 backlog**：「Investigate `io_uring` send batching or kernel-bypass style transmit only as a larger architecture experiment.」 |
| Windows | 无 `SO_REUSEPORT` 时 coturn 用 `SIOCGRCVBUF`/多 socket 的兼容 hack（`ns_ioalib_engine_impl.c:1864,1905`），且 relay 线程数在旧系统有上限（`README.turnserver`）。coturn 没有任何 Windows 性能数据 |

---

## 3. 可比性分析：哪些能对标，哪些不能

### 3.1 技术栈差异（必须写在任何对比报告的第一行）

| 维度 | coturn | QuickRelay |
| --- | --- | --- |
| 语言 / 分配 | C，`calloc`/`turn_malloc`，`ns_turn_buf` 手工管理 | Rust，需选定 `Box` / arena / slab 策略 |
| 事件引擎 | libevent2（多 `event_base`，每 relay 线程一个） | 待定（tokio / smol / mio / 自研 epoll）— YEJ-138 |
| 内核路径 | 内核 UDP，Linux 上叠加 `recvmmsg` + `sendmmsg` + **UDP-GSO** | 待定；UDP-GSO / `sendmmsg` / `SO_REUSEPORT` 是必须评估项 |
| kernel bypass | **无**（无 DPDK、无 io_uring） | 若上 DPDK/AF_XDP 则**不可直接对标** |
| 协议库 | 自研 `src/apps` | `stun-rs` / `turn`（见 3.3） |
| TLS | OpenSSL | RustLS（需实测握手与 per-handshake 成本） |

### 3.2 可以直接对标的

1. **协议正确性指标**（STUN/TURN 消息语义、Attribute 集合、错误码）——与技术栈无关。
2. **控制面延迟**（STUN Binding RTT、Allocate RTT，单 client / 低并发）——两者都走内核 UDP 且都由服务端单核处理，数量级可比。
3. **每 allocation 常驻内存**——都是「结构体 + 权限表 + 映射表」，可比。
4. **端口占用与扩容策略**——coturn 的 16 000 上限与 multiplex-peer 取舍可作为设计参照。

### 3.3 不可直接对标的

| coturn 数据 | 为什么不能对标 |
| --- | --- |
| 240 k pps / eth1 TX（GSO 后） | ① `-Y packet` 是**单条 allocation 洪泛**（120 B 载荷），不是 500 路 1080p30 的真实多流分布；② `SO_REUSEPORT` 把该流钉死在 1 个 relay 线程，其余 3 核空转；③ GSO 只在「同目的 + 同长度批量」生效，且**依赖 `--multiplex-peer`**，QuickRelay 若不做多路复用，此项收益直接归零；④ `virtio-net`（半虚拟化网卡），与物理网卡/多网卡/DPDK 结果不同 |
| 257 k pps（iter0，无 GSO） | 同上，另 `CPU avg 97.8 %` 已近饱和，是「极限」不是「稳态目标」 |
| 146,984–155,468 round-trips / 30 s | 单核单机、单 client、单 peer 的往返计数，**不包含 20 万并发场景**，也没有 STUN Binding 并发压测数据 |
| `server RX avg pps 360,900` | 服务端 ingress 计数，**未反映** relay→client 的下行完成（coturn 文档自己指出要用 `eth1` 与 `recv_pps`） |
| 每代测试报告 | **不存在**（见 1.1），任何「coturn vX.Y 官方吞吐 = N」的说法都是伪引用 |
| 多机/集群扩展 | coturn 无官方多机数据（CUPS 未实现，只有 ALTERNATE-SERVER 重定向），无法对标水平扩展 |
| TURN over TLS / DTLS / TCP 吞吐 | coturn `PerformanceIterationLog.md` **没有任何 TLS/DTLS/TCP 实测数据**（全部是 UDP 无认证洪泛）。而 QuickRelay 把 TURN over TLS / TCP 列为**必须**，这块没有外部基线，只能自建 |

### 3.4 Rust 协议库现状（影响「是否可对标 coturn 的自研 codec」）

通过 crates.io sparse index 核实（`cargo metadata`）：

| crate | 版本 | edition | 依赖 |
| --- | --- | --- | --- |
| `stun-rs` | 0.1.11 | 2021 | 纯同步、blocking；含 `ice` / `experiments`（ICE-TCP）/ `mobility` / `turn` / `discovery` features；依赖 `md5`、`hmac-sha1`、`hmac-sha256`、`precis-core`/`precis-profiles`、`crc`、`bounded-integer`。无异步 IO 依赖 |
| `turn` | 0.17.2 | 2021 | `tokio`、`tokio-util`、`futures`、`ring`、`async-trait`、`portable-atomic`、`webrtc-util`、**`stun`**（注意：依赖的是 **`stun`** crate，**不是** `stun-rs`） |

**架构影响**：两条生态线（`stun-rs` 同步 / `turn`+tokio 异步）不能混用；`stun-rs` 的 codec 是可单独取用的无 IO 层，`turn` 是完整 tokio 栈。QuickRelay 若走自定义事件循环（性能优先），`turn` crate 的 tokio 依赖会成为硬约束。**技术选型定稿属于 YEJ-138**，此处只给出「依赖现实」。

---

## 4. 从 coturn 数据推导出的 QuickRelay 硬约束（给 YEJ-138 架构设计）

这些是调研发现，**不是**架构决策，但 YEJ-138 必须显式满足或显式驳回：

1. **必须支持 ≥ 8 个独立 relay worker，且必须用 `SO_REUSEPORT` 类机制分核**，否则单核上限（coturn 实测 ≈ 150–240 k pps/核）无法支撑 2 Gbps。coturn 自己的教训：单 client → 单 5 元组 → 单线程，其余核空转。
2. **必须解决「每 allocation 一个 bound socket」的端口上限**：要么扩大 relay 端口池，要么实现 coturn 式 peer-side multiplexing（代价：EVEN-PORT 拒绝、需保留源 IP、peer 表容量上限）。这是「≥ 200 000 并发」能否成立的**唯一前置条件**。
3. **发送侧必须评估 UDP-GSO（Linux `UDP_SEGMENT`）**：coturn 实测 +91 % 吞吐、2.8× CPU 效率，且 `sendmmsg` 已被否证（**不要**走 sendmmsg 路线，先做 GSO/批量下沉）。
4. **压测客户端本身是瓶颈**：必须支持多进程/多线程 + 多 peer port，且**每 allocation 独立 client 源端口**，否则测到的是客户端而非服务器。计数器必须 per-shard 聚合（coturn 踩了 19× 的坑）。
5. **kernel 占 87 %+ CPU**：任何「优化服务端用户态代码换取 10 % 吞吐」的预期都是错的（coturn 5 个 commit 累计仅 +5.8 %）。性能工作的重心必须在 syscall 次数与内核路径，而不是业务逻辑微优化。
6. **TURN over TLS/TCP 无外部基线**，必须自建基准（见 4.2）。

---

## 4.2 QuickRelay 2 Gbps 目标的换算（验收时必须用同一口径）

| 项 | 值 |
| --- | --- |
| 目标带宽 | 2 Gbps 双向容量（README 已确认：`500 路 × 3 Mbps = 1.5 Gbps` + 控制流/TLS 余量） |
| UDP 有效载荷假设 | 1200 B（1500 MTU − 28 B IP/UDP；STUN/TURN ChannelData 头另算，实测取 `1400 B` 上限） |
| 折算包速率 | 2 Gbps ÷ (1200 B × 8) = **≈ 2.1 × 10⁶ pps** 双向合计（单向 ≈ 1.05 M pps） |
| 折算吞吐 | **≈ 2 × 10⁸ B/s** |
| 与 coturn 单核上限对照 | 1.05 M pps ÷ 240 k pps/核（GSO）≈ **4.4 个满载 relay 线程**；无 GSO（150 k）≈ **7 个**。⇒ 2 Gbps 目标**在 coturn 数量级内可达**，但必须同时满足约束 1（≥8 核）与约束 3（GSO 或等价） |
| 每 allocation 速率 | 3 Mbps ÷ 1200 B × 8 = **2500 pps/allocation**；500 路 = 1.25 M pps 双向，与 2 Gbps 自洽 |

**注意**：coturn 的 `-Y packet -l 120` 用的是 120 B 小包，其 pps 与字节吞吐的换算与上面的 1200 B 假设不同。**任何跨文档的 pps 对比都必须先声明包长。**

---

## 5. QuickRelay 性能目标表（唯一版本，可测量）

### 5.1 主表

所有指标以「同一台机器、同一台压测机、Release 构建、无其他负载」为前提。阶段编号对应本项目看板（Stage 1 架构设计 / Stage 2 STUN / Stage 3 TURN 数据面 / Stage 4 传输与配置 / Stage 5 压测与文档）；**阶段归属是本文档的建议，最终由 YEJ-151 与 YEJ-138 共同定稿**。

| # | 指标 | 目标值 | 测量方法 | 阶段 |
| --- | --- | --- | --- | --- |
| P1 | 稳态并发 allocation（单机，UDP，ephemeral auth） | **≥ 200 000** | `qr-perf alloc-soak -n 200000`：持续持有 200 k allocation 30 分钟，采样 `RSS`/`active allocations`，全程 0 个 508、0 个 OOM；同时 `--live-streaming` 让每条分配以 2500 pps 收发 | Stage 3 |
| P2 | STUN Binding 往返延迟（单 client，1 核） | P50 < **200 µs**，P99 < **2 ms** | `qr-perf stun-lat -rps 100000 -duration 60s`，客户端记录每包单调时钟，输出直方图（HdrHistogram）；同时 `recv_pps` ≥ 发送 pps − 1 % | Stage 2 |
| P3 | STUN Binding 高并发延迟 | P50 < **200 µs**，P99 < **10 ms**，丢包 < 0.1 %，持续 60 s | 100 个独立 client 进程（各独立源端口），聚合 1 M rps 压测；服务端 `recv_pps` 为准，不用 client `send_pps` | Stage 2 |
| P4 | 分配类消息延迟（Allocate / Refresh / Stop，UDP，ephemeral） | P50 < **200 µs**，P99 < **1 000 µs**（**P99 < 1 ms 为验收线**） | `qr-perf alloc-lat -concurrency 8 -rps 20000`，每请求独立测 RTT；8 并发（跨 8 个 relay 线程）条件下也必须满足 | Stage 3 |
| P5 | 分配类消息延迟（TURN over TLS，长期凭证） | P50 < **500 µs**，P99 < **5 ms**（含 1 次额外 TLS RTT；**不**沿用 1 ms 线） | 同上，`-transport tls -auth long-term`；与 P4 分开报告，避免口径混淆 | Stage 4 |
| P6 | 分配创建速率（alloc-flood） | ≥ **1 000 alloc/s**（P99 单条分配耗时 < 10 ms） | `qr-perf alloc-flood -duration 60s -clients 16`，指标 `total_allocations / duration` 与分配耗时直方图 | Stage 3 |
| P7 | 数据面稳态吞吐（UDP，1200 B ChannelData，双向） | ≥ **2 × 10⁸ B/s**（≈ 1.67 M pps），500 路 × 2500 pps，持续 10 分钟，丢包 < 0.1 % | `qr-perf relay-flood -allocations 500 -pps-per-alloc 2500 -size 1200`，用 `sar -n DEV` / `ip -s link` 取服务端网卡计数，不取 client 端 | Stage 3 |
| P8 | 数据面吞吐上限（单 relay 线程，GSO 或等价路径开启） | ≥ **300 k pps**（120 B 小包，单核） | `qr-perf relay-flood -allocations 1 -size 120`，单核绑核，与 coturn 240 k pps/核 对照 | Stage 3 |
| P9 | 数据面吞吐上限（全核） | ≥ **1.5 M pps**（120 B 小包，≥ 8 relay 线程，多 client 源端口分散） | 同 P8，8 进程 client，每进程独立源端口与独立 peer port | Stage 5 |
| P10 | CPU 效率（吞吐 / CPU%） | 相对 P9 的 `sys CPU` 占比 < **70 %**；且开启批量发送路径后 CPU 效率提升 ≥ **2×**（coturn GSO 参考值） | `mpstat -P ALL 1` + `pidstat`，取稳态均值，丢弃前 2 个采样 | Stage 5 |
| P11 | 每 allocation 常驻内存 | ≤ **4 KiB**（含 session/凭证/权限表/映射/计费/时间轮桶） | `alloc-soak` 在 0 → 200 000 分配间每 5 000 步采 `process.memory.current`，用回归斜率 `ΔRSS / Δalloc`；**排除**收发路径临时缓冲（参照：coturn 压测端 `app_ur_session` 携带两个 ~64 KiB `stun_buffers`，`uclient.c:2286` 注释要求「一次性分配、每轮复用」，不进入分配结构体） | Stage 3 |
| P12 | 常驻内存（200 000 allocation 稳态） | ≤ **1.5 GiB**（P11 达成时的推论：200 000 × 4 KiB = 800 MiB + 线程/事件循环/日志缓冲） | 同 P11 的 30 分钟 soak 曲线终点 | Stage 3 |
| P13 | TURN over TLS：稳态并发与吞吐 | ≥ 50 000 并发 allocation；≥ **500 MB/s**（1200 B，双向） | `qr-perf relay-flood -transport tls -allocations 50000`，TLS 握手摊销在稳态窗口外 | Stage 4 |
| P14 | TURN over TLS：握手速率 | ≥ **2 000 握手/s**（服务端单核），P99 握手耗时 < 50 ms | `qr-perf tls-handshake -clients 32`，客户端记录握手完成时刻 | Stage 4 |
| P15 | TURN over TCP：并发与吞吐 | ≥ 20 000 并发；≥ **300 MB/s** | `qr-perf relay-flood -transport tcp` | Stage 4 |
| P16 | TURN over TCP：分配延迟 | P50 < 300 µs，P99 < 3 ms | `alloc-lat -transport tcp` | Stage 4 |
| P17 | 端口占用 | 每 allocation 消耗 UDP 端口 **0**（peer-side multiplexing 或等价）；否则记录端口区间与上限 | `ss -unlp | wc -l` 在 P1 的 200 k 并发下 | Stage 3 |
| P18 | 优雅扩缩 | 负载在 ≥ 8 relay 线程下，吞吐随线程数线性增长到 8 线程（斜率 ≥ 0.85× 单线程/核） | 2 → 4 → 8 线程阶梯压测，画吞吐/线程图 | Stage 5 |
| P19 | 稳定性 | P1 的 30 分钟 soak + P7 的 10 分钟压测：0 崩溃、0 OOM、RSS 波动 < ±5 %、无泄漏（RSS 曲线无单调上升段） | 压测机全程 `pidstat -r`，压后跑 10 分钟 idle 看 RSS 回落 | Stage 5 |
| P20 | 控制面与数据面隔离 | 在 P7 满吞吐下，P4 的 P99 相对空载退化 < **5×** | 同时跑 `alloc-lat` 与 `relay-flood` | Stage 5 |

### 5.2 与验收标准 3 的一致性声明

| 验收标准 3 要求 | 本文档 |
| --- | --- |
| 「单机 ≥ 20 万并发 allocation」 | **P1 原样保留**，并补上前置条件 P17（端口/描述符预算）——这是 coturn 数据揭示的唯一阻塞项 |
| 「分配类消息 P99 < 1 ms」 | **P4 原样保留**（UDP/ephemeral 口径），并新增 P5（TLS 口径单独给 5 ms，因为 TLS 握手本身多一个 RTT，同一门限在技术上不可达）与 P16（TCP 口径 3 ms）。**未下调原目标**，只是明确口径 |

### 5.3 全部目标的可测性自检

每一行都满足：**输入参数显式**（并发/包长/包速率/时长）、**采集点在服务端或压测机（不是待测进程内部日志的自我报告）**、**有采样与丢弃规则**（丢弃预热 2–3 个采样）、**有噪声带宽声明**（单轮方差 ~5–10 %，显著性需 6 轮交替）。

---

## 6. 测试方法论

### 6.1 工具分工

| 工具 | 用途 | 阶段 |
| --- | --- | --- |
| `turnutils_rfc5769check`（`examples/scripts/rfc5769.sh`） | RFC 5769 测试向量，验证 codec 正确性——**先跑通这个再谈性能** | Stage 2（复用 coturn 资产，行为引用而非拷贝，见 YEJ-136 合规边界） |
| `turnutils_stunclient -c -i 10 -t 3000` | 手工冒烟：min/avg/max RTT 与丢包；**不用于压测**（单进程、libevent 单 base） | Stage 2 |
| `turnutils_turn` / `turnutils_uclient`（非 loadgen 模式） | 人工交互式验证 Allocate/Refresh/Stop/权限/ChannelData 语义，以及 TCP/TLS 路径的端到端 smoke | Stage 3/4 |
| `turnutils_uclient -Y alloc` | 分配速率/并发参照（coturn 官方 loadgen 的第三种模式） | Stage 3 |
| **`qr-perf`（自建，必须）** | 承担 P2/P3/P4/P6/P7/P8/P9/P11/P12/P13/P14/P15/P16/P18/P20 全部指标 | Stage 3 起 |

**为什么必须自建 `qr-perf`**：`turnutils_uclient -Y packet` 是「单 allocation 洪泛」，无法产生「500 路 × 2500 pps」的 WebRTC 式多流分布；`-Y alloc` 是**串行** allocate-refresh-delete 循环，无法测稳态并发；`-Y invalid` 只压控制面错误路径。三项都缺。且 loadgen 的 listener/sender 线程池各上限 4，200 k 并发的 socket 数远超单进程可承受（coturn 自己在 8 进程 × `-m 1` 上跑）。

### 6.2 `qr-perf` 的设计要求（约束，非实现）

1. **多进程优先**，进程内多线程作为二级；每个 worker 一个独立 `SO_REUSEPORT`/独立源端口、独立 libevent/epoll base。
2. **计数器 per-shard 聚合**，禁止跨核 `atomic fetch_add` 到单全局变量（coturn 因此损失过 ~19× 吞吐）。
3. **延迟用单调时钟 + HdrHistogram**（P50/P99/P999），不用均值。
4. **吞吐从服务端网卡计数读取**（`sar` / `ip -s link` / eBPF `net`），client 端 `send_pps` 仅作为「是否已打满客户端」的诊断信号。
5. **A/B 交替**，≥ 6 轮，丢弃服务端重启后第一轮；报告均值 + 中位数 + stdev。
6. **反射端必须多进程**（8 × `turnutils_peer` 或等价自建），否则测到的是反射端单线程上限。
7. 需支持 `-transport {udp,tls,tcp}`、`-auth {ephemeral,long-term}`、`-size <bytes>`、`-allocations <n>`、`-pps-per-alloc <r>`、`-duration <s>`、`-histogram <file>`。

### 6.3 消除客户端瓶颈的清单

| 项 | 做法 |
| --- | --- |
| 内核接收缓冲 | `sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728 net.core.netdev_max_backlog=250000`（coturn 实验组同款） |
| fd 上限 | `ulimit -n 1048576`（200 000 allocation × 2 fd 起跳） |
| NIC ring buffer | `ethtool -G <if> rx 4096 tx 4096`；虚拟环境记录 `virtio`/`gso_max_segs` |
| 亲和性 | 服务端与压测端各自 `taskset` 绑核，避免跨 NUMA；单核基准用 `numactl --cpunodebind=0 --membind=0` |
| 源端口分散 | 每个 worker 绑定独立本地端口，避免 `SO_REUSEPORT` 的 5 元组哈希把它们压到同一 relay 线程 |
| 多网卡 / RSS | 多网卡时确认内核 RSS 队列与 relay 线程数匹配（`/proc/interrupts` + `mpstat -P`） |
| 环境漂移 | 同一段 30 分钟内完成，交替 A/B；记录 `lscpu`/`virt-host-platform`/内核版本/负载机 IP |

### 6.4 复现纪律（写进 YEJ-151 验收）

1. 每次运行必须记录：commit SHA、`--release` 构建参数、OS/内核、`lscpu`、NIC 驱动与 ring 配置、sysctl 全量、服务端启动参数、压测命令全文、每轮原始日志路径。
2. 只报告「服务端网卡计数」与「服务端/客户端两侧各自的 RTT 直方图」；禁止只报单一数字。
3. 与 coturn 对比的报告必须按 3.3 声明不可比项，并按 4.2 声明包长口径。

---

## 7. 风险登记

| # | 风险 | 影响 | 缓解 / 决策点 | 归属 |
| --- | --- | --- | --- | --- |
| R1 | **200 000 并发的前置条件是解决端口上限**（coturn 硬上限 ~16 000，靠 multiplex-peer 突破）。若 QuickRelay 沿用「每 allocation 一个 bound socket」，20 万并发在操作系统层面不可能 | P1 直接不可达 | 必须在 YEJ-138 定稿 peer-side multiplexing 或等价设计；否则 P1 需重新协商 | YEJ-138 |
| R2 | **DPDK / kernel-bypass 是否纳入路线** | 一旦引入，全部 coturn 数据失效（无共同内核路径），需另建 DPDK 基线 | 建议本轮**不纳入**（coturn 本身无 DPDK，且需求方给的是 2 Gbps，处于内核 UDP 可达范围）；单开 issue 记录决策 | 架构决策 issue（新） |
| R3 | **内核 UDP 路径上限**：单核 150–240 k pps，8 核理论 1.2–1.9 M pps，与 2 Gbps（1.67 M pps）距离极近，几乎没有余量 | P7 处于边界，可能因 NUMA/中断分布/网卡虚拟层失败 | ① 必须实现 UDP-GSO 或等价批量下沉（coturn 证据：+91 %）；② 目标 P9 设为 1.5 M pps（非 2 M）作为「全核极限」指标，P7（2 Gbps 稳态）作为业务指标，两者分开验收；③ 压测机不得与服务器同机 | YEJ-138 + YEJ-151 |
| R4 | **CUPS 未纳入路线**（coturn 亦未实现，只有 ALTERNATE-SERVER 重定向） | 单机 20 万并发之外无水平扩展路径 | 记录为「不在本轮范围」；QuickRelay 至少提供多进程/多实例 + L4 负载均衡的部署文档（不实现 ALTERNATE-SERVER 协商也可以，但必须文档化部署拓扑） | 新 issue |
| R5 | **`io_uring` / 批量发送** | coturn 实测 `sendmmsg` **无效甚至负收益**，`io_uring` 仅为 backlog | 不做 `sendmmsg` 主路径；评估顺序应为 UDP-GSO > 批量下沉回调 > io_uring（后者只作架构实验，不进主路径） | YEJ-138 |
| R6 | **`SO_REUSEPORT` 多核并发的正确性**：session 必须在连接建立时钉死到单一 relay 线程，否则跨线程转发会有顺序与所有权问题 | 正确性风险（乱序、丢包、重复） | YEJ-138 必须显式给出「线程亲和 + 无跨线程移交」的不变式；P18 是该项的验收指标 | YEJ-138 |
| R7 | **TURN over TLS 与 1 ms 目标冲突**：TLS 握手至少一个额外 RTT | P4 的 1 ms 在 TLS 下不可达 | P5 单独设 5 ms 门限并声明；不做「把 TLS 摊进 1 ms」这种口径作弊 | 本文档已处理 |
| R8 | **无 TLS/DTLS/TCP 性能基线**（coturn 实测数据全为 UDP 无认证洪泛） | P13/P14/P15/P16 无外部参照，只能自建 | 目标值取「保守且可测」，第一轮实测后向上校准；验收只看 QuickRelay 自身指标 | YEJ-151 |
| R9 | **压测器本身成为瓶颈或被误读** | 结论错误 | 强制采用 6.2/6.3/6.4；每份报告必须同时给出「客户端是否已饱和」判定 | YEJ-151 |
| R10 | **验收引用了不存在的 coturn 资产**（`docs/user/performance-test`、`share/scripts/turnperf.sh`、`turnutils_stun --test`） | 下游 issue 会按错误路径开工 | 见 1.1 的修正表；请 YEJ-136 / YEJ-151 在开工前对齐 | YEJ-136、YEJ-151 |
| R11 | **`stun-rs` 与 `turn` 生态不兼容**（`turn` 依赖 `stun` crate，不依赖 `stun-rs`；`turn` 强绑 tokio） | 若选 `turn`，则 tokio 成为硬约束，自定义事件循环不可行 | YEJ-138 技术选型必须显式二选一并给出吞吐依据（建议：Stage 3 先用 `stun-rs` codec + 自研 IO 层做基线，再决定是否引入 tokio） | YEJ-138 |
| R12 | **licensing 边界**（coturn GPL-2.0） | 误引用性能数据不构成代码复用，**可引用**；引用其测试脚本/源码则违规 | 本文档只引用「数据与方法学」，未拷贝任何 coturn 代码或脚本；`qr-perf` 为自研，不复用 `turnutils_uclient` 源码（可复用其**命令行语义**作为互操作测试，不可 vendor） | YEJ-136 |

---

## 8. 交付与后续动作

1. **本文档即 Stage 5（YEJ-151）的验收基线**：P1–P20 全部为可测量指标 + 测量方法 + 阶段。
2. **YEJ-136（coturn 测试资产清单）**：必须修正 1.1 的三处错误引用（`docs/user/performance-test`、`share/scripts/*`、`turnutils_stun --test`），并补充核实 wiki 页面 `coturn/coturn/wiki/TURN-Performance-and-Load-Balance` 的当前状态。
3. **YEJ-138（架构设计）**：必须显式处理第 4 节的 6 条约束与 R1/R2/R3/R5/R6/R11。
4. **YEJ-151（压测）**：必须按 6.2 自建 `qr-perf`，按 6.4 记录复现信息；`turnutils_uclient` 仅作参照不作主压测器。
5. **需新开 issue**：DPDK/kernel-bypass 路线决策（R2）、多机/水平扩展部署与 CUPS 取舍（R4）。
6. **需向需求方确认**：2 Gbps 是否为**单机**目标；是否接受 UDP-GSO 仅 Linux 可用（非 Linux 部署的性能预期需下调）。

---

## 附录 A：本文档引用的所有 coturn 路径与行号

| 内容 | 路径（commit `1986df21`，Release 4.18.0） |
| --- | --- |
| 性能微优化与 A/B 数据 | `docs/PerformanceIterationLog.md`（全文；含 iter0–3 sendmmsg 表、GSO 表、perf 表、方法学） |
| 性能页占位 | `docs/Performance.md`（4 行，指向 wiki） |
| multiplex-peer 设计、16 000 端口上限、sendmmsg 双向批处理原理、`--multiplex-peer-max-peers` 默认 256、观测 flag | `docs/multiplex-peer.md` |
| relay 端口区间默认 49152–65535、`--relay-threads`、`--total-quota`、`--max-bps`、`--udp-recvmmsg` / `--udp-gso` / `--multiplex-peer` 说明、ALTERNATE-SERVER 负载均衡 | `README.turnserver` |
| `turnutils_uclient` 全部选项（`-Y packet|alloc|invalid`、`-l`、`-m`、`-n`、`-z`、`--listener-threads`、`--sender-threads`、`--no-even-port`）与 loadgen 说明 | `README.turnutils` |
| `turnutils_stunclient`（`-c` 连续 RTT/丢包，`-i`，`-t`）与 `turnutils_turn` 选项 | `README.turnutils` |
| `start_allocation_flood()`（alloc-flood 串行实现、2×64 KiB 栈缓冲注释、`total_allocations` 指标） | `src/apps/uclient/uclient.c:2273–2343`（64 KiB 注释在 `:2286`） |
| loadgen 计数器 slab 化（19× 崩溃注释） | `src/apps/uclient/uclient.c:211,246` |
| listener/sender 线程池与上限 4 | `src/apps/uclient/uclient.c:189,205,338–357` |
| `SO_REUSEPORT` 设置与无 `SO_REUSEPORT` 平台的兼容 hack | `src/apps/relay/ns_ioalib_engine_impl.c:1415–1417,1864,1905` |
| UDP-GSO 实现与 sticky-disable | `src/apps/relay/ns_ioalib_engine_impl.c:3936–3999` |
| relay 线程上限 128 | `src/apps/relay/mainrelay.c:2279` |
| RFC 5769 测试向量入口 | `examples/scripts/rfc5769.sh`、`docs/Testing.md` |
| 功能完备性声明（含「ICMP relaying 未实现」、RFC 8489 仅走 MD5/SHA-1 路径） | `STATUS.md` |
| 版本 | `ChangeLog` 首部 `Release 4.18.0`；tag `docker/4.18.0-r0` |

**未找到（已核验为不存在）**：`docs/user/`、`share/`、`dpdk`/`DPDK`、`--cups`、`io_uring`（除 backlog 提及）、任何官方吞吐/并发世代报告、任何 Windows 性能数据、任何 TLS/DTLS/TCP 性能实测数据。
