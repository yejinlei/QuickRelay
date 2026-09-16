# 调研：coturn 可复用测试资产清单与合规复用边界

- 调研对象：`https://github.com/coturn/coturn`，tag `4.18.0`（2026-09-08 发布，上游 master 与之同构，`docs/Testing.md` 逐字一致）
- 取证方式：GitHub Contents API + tarball 全量抽取 + `.github/workflows/*.yml` + `tests/CMakeLists.txt` + `Makefile.in` 逐文件核对
- 关联 issue：YEJ-136（本 issue）；下游消费者为同 stage 架构设计 issue 与 YEJ-134（Stage 5 测试落地）
- 结论先行：**问题描述点名的 `share/scripts/daily-run.sh`、`utils/turnutils_stun`、`utils/turnadmin`、`share/scripts/turnperf.sh`、`nat64_*`、`nat1to1_*` 在当前上游仓库不存在**（详见 §2）；本仓库可直接复用的资产是 `examples/run_tests*.sh` 这一套 15 个脚本 + `turnutils_rfc5769check` + 20 个 C 单元测试。另外 **coturn 官方仓库当前不是 GPL-2.0**（详见 §6）。

---

## 1. 资产分层总览

coturn 的测试资产实际分 7 层，本仓库的复用策略必须逐层区分：

| 层 | 路径 | 数量 | 复用策略 |
| --- | --- | --- | --- |
| A | `examples/run_tests*.sh`（CI 驱动的自动化回归套件） | 15 个脚本 | **改造复用**（断言语义转写为 Rust 集成测试） |
| B | `src/apps/rfc5769/rfc5769check.c` + `make check` | 1 个二进制 | **改造复用**（转写为 Rust 集成测试） |
| C | `tests/test_*.c`（Unity 框架，CMake opt-in） | 20 个测试二进制（25 个 .c，含 5 个 stub/support） | **仅参考行为**（转写，不拷贝） |
| D | `examples/scripts/**`（手动三窗口演示脚本） | 49 个 .sh（+1 .pl） | **改造复用**（拓扑与断言方式） |
| E | `examples/loadtest/*` + `examples/cpu-mem.sh` | 4 .sh + 1 .c + 1 .sh | **改造复用**（自建 Rust 压测工具，不复用其生成器） |
| F | `docker/coturn/tests/main.bats` | 1 个 .bats | **参考复用**（能力冒烟思路） |
| G | `fuzzing/**`（OSS-Fuzz，libFuzzer + clang） | 3 个 target | **仅参考**（自建 Rust fuzz harness） |

RFC 向量（RFC 5769 §2.x）不属于 coturn 资产，是 IETF 公开文本，可自由直接使用。

---

## 2. 首要发现：issue 描述点名的资产在上游不存在（需需求方确认）

验收标准 #1 要求 "`share/scripts/daily-run.sh` 覆盖到的脚本必须 100% 列出"。**这条标准在当前上游仓库无法满足**，已用三种方式交叉验证：

| 验证方式 | 命令 / 路径 | 结果 |
| --- | --- | --- |
| GitHub Contents API | `repos/coturn/coturn/git/trees/4.18.0?recursive=1`（450 个条目，`truncated=false`） | 无 `share/` 目录，无 `utils/` 目录 |
| raw 文件逐个取 | `raw.githubusercontent.com/coturn/coturn/4.18.0/share/scripts/daily-run.sh` 等 9 个路径 | 全部 `404` |
| commits API | `repos/coturn/coturn/commits?path=share/scripts/daily-run.sh` | `n=0`（该路径历史上无任何提交） |
| 历史 tag 回溯 | `4.6.3`、`4.5.2`、`4.7.0`、`4.9.0` 的完整 tree | 均无 `share/`、`utils/` |
| 全仓 grep | `daily-run\|check_.*\.sh\|turnperf\|nat64\|nat1to1` | 0 命中 |

逐条对照问题描述点名的资产：

| 问题描述点名 | 当前上游实际状态 |
| --- | --- |
| `share/scripts/daily-run.sh` | 不存在（`share/` 目录不存在） |
| `check_*.sh` / `turnserver_*.sh` | 不存在 |
| `share/scripts/turnperf.sh` | 不存在 |
| `share/scripts/nat64_*.sh`、`nat1to1_*.sh` | 不存在 |
| `utils/turnutils_stun` | 目录不存在；该工具在 4.18.0 已改名为 `turnutils_stunclient`（源码 `src/apps/stunclient/stunclient.c`） |
| `utils/turnutils_turn` | 目录不存在；已合并进 `turnutils`，通过子命令 `turnutils turn` 调用（`README.turnutils`） |
| `utils/turnadmin` | 目录不存在；已合并进 `turnutils`，通过子命令 `turnutils turnadmin` 调用 |
| `utils/stunclient --test` 自检模式 | `grep --test src/apps/stunclient/stunclient.c` → 无命中，无自检模式 |
| `docs/Testing.md` 提到的 `examples/scripts/peer.sh` | **实际存在**（`examples/scripts/peer.sh`），但 `docs/Testing.md` 把它写成了 `./scripts/peer.sh`，而 `run_tests.sh` 已内联改为直接调用 `turnutils_peer`，不再经它 |

> **需要需求方决策（1/3，见 §7）**：以上资产是否存在于某个 fork、旧版或发行版包内？若无，验收标准 #1 应改写为 "`examples/run_tests*.sh` 在 `.github/workflows/linux.yml` 中被调用的脚本必须 100% 列出"——本文件按改写后的口径执行（§3 已 100% 覆盖）。

补充事实：`turnutils_natdiscovery` 与 `turnutils_oauth` 在当前上游仅存在源码与 man page（`src/apps/natdiscovery/natdiscovery.c`、`src/apps/oauth/oauth.c`），**无任何测试脚本或 CI 覆盖**。`src/apps/stunclient/stunclient.c` 也无任何自动化测试覆盖，仅被 `run_tests_rfc5780.sh` 间接使用。

---

## 3. 资产总清单（100% 覆盖 `.github/workflows/linux.yml` 调用面）

`linux.yml` 是权威调用面：`make check` + `examples/run_tests.sh`、`run_tests_ratelimit_401.sh`、`run_tests_conf.sh`、`run_tests_dtls_default.sh`、`run_tests_ipv6_relay.sh`、`run_tests_mobile.sh`、`run_tests_prom.sh`、`run_tests_mobility_quota.sh`、`run_tests_mobility_resume_flood.sh`、`run_tests_stateless_binding.sh`、`run_tests_stateless_nonce.sh`、`run_tests_expiry.sh`、`run_tests_rfc5780.sh`、`run_tests_multiplex_peer.sh`。`macos.yml` 运行其中 8 个（`run_tests.sh`、`run_tests_conf.sh`、`run_tests_dtls_default.sh`、`run_tests_ipv6_relay.sh`、`run_tests_mobility_quota.sh`、`run_tests_mobility_resume_flood.sh`、`run_tests_stateless_binding.sh`、`run_tests_stateless_nonce.sh`），跳过 `run_tests_ratelimit_401.sh`、`run_tests_mobile.sh`、`run_tests_prom.sh`、`run_tests_expiry.sh`、`run_tests_rfc5780.sh`、`run_tests_multiplex_peer.sh`。注意 `run_tests_dscp.sh` **没有被任何 workflow 调用**（依赖 tcpdump+CAP_NET_RAW，只在本地手动跑）。

### A 层：`examples/run_tests*.sh` — 自动化回归套件（核心可复用资产）

| 路径 | 作用 | 前置条件 | 复用策略 | 预期用例数 |
| --- | --- | --- | --- | --- |
| `examples/run_tests.sh` | 4 种传输协议（TURN/UDP、TURN/TCP、TURN/TLS、TURN/DTLS）的端到端 relay 回环，每种再跑一遍 listener+sender 双线程池路径；Linux 下追加 `-Y packet` 模式 pps 指标烟测 | bash；`timeout`/`gtimeout`（缺失时优雅降级为不设界）；OpenSSL 证书已在 `examples/ca/` 预生成；**不需 root** | **改造复用**：协议矩阵与断言锚点直接转写 | 9（8 协议回环 + 1 pps 烟测） |
| `examples/run_tests_conf.sh` | 同上，但服务配置来自 `turnserver.conf` 文件而非 CLI 参数 | 同上 | **改造复用**：验证 QuickRelay 配置文件解析与 CLI 等价性 | 9 |
| `examples/run_tests_ratelimit_401.sh` | `--unauthorized-ratelimit-rps` 的正向/反向对：低阈值下驱动坏凭据客户端必须恰好打出一条限速日志；高阈值下不得出现；再对伪造 MESSAGE-INTEGRITY 的 438 响应做同样的上限/下限成对断言 | bash；`python3`（仅用于伪造 MI 探测）；`timeout` | **改造复用**：正向+反向成对断言的写法值得照抄 | 4 |
| `examples/run_tests_dtls_default.sh` | 断言 DTLS 监听器**默认不启动**（未给 `--dtls` 时即使证书就绪也不起 DTLS，且日志给出开启提示，DTLS 客户端必须失败），给 `--dtls` 后必须端到端通 | bash；`timeout`；预生成证书 | **改造复用** | 5 |
| `examples/run_tests_ipv6_relay.sh` | RFC 8656 §7.2/§3 的 IPv6 分配：XOR-RELAYED-ADDRESS 必须与 relay socket 同族；`--external-ip`（单族）与 `-A keep` 策略不得把 IPv6 分配广告成 IPv4 relay | 主机具备可绑定的 IPv6 loopback `::1`（否则脚本自 SKIP） | **改造复用** | 4 |
| `examples/run_tests_mobile.sh` | `--mobility` + `-M` 的完整 resume 链路：Allocate → 取 MOBILITY-TICKET → 新五元组重开 → REFRESH 携带 ticket 命中 resume 分支（`copy_auth_parameters` + `check_stun_auth`） | bash；`timeout` | **改造复用** | 5（4 回环 + 1 日志锚点） |
| `examples/run_tests_prom.sh` | Prometheus exporter：开关、自定义 address/port/path、`--prometheus-tls`（显式证书 / 继承 server 证书 / 证书路径非法时 exporter 必须不起）、401 与 ratelimit 计数指标非零 | bash；`wget`；`timeout` | **改造复用**（QuickRelay 若保留 Prometheus 指标） | 14 |
| `examples/run_tests_mobility_quota.sh` | RFC 8016 resume 滥用防护：用 `python3` 驱动裸 STUN resume 洪泛，断言配额生效 | **`python3` 必须**（缺失即 SKIP）；`timeout` | **改造复用**（自建裸 STUN 探测，Rust 实现） | 1 |
| `examples/run_tests_mobility_resume_flood.sh` | 同上，resume 洪泛的日志锚点 + 计数断言 | **`python3` 必须** | **改造复用** | 2 |
| `examples/run_tests_stateless_binding.sh` | 监听器侧无状态 Binding 快速路径的 wire 级等价性：未知属性清单、ICE 客户端附加属性、RFC 5780 探测仍须到达 relay；`--no-stun` 静默；`--secure-stun` 挑战；以及 3000 条 Binding 不得推高内存（防 session 泄漏回归） | **`python3` 必须** | **改造复用**（自建裸 STUN 探测） | 4 |
| `examples/run_tests_stateless_nonce.sh` | 派生 nonce 的快速路径：无 session 直接回 401、伪造 MESSAGE-INTEGRITY 由监听器直接回 438 且不建 session、16 字节 legacy nonce 兼容 | **`python3` 必须** | **改造复用** | 5 |
| `examples/run_tests_expiry.sh` | 权限/通道过期扫描：服务端自有 lifetime 优先于客户端请求值；扫描必须真的收割并打日志，且收割不得破坏会话与 relay 转发 | bash；`timeout` | **改造复用** | 2 |
| `examples/run_tests_rfc5780.sh` | RFC 5780 端到端：`OTHER-ADDRESS` 广告 + `CHANGE-REQUEST`/`RESPONSE-PORT` 探测必须有响应 | **需要第二个可绑定 loopback IP**（Linux 上 127/8 全段可用故天然满足；macOS 上无 root 加别名则 SKIP） | **改造复用**（Linux 下零成本） | 1 |
| `examples/run_tests_multiplex_peer.sh` | `--multiplex-peer` 特性：4 种协议 + peer-endpoint 上限 4 放行 / 上限 1 时必须 508 拒绝 | bash；`timeout` | **仅参考**（QuickRelay 是否做 multiplex-peer 取决于架构设计结论） | 6 |
| `examples/run_tests_dscp.sh` | RFC 语义级：relay 必须保留 IP DSCP/TOS，用 `tcpdump` 抓 loopback 断言正向（relay→peer）与反向（listener→client）两跳都保留 `0x22` | **Linux + `tcpdump` + `CAP_NET_RAW`/root**；否则自 SKIP | **改造复用**（可降级为 socket 层 `IP_RECVTOS` 断言，去掉 tcpdump） | 2 |

**A 层断言总量 ≈ 78 个**（含 `make check` 的 12 个 RFC 5769 向量见 §3 B 层）。

### A 层的可复用方法论（比脚本本身更值钱）

读源码时提炼出的、应写进 QuickRelay 测试规范的 6 条：

1. **正向/反向成对断言**：`ratelimit_401.sh`、`stateless_binding.sh`、`stateless_nonce.sh` 全部是「低阈值必须触发 / 高阈值必须不触发」的两半，单跑正半会漏掉误触发回归。
2. **就绪探测替代固定 `sleep`**：统一轮询服务端唯一命名的日志文件里的一行「已就绪」标记（`Total auth threads:`），而非 `sleep 2`。理由：ASan/TSan 或慢机器上 5–10 秒才绑完监听口，固定 sleep 会直接变成 flaky。
3. **端口与日志文件用 `$$` 隔离**：并发跑或上一次没清干净时不会串台。
4. **失败即 dump 三件套**：客户端进度行 + 客户端 error/warning + 服务端相关日志尾，让失败一次就可定位，不需要重跑插桩。
5. **`timeout` 包住客户端而非服务端**：客户端被 kill 后仍可用已打印的 marker 判定成败，而服务端不能被 kill（否则拿不到服务端侧证据）。
6. **无法跑时 SKIP 而不是 FAIL**：`dscp.sh`、`rfc5780.sh` 都是「缺前置 → 明确打印缺什么 → exit 0」，这保证了跨平台 CI 矩阵不炸。

### B 层：RFC 5769 测试向量（最高价值、零合规风险）

| 路径 | 作用 | 前置条件 | 复用策略 | 预期用例数 |
| --- | --- | --- | --- | --- |
| `Makefile.in` 的 `check:` target → `bin/turnutils_rfc5769check`；实现 `src/apps/rfc5769/rfc5769check.c`；包装脚本 `examples/scripts/rfc5769.sh` | 用 RFC 5769 §2.x 的**逐字节 hex 向量**校验 STUN 消息编解码、长/短期凭据的 MESSAGE-INTEGRITY、FINGERPRINT，**含 4 组 NEGATIVE（错误指纹/错误凭据必须拒绝）** | 无（编译即跑，不需网络/服务器） | **直接复用向量 + 改造复用实现**：hex 常量从 RFC 文本直接取（IETF 授权），检查逻辑用 Rust 重写 | 12 |

12 组向量的确切清单（从源码打印语句逐条提取）：

1. `message structure, long-term credentials and integrity`
2. `simple request short-term credentials and integrity`
3. `IPv4 response short-term credentials and integrity`
4. `IPv6 response short-term credentials and integrity`
5. `NEGATIVE long-term credentials`
6. `message fingerprint test(0)`（`stun_is_command_message_full_check_str` 全量校验：头 + XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT）
7. `message fingerprint test(1)`（IPv4 响应向量）
8. `message fingerprint test(2)`（IPv6 响应向量）
9. `NEGATIVE fingerprint test(0)`
10. `NEGATIVE fingerprint test(1)`
11. `NEGATIVE fingerprint test(2)`
12. `message encoding test`（响应回包编码逐字节比对）

> 建议：这 12 组应为 QuickRelay **测试套件的第 0 关**，因为它不依赖任何运行时、不依赖 QuickRelay 自身，能独立证明编解码层正确，是后续所有集成测试的前提。

### C 层：`tests/test_*.c`（Unity 框架，20 个测试二进制）

`tests/CMakeLists.txt` 里以 `coturn_add_test(...)`（14 个）与显式 `add_test(NAME ...)`（6 个）注册的完整清单（全 20 个，无遗漏）：

`test_ioaddr`、`test_stun_msg`、`test_saslprep`、`test_stateless_nonce`、`test_base64`、`test_http_server`、`test_acme`、`test_redis_conninfo`、`test_log_min_level`、`test_ratelimit`、`test_mp_peer_table`、`test_alt_server_list`、`test_turn_server_send`、`test_turn_ports`、`test_sqlite_dbd`、`test_pgsql_dbd`、`test_mysql_dbd`、`test_prometheus`、`test_redis_format`、`test_redis_libevent_cleanup`

| 类别 | 测试 | 对 QuickRelay 的价值 |
| --- | --- | --- |
| 编解码/工具 | `test_ioaddr`、`test_stun_msg`、`test_saslprep`、`test_base64` | **值得转写**：SASLprep 边界（4.18 修掉了 0x1F 控制字符）与 base64 边界 |
| 核心转发 | `test_turn_server_send` | **最有价值**：它用自建的 `ioa_*` 假实现把 `src/server/ns_turn_server.c` 在进程内、无 socket/timer/数据库地跑起来。QuickRelay 若采用类似的 trait 抽象，就能把「Send 指示的分发与丢弃」这类逻辑做纯单元测试 |
| 端口分配 | `test_turn_ports` | **必须转写**：uint32 游标在 ~4G 次 alloc/release 后回绕导致的永久空池 bug（#1649）。QuickRelay 按核分片分配表同样会遇到 |
| 特性回归 | `test_alt_server_list`（60s TIMEOUT，防止死锁表现为 hang）、`test_stateless_nonce`、`test_ratelimit`、`test_mp_peer_table` | **建议转写**：注意「用 TIMEOUT 把死锁转成超时失败」这个写法 |
| 存储/观测 | `test_sqlite_dbd`、`test_pgsql_dbd`、`test_mysql_dbd`、`test_redis_format`、`test_redis_conninfo`、`test_redis_libevent_cleanup`、`test_prometheus`、`test_acme`、`test_http_server` | **多数可跳过**：QuickRelay 明确不做外部数据库存储动态值；`test_prometheus` 可参考 |
| 配置 | `test_log_min_level` | 低价值 |

**关键事实**：`make unit-tests` 依赖 `FetchContent` 拉 `github.com/ThrowTheSwitch/Unity`（v2.6.0）——**跑 coturn 的单元测试需要访问 GitHub**。QuickRelay 若照此模式必须换成 crates.io 上的 Rust 框架（离线可用）。

### D 层：`examples/scripts/**`（49 个手动三窗口演示脚本 + 1 个 Perl）

用途是拓扑演示，**不是 CI 用例**；但拓扑组合覆盖了 `run_tests*.sh` 没有的几种重要能力，值得作为 QuickRelay 集成测试的**拓扑设计参考**：

| 子目录 | 脚本数 | 覆盖的拓扑/能力 | QuickRelay 是否需覆盖 |
| --- | --- | --- | --- |
| `basic/` | 6 | 无认证模式；c2c client-to-client（peer 不经服务端）；DONT-FRAGMENT `-g`；TCP relay 到 TCP relay | 是（无认证模式用于本地测试；c2c 是 WebRTC 直连路径） |
| `longtermsecure/` | 13 | 长期凭据；DTLS/TLS 证书模式（`-i`/`-R`/`-E` 客户端证书校验）；**SCTP over TLS**（`-b`） | 部分是：SCTP 需评估是否在协议矩阵内（WebRTC DATA channels 用到） |
| `longtermsecuredb/` | 6 | SQLite/PostgreSQL/MySQL(含 SSL)/Redis/MongoDB 用户库 | **否**：QuickRelay 明确不做外部数据库 |
| `restapi/` | 7 .sh + 1 .pl | `--use-auth-secret` 的 shared-secret 模式；`shared_secret_maintainer.pl`（Perl）周期轮换 secret | 是：`--use-auth-secret` 是 WebRTC 生产标配，QuickRelay 必须支持；轮换流程需自建（不引用 Perl） |
| `loadbalance/` | 5 | `ALTERNATE-SERVER` 主从负载分担；master/slave 双服务端 | 待定：取决于架构设计是否做多节点 |
| `selfloadbalance/` | 2 | 单服务端自负载分担 | 否 |
| `mobile/` | 5 | RFC 8016 移动性会话的拓扑演示 | 见 A 层 `run_tests_mobile.sh` |
| 顶层 | 3 | `rfc5769.sh`（B 层包装）、`oauth.sh`（`turnutils_oauth`）、`pack.sh` | oauth 是 oAuth 凭据工具，属可选 |

**D 层的证书资产**：`examples/ca/`（含 CA 目录 + `openssl.conf` + 已签发的 server/client 证书与私钥）与 `examples/etc/`（`cacert.pem`、`coturn.service`、`turnserver.conf` 样例）。**QuickRelay 应自己生成一套等价证书**（`openssl` 一条命令即可），不 vendor 现成的。

### E 层：压测与观测

| 路径 | 作用 | 前置条件 | 复用策略 |
| --- | --- | --- | --- |
| `examples/loadtest/allocation_flood.sh` | Allocate 洪泛：`turnutils_uclient` 每个分配周期生成唯一合成 peer 地址，只起 turnserver + uclient，不起 peer | 已构建的 turnserver + uclient | **改造复用**：转写为 Rust 压测工具，直接对齐 QuickRelay 的 500 路/2 Gbps 容量指标 |
| `examples/loadtest/packet_flood.sh` | 数据面报文洪泛 | 同上 | **改造复用** |
| `examples/loadtest/invalid_flood.sh` | 畸形包洪泛 | 同上 | **改造复用**（畸形包构造必须自建） |
| `examples/loadtest/401_response_flood.c` + `.sh` | C 写的 401 响应路径洪泛生成器，独立编译 | `cc`/`pthread` | **仅参考**：不复用 C 生成器，用 Rust 重写 |
| `examples/cpu-mem.sh` | 轮询 `top`/`ps` 采样 CPU/内存 | `top`/`ps`/`pidof` | **参考**：QuickRelay 用 Rust 直接读进程指标，不需要 shell 轮询 |
| `examples/run_all_clients.sh` | 串跑 `longtermsecure` 下 9 个客户端 | 已起服务端 + peer | 参考 |

### F 层：`docker/coturn/tests/main.bats`

16 个 `@test`，全部是**镜像能力冒烟**（跑 `turnserver -o` 然后 grep 日志里有没有某能力字符串：TLS 1.3、DTLS 1.2、TURN/STUN ALPN、oAuth、SQLite、Redis、PostgreSQL、MySQL、MongoDB、Prometheus、`detect-external-ip` 存在且能返回合法 IPv4/IPv6）。对 QuickRelay 的价值是**模式**：QuickRelay 也应该有一套「编译产物能力矩阵冒烟」，验证 TLS/DTLS 版本、oAuth、IPv6、指标端点等按 feature 开关正确注册。

### G 层：`fuzzing/`（OSS-Fuzz）

3 个 libFuzzer target：`FuzzStun`（服务端 STUN 解析）、`FuzzStunClient`（客户端库）、`FuzzOpenSSLInit`；带 `stun.dict` 字典和两个 seed corpus zip。**仅参考**：QuickRelay 自建 Rust fuzz harness（cargo-fuzz），字典思路（STUN 头部、属性类型、长度越界）可借鉴，源码与 seed corpus 不拷贝。

### H 层：CI 矩阵（`9` 个 workflow，可参考的覆盖面）

| workflow | 覆盖面 |
| --- | --- |
| `linux.yml` | amazonlinux:2023 + ubuntu:22.04 + ubuntu:26.04，跑全部 14 个 run_tests 脚本，40 分钟 job 上限（防脚本挂死） |
| `macos.yml` | 10 个 run_tests 脚本（不含 prom/expiry/rfc5780/multiplex_peer） |
| `mingw.yml` | Windows cross-compile（无协议测试） |
| `msvc.yml`、`clang.yml`、`cmake.yml` | 编译器矩阵；clang/cmake 各跑子集 |
| `codeql.yml` | 静态分析 |
| `cifuzz.yml` | OSS-Fuzz |
| `docker.yml` | 镜像构建 + bats 冒烟 |

QuickRelay 的 CI 应对齐 `linux.yml` 的结构（多 OS + 显式 job timeout + 脚本自检 SKIP），不需要对齐编译器矩阵。

---

## 4. 当前无法自动跑的用例及原因

**结论：coturn 的 A 层脚本不需要 root、不需要 tun、不需要多网卡、不需要 NAT 模拟器、不需要远端 turnserver**——已用词边界 grep 全量确认（`-wE "expect"`、`-wE "tun"` 在 `examples/run_tests*.sh` 中均为 0 命中；脚本内的 `expect`/`tun` 字样全是注释里的普通单词）。所有依赖都是**可优雅降级**的：

| 前置 | 影响的脚本 | 是否必需 | 缺失时行为 |
| --- | --- | --- | --- |
| Linux 内核 | `run_tests.sh`、`run_tests_conf.sh` 的 `--udp-recvmmsg`；`run_tests_dscp.sh` 全部 | 否（可选） | 前两者跳过该参数继续跑；`dscp.sh` 整体 SKIP |
| `python3` | `mobility_quota`、`mobility_resume_flood`、`stateless_binding`、`stateless_nonce`、`ratelimit_401`（部分） | **是** | SKIP（不 FAIL） |
| `tcpdump` + `CAP_NET_RAW` | `run_tests_dscp.sh` | 是 | SKIP |
| 第二个可绑定 loopback IP | `run_tests_rfc5780.sh` | 是 | Linux 天然满足（127/8 全段）；macOS 无 root 加别名则 SKIP |
| 可绑定 IPv6 `::1` | `run_tests_ipv6_relay.sh` | 是 | 自 SKIP |
| 外部数据库（SQLite/PgSQL/MySQL/Redis/Mongo） | `examples/scripts/*db*`（D 层） | 是 | 不跑（QuickRelay 本来就不支持） |
| `expect` | 无 | — | **coturn 脚本完全不用 expect**（澄清：常被误认为需要） |
| tun / `/dev/net/tun` / 多网卡 / NAT 模拟器 | 无 | — | **coturn 脚本完全不依赖** |
| 远端 turnserver | 无 | — | 全部 loopback 自洽 |
| GitHub 网络 | `make unit-tests`（Unity FetchContent） | 是 | 无法跑（QuickRelay 应换 crates.io） |
| Docker | `docker/coturn/tests/main.bats` | 是 | 无法跑 |
| clang + libFuzzer | `fuzzing/` | 是 | 无法跑 |
| **macOS** | `run_tests_prom.sh`、`run_tests_expiry.sh`、`run_tests_rfc5780.sh`、`run_tests_multiplex_peer.sh` | — | workflow 未调用，脚本自身也 SKIP |
| **Windows** | 全部 A 层脚本 | — | 脚本是 bash，QuickRelay 的 CI 不应放 Windows 上跑协议测试；`mingw.yml` 只验编译 |

**换句话说：QuickRelay 的协议回归套件在任意一台 Linux（有 Python3）上就能 100% 跑起来，无需任何内核级特权。** 这直接降低了 Stage 5 的落地成本。

---

## 5. QuickRelay 需要自建的缺口用例清单

以下每条都是 RFC 明确要求、但 coturn A/B 层**没有 wire 级断言**的行为。引用格式统一用 RFC 章节号（不用 coturn 代码位置），以规避合规风险并便于追溯。

### 5.1 RFC 一致性缺口（必须补）

| # | 缺口 | RFC 依据 | 为什么重要 |
| --- | --- | --- | --- |
| G1 | 401/438 分流矩阵：无 MI 挑战 → 401；挑战后第二次凭据错误 → 438；bad nonce → 438；凭据过期后 Refresh → 401 重新挑战而非 441 | RFC 8656 §11.4.1、§13.1.2(438)、§13.1.12(441) | coturn 只断言 401 限速日志，不断言错误码本身选对 |
| G2 | MESSAGE-INTEGRITY 之后的属性必须忽略；FINGERPRINT 必须是最后一个属性 | RFC 8489 §14.7、§6.3.1 | coturn 4.18 刚修过两个相关 bug，无回归断言 |
| G3 | REALM ≤127 字节、NONCE ≤255 字节（按字节计），超长必须拒绝而非崩溃 | RFC 8489 §14.9、§14.10 | coturn 4.18 刚修过字节数口径 |
| G4 | ERROR-CODE 的 reason phrase 编码与 `HHH-RRR` 数字格式解析容错 | RFC 8489 §14.8 | 现有断言只看错误码数字 |
| G5 | ChannelBind 错误矩阵：channel 0/1 无效；无分配时 ChannelBind → 437；同 channel 换 peer → 403；两个 XOR-PEER-ADDRESS 必须绑**第一个** | RFC 8656 §11.4.3 | coturn 4.18 刚修「绑第一个而非最后一个」 |
| G6 | Send 重复 DATA 属性必须忽略第二个（不是丢弃整包）；payload >1500 字节必须拒转；Send 到未许可 peer 必须静默丢弃（非错误） | RFC 8656 §11.2、§11.4.4 | coturn 4.18 刚修重复 DATA |
| G7 | ChannelData 帧结构 wire 级断言：2 字节 channel + 2 字节 big-endian length 编解码、length=0 必须合法、channel 必须偶数 | RFC 8656 §12.4、§18.1 | 现有测试只发合法包，从不构造边界包 |
| G8 | 服务端自有 permission/channel lifetime 优先于客户端请求值；超限 clamp；CreatePermission 到未分配地址 → 437 | RFC 8656 §10.2、§13.1.1 | 现测试只断言「过期扫描真的收割了」 |
| G9 | STOP 语义：立即释放分配；后续 Send 丢弃；对端 ICMP Port Unreachable 处理 | RFC 8656 §11.4.1、§11.4.5 | 完全没测 |
| G10 | Allocation lifetime=0 的释放语义：刷新成功释放后，同一 transaction 的后续 Refresh 必须 437 | RFC 8656 §8.1、§8.2 | 现测试只测 permission/channel 过期 |
| G11 | **EVEN-PORT 正路**：`--even-port` 开启时 relay 端口必须为偶数（WebRTC ICE 必需）；coturn 全部测试用 `--no-even-port` | RFC 8656 §18.7、§7.1 | **WebRTC 场景关键缺口** |
| G12 | 资源耗尽错误码：分配数到上限 → 508；relay 端口池耗尽 → 508（而非静默失败/崩溃） | RFC 8656 §13.1.4(508) | 现 508 断言绑在 multiplex-peer 特性上 |
| G13 | REQUESTED-ADDRESS-FAMILY 不支持 → 440 | RFC 8656 §7.2、§13.1.12(440) | 现只测 IPv6 happy path |
| G14 | DONT-FRAGMENT 无法保证 → 443/502；coturn 4.18 已弃用 `--drop-invalid-packets` | RFC 8656 §11.4.6、§18.9 | 语义变更未跟进测试 |
| G15 | **TURN over TCP/TLS 分帧**：2 字节长度前缀的 0x7FFE 截断、粘包、0 长度、TLS record 边界；**TLS 首字节非 0x16 时必须当作明文处理**；RFC 6061（TLS over UDP）已被 RFC 8656 废弃为 MUST NOT，收到 0x16 开头的 UDP 包必须忽略 | RFC 8489 §6.2.2、§6.2.3、§6.3；RFC 6061 | **WebRTC 场景最敏感，coturn 完全没有分帧边界测试** |
| G16 | XOR- 属性前缀计算正确性（UDP 用 MAPPED-ADDRESS 的 IP+port，TCP 用 0）独立解码断言 | RFC 5769 §2.4、RFC 8656 §18.5 | 现有断言是隐式的（通过客户端成功） |
| G17 | peer 不可达时的 ICMP 反射与 404；ICMP 属性（可选特性） | RFC 8656 §11.5、§11.6、§18.13 | 完全没测 |
| G18 | ALTERNATE-SERVER / ALTERNATE-DOMAIN 广告与负载分担语义 | RFC 8489 §14.15、§14.16 | 只有手动脚本，无断言 |
| G19 | PASSWORD-ALGORITHMS 协商与 bid-down 防护 | RFC 8489 §9.2.4、§14.11、§14.12、§16.1.3 | 完全没测 |
| G20 | RFC 5780 的 OTHER-ADDRESS 之外：NAT 行为发现的 `CHANGE-REQUEST`/`RESPONSE-PORT` 响应体内容 | RFC 5780 §2.1、§2.2 | 现只断言「收到了响应」 |
| G21 | ICE-TCP non-controllable candidate 约束：TURN/TCP 分配出的 relayed candidate 必须被客户端标为 non-controllable | RFC 8445 §11.1.2.1 | 约束在客户端侧，但需断言服务端响应不违反 |
| G22 | 非特权端口（<1024）分配的接受/拒绝行为 | RFC 8656 §3.6 | 完全没测 |
| G23 | 重复 transaction id / 事务唯一性处理 | RFC 5769 §5.2 | 完全没测 |
| G24 | oAuth 凭据（OAuth 4.1）与 `PASSWORD-ALGORITHM` 的绑定 | RFC 8804 | 只有工具脚本，无断言 |

### 5.2 性能与容量缺口（README 已确认指标，coturn 完全不覆盖）

| # | 缺口 | 指标来源 |
| --- | --- | --- |
| P1 | 500 路视频 / 2 Gbps 双向吞吐容量（下限，非目标上限） | README 已确认需求 |
| P2 | Allocate/Refresh/Stop 的 P99 < 1 ms | README 已确认需求 |
| P3 | 500 路并发的内存占用曲线与 session 表上限 | 架构要求 |
| P4 | 无锁内核 + 零拷贝转发 + 按核分片分配表的**实测验证**（架构声称的能力必须有对应压测） | 架构要求 |
| P5 | relay 端口分配器长期运行的游标回绕（对标 C 层 `test_turn_ports`，QuickRelay 必须自建） | 架构风险 |
| P6 | 24 小时长跑内存泄漏 | 架构要求 |
| P7 | TLS 握手对 UDP 监听器事件循环的阻塞影响（TLS 必须与 UDP 分流） | 协议矩阵（TURN over TLS 必需） |
| P8 | TURN over TCP 长连接的半开连接检测与 keepalive | 协议矩阵（TURN over TCP 必需） |
| P9 | 无认证 Binding 快速路径的 DoS 抗性（对标 `stateless_binding` 的内存断言） | 安全 |
| P10 | 多 CPU 核扩展性（同一台机器不同核数的吞吐对比） | 超高性能目标 |

### 5.3 配置与运维缺口

| # | 缺口 |
| --- | --- |
| C1 | 静态配置文件的解析与 CLI 等价性（对标 `run_tests_conf.sh`） |
| C2 | **REST 动态变更**：临时生效、并发安全、重启回落静态配置（QuickRelay 特有，coturn 无等价测试） |
| C3 | 能力矩阵冒烟（对标 bats：TLS/DTLS 版本、oAuth、IPv6、指标端点按 feature 开关正确注册） |
| C4 | 日志级别切换生效（对标 `test_log_min_level`） |
| C5 | `--use-auth-secret` 凭据轮换流程（对标 `shared_secret_maintainer.pl`，QuickRelay 用 Rust 自建） |

---

## 6. Licensing 结论

### 6.1 关键更正：上游 coturn 当前不是 GPL-2.0

| 事实 | 证据 |
| --- | --- |
| GitHub 元数据 | `api.github.com/repos/coturn/coturn` → `license: {"key":"other","name":"Other","spdx_id":"NOASSERTION"}`（未识别许可证，仓库根无 SPDX 标识） |
| 仓库根 `LICENSE` | 3-clause BSD 风格全文：*"Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 1. 保留版权声明与条件… 2. 二进制再分发须保留声明… 3. 不得以项目或贡献者名义背书。"*（Copyright (C) 2011-2013 Citrix Systems） |
| 全仓源码头扫描 | `grep -rIl "GNU GENERAL PUBLIC LICENSE"` → **0 命中**；`grep -rIl "Lesser General Public License"` → **0 命中**；BSD-3 风格头 → **100 个文件** |

**GPL 说法的来源**：这是发行版打包口径，不是上游口径。Debian/Ubuntu 的 `turn-server` 包在 `debian/copyright` 中以 GPLv2+ 分发，且历史上 Debian 与上游就许可证有争议；部分企业 fork 也以 GPL 分发。因此在中文语境里 "coturn 是 GPL" 是常见但**与上游现状不符**的表述。

### 6.2 对 QuickRelay 的处理结论（保守口径）

无论上游真实许可证是 BSD-3 还是 GPL，QuickRelay 的技术结论都不变（本来就不拷代码），所以建议**按最严格解释（GPL-2.0-or-later）处理**，成本为零、风险为零。在此口径下：

**✅ 允许（不产生任何许可证义务）**

- 阅读源码以理解行为预期、边界处理、错误码选择 —— 这是事实观察，思想与事实不受版权保护
- 直接引用 RFC 5769 §2.x 的 hex 测试向量（IETF 授权，与 coturn 无关）
- 在自己的 Rust 代码中实现等价行为（独立开发，参照 RFC + 观察到的行为）
- 在文档中记录 "coturn 4.18.0 修复了 X" 作为回归依据（事实陈述）
- 引用短日志关键字作为断言锚点（如 `401 rate-limit exceeded from`、`mobility handoff completed`、`lifetime updated`、`Total auth threads:`）—— 事实性短字符串，通常不受版权保护（**建议向需求方确认，见 §7 决策 2**）

**❌ 禁止（即使 BSD-3 也要求保留版权声明；GPL 口径下更严格）**

- 拷贝 `examples/run_tests*.sh`、`examples/scripts/**` 的任何脚本源码（**连注释都不拷**，注释里是行为规格，转写为自己的描述）
- 拷贝 `src/**`、`tests/**` 的任何 C 代码
- vendor `examples/ca/**`、`examples/etc/turn_server_cert.pem` 等预生成 PEM 数据文件（建议自己用 openssl 生成）
- 引用 `README.turnserver`、man page 的大段文字
- 把 coturn 的 docker image 作为构建或测试依赖分发（会引入其条款）
- 把 `fuzzing/` 的 seed corpus zip 或 `stun.dict` 引入本仓库

**🔶 建议保留（可追溯性，低风险）**

- 在本文件顶部保留调研对象版本（`4.18.0`）与仓库 URL —— 这是出处引用，不是拷贝
- 缺口用例清单统一用 `RFC 编号 §章节` 引用，**不用 coturn 代码行号或函数名**（函数名本身是事实，但少用可以减少后续争议面）

### 6.3 需要向需求方确认的许可证事项（见 §7）

README 已写定 "QuickRelay 不复用 coturn 代码；复用测试资产仅限读取行为规格并转写，不 vendor 其脚本与代码" —— **本调研的结论与该表述完全一致，无需修改 README**。但有两点需要澄清：

1. coturn 许可证口径：按 GPL-2.0 严格解释（推荐，零成本）还是按上游实际的 BSD-3？
2. 引用日志关键字字符串作为回归锚点是否可接受？

---

## 7. 需要需求方决策的事项（3 项，架构设计 issue 可直接引用）

| # | 决策项 | 建议 | 影响面 |
| --- | --- | --- | --- |
| **D1** | 验收标准 #1 里的 `share/scripts/daily-run.sh` 在上游不存在（§2 已五重验证）。是否改写为 "`examples/run_tests*.sh` 在 `linux.yml` 中被调用的脚本必须 100% 列出"？ | 是（本文件已按改写口径完成 100% 覆盖） | 验收标准措辞 |
| **D2** | 日志关键字作为断言锚点：是否允许在测试代码里 hardcode coturn 风格的短日志字符串？注意这些字符串是**为 coturn 写的**，QuickRelay 应改用**自己的**日志锚点，coturn 的仅作为语义参考 | 采用 QuickRelay 自有锚点 | 测试实现 |
| **D3** | coturn 许可证口径（§6.3） | 按 GPL-2.0 严格解释 | 措辞，不影响技术 |

---

## 8. 给架构设计 issue 的三条直接可用结论

1. **测试分层应该照抄 coturn 的 3 层结构**：(a) 无依赖的编解码单测（RFC 5769 向量，12 组，第 0 关）；(b) 进程内核心逻辑单测（需要把转发逻辑抽成可注入的 trait，对标 coturn 的 `ioa_*` 抽象）；(c) 端到端协议回归（对标 A 层 15 个脚本）。缺 (a) 会让 (c) 的失败无法定位。

2. **架构上必须预留两个测试性设计点**：一是转发/IO 抽象要能让核心逻辑在无 socket、无 timer、无网络的环境下跑单测（coturn 用 `ioa_*` 接口做到，`test_turn_server_send` 就是靠它）；二是端口分配器要能独立于网络栈被单测（coturn 的 #1649 回绕 bug 就是靠独立 `test_turn_ports` 抓住的）。**这两点如果不在架构设计阶段定下来，Stage 5 的测试覆盖率会显著打折。**

3. **WebRTC 场景有三个 coturn 完全不覆盖的高风险区，必须由 QuickRelay 自建用例**：`G11`（EVEN-PORT 正路）、`G15`（TURN over TCP/TLS 分帧与 TLS/明文首字节区分）、`G7`（ChannelData 帧边界）。coturn 的测试全用 `--no-even-port`，且从不构造畸形分帧包 —— 这恰好是浏览器 ICE 栈最敏感的地方。

---

## 附录 A：调研取证记录

| 项 | 值 |
| --- | --- |
| 上游仓库 | `https://github.com/coturn/coturn`（`default_branch: master`，`pushed_at: 2026-09-14`） |
| 主调研 tag | `4.18.0`（2026-09-08，最新 release） |
| 交叉验证 tag | `4.17.2`、`4.6.3`、`4.5.2`、`4.7.0`、`master` |
| 4.18.0 全量条目数 | 450（`truncated: false`），文件 384 |
| A 层脚本数 | 15（`examples/run_tests*.sh`） |
| `examples/scripts/**` 脚本数 | 70 .sh + 4 .py |
| C 层单元测试数 | 20（25 个 .c，含 5 个 stub/support） |
| `make check` target | `bin/turnutils_rfc5769check`（12 组 RFC 5769 向量） |
| CI 协议测试总调用面 | `linux.yml` 14 项 + `macos.yml` 10 项 |
| 本机是否可跑 coturn 测试 | 否（Windows，无 `share/` 依赖但也无 bash CI 环境）；本调研基于源码静态分析，未执行任何 coturn 脚本 |
| QuickRelay 当前可跑性 | 仓库仅 README + .gitignore，无测试框架；Stage 5 需从零建立 |
