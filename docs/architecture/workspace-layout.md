# 仓库结构契约（Workspace / Crate 拓扑）

- 生效日期：2026-09-17
- 裁决单：YEJ-177
- 适用对象：YEJ-140（消息编解码）、YEJ-141（UDP/TCP 传输层 + Binding 链路）、YEJ-142（Binding 语义 + ICE 校验）
- 取代内容：本文档取代 `docs/architecture/architecture.md` section 1.1 的 crate 清单（原 section 1.1 只列 7 个 crate，未覆盖 ICE 语义与 TLS 归属）；架构模型部分（线程模型、shard、time wheel、REST、TLS 组合）仍以 `architecture.md` / `tech-stack.md` / `protocol-matrix.md` 为准，**只有 crate 命名与边界以本文为准**。

---

## 0. 结论速览（先看这一节就能动手）

| 项 | 裁决 |
| --- | --- |
| `quickrelay-protocol` 谁说了算 | **YEJ-140 的版本**。11 个源文件、5888 行、117 个 RFC 向量单测，码点经 IANA 2024-12-20 注册表逐条核对，且已修正 `protocol-matrix.md` 中的错误码点。YEJ-141 的同名 crate **整体删除** |
| `CHANGE-REQUEST` 用哪个码点 | **`0x0003`**（RFC 5780 section 2.1 与 RFC 8489 section 13.17 一致，coturn 与 stun-rs 均按此收发）。IANA 注册表把该值标为 "Reserved; was CHANGE-REQUEST prior to RFC 5389"，属注册表同步遗留，不是码点变更。**140 的 `AttrCode` 缺少该变体，须按 section 4.11 第 1 条补齐** |
| `0x8003` 是什么 | `ALTERNATE-DOMAIN`（RFC 8489 section 15.9），**不是** CHANGE-REQUEST。140 的 `AttrCode::AlternateDomain = 0x8003` 正确，保留 |
| TURN over TCP framing | **16 位大端长度前缀**，由 **YEJ-141** 实现，`quickrelay-transport` 内 |
| ICE-TCP（RFC 6544）framing | 与上一行**是同一套 framing**（RFC 6544 section 1 规定 ICE over TCP 建在 RFC 4571 shim 之上，而 4571 shim 只承载 STUN）。142 **不得**另建一套 shim；142 只做语义判定 |
| 收敛方式 | **本单已把骨架提交进 `main`**（commit SHA 见 section 7.1）。三条单一律 rebase 到该 commit 之上，只做删/加，不再各自声明 workspace |
| `lib.rs` 冻结 | 骨架中每个 crate 的 `src/lib.rs` 已写好**精确占位内容**，三条单**逐字保留**，只允许在其后追加自己的 `pub mod` 与 `pub use` |

---

## 1. 最终 crate 清单

```
quickrelay/
├── Cargo.toml                  # workspace 根（含 [profile.release] lto="fat"）
├── .gitignore
├── crates/
│   ├── quickrelay-protocol/    # ← 唯一编解码 crate（冻结）
│   ├── quickrelay-binding/     # ← Binding 语义判定 + ICE 校验（纯逻辑，无 I/O）
│   ├── quickrelay-transport/   # ← UDP/TCP 收发、SO_REUSEPORT worker、framing、TLS 记录层
│   └── quickrelay-server/      # ← 装配层：组合 protocol + binding + transport，最终二进制
├── docs/
└── config.example.toml
```

**`transport` 不依赖 `binding`，`binding` 不依赖 `transport`。** `server` 是唯一做双向装配的 crate（它同时实现两个 crate 暴露的 trait）。这是本契约最核心的一条，也是 141/142 不重复写代码的前提。

### 1.1 九个关注点各自落在哪里（对应本单问题 1）

| 关注点 | crate | 阶段 |
| --- | --- | --- |
| 协议编解码（头/属性/地址/错误码） | `quickrelay-protocol` | Stage 2（140） |
| `integrity` / `fingerprint` 计算与校验 | `quickrelay-protocol` | Stage 2（140） |
| 消息时序规则（FINGERPRINT/INTEGRITY 末位、长度对齐） | `quickrelay-protocol` | Stage 2（140） |
| Binding **语义判定**（role conflict、487、XOR-MAPPED 是否回、ICE 校验） | `quickrelay-binding` | Stage 2（142） |
| Binding **请求-响应链路**（事务匹配、socket 收发、多地址监听） | `quickrelay-server` | Stage 2（141） |
| UDP/TCP framing（2 字节大端长度前缀）、半开连接 | `quickrelay-transport` | Stage 2（141） |
| Allocate 状态机 / AllocShard / PeerShard / time wheel | **`quickrelay-core`**（Stage 3 新建，`YEJ-143`） | Stage 3 |
| 转发（Relayed / Peer / Data-Channel 字节流） | `quickrelay-core`（决策 + 字节流）+ `quickrelay-transport`（收发与出站零拷贝） | Stage 3（144/145） |
| 认证（nonce、long-term/ephemeral/static key、CredentialProvider） | **`quickrelay-auth`**（Stage 3 新建，`YEJ-146`）；key 派生原语已在 `protocol` 内 | Stage 3 |
| 指标 + 健康检查 + REST 动态变更端点 | **`quickrelay-metrics`**（Stage 4 新建，`YEJ-149`/`147`） | Stage 4 |
| CLI / 配置（clap + toml） | `quickrelay-server`（启动期装配） | Stage 4 |
| TLS 记录层（RFC 7635 UDP-over-TLS、RFC 8326 TLS over TCP） | `quickrelay-transport` | Stage 4（148） |

即：本轮骨架**只落 4 个 crate**。`quickrelay-core` / `quickrelay-auth` / `quickrelay-metrics` 是已锁定的**保留名字**，Stage 3/4 的新 issue 创建时不得改名、不得合并进现有 crate。

---

## 2. 每个 crate 的职责边界

### 2.1 `quickrelay-protocol`（冻结，F0）

**职责**
- STUN/TURN 消息头与属性 TLV 编解码；XOR 地址；`ERROR-CODE` 结构；码点表。
- `integrity`（HMAC-SHA1 / HMAC-SHA256）与 `fingerprint`（CRC-32）的**计算与校验**。
- RFC 8489 消息时序规则（INTEGRITY 在 FINGERPRINT 之前且为倒数第二、FINGERPRINT 必须是最后属性、message-length 的填充规则）。
- key 派生原语：`integrity::short_term_key` / `long_term_key` / `static_key`。

**非职责（禁止放入）**
- 任何 socket / I/O / 线程 / 锁 / `tokio` / `mio` / `log` / `tracing`。
- 任何会话或 allocation 状态。
- 任何**策略判定**（「是否应该拒绝」「应该回什么码」都不属于本 crate）。本 crate 只能判「这段字节是否合法」。
- CLI、配置、指标、TLS。

**允许依赖**：`bytes`、`crc32fast`、`hmac`、`md5`、`sha1`、`sha2`、`subtle`（+ 可选 `rand`）。**不得新增其他依赖**，需先在本单回帖申请。

### 2.2 `quickrelay-binding`（冻结，F1）

**职责**
- 给定一份**已解析**的 Binding 请求事实，决定应答策略：`BindingResponsePlan`。
- ICE 属性校验（`ICE-CONTROLLED`/`ICE-CONTROLLING`/`ICE-PRIORITY`，RFC 8445 section 7.2.1.1 的 role conflict → **487**）。
- `CHANGE-REQUEST`（`0x0003`，A/B 两位）语义 → `ChangeResponseAction`（换 IP / 换端口 / 两个都换 / 不变 / 需要错误应答）。
- `ALTERNATE-SERVER` 与 `SOFTWARE` 的应答内容选择。
- 错误码决策表：role conflict、bad request、unsupported address family 等。**所有错误码必须是 IANA 已分配值**（`430`/`390`/`370` 均 Unassigned，禁止使用）。

**非职责（禁止放入）**
- 不解析字节、不发射字节：**不依赖 `quickrelay-protocol`**（这是硬性约束，见 section 3.2）。
- 不碰 socket、不做 framing、不持有 listener。
- 不实现 ICE agent / nomination。
- 不做 TURN Allocate 语义（属于 `quickrelay-core`）。

**允许依赖**：无第三方依赖（纯逻辑）。

### 2.3 `quickrelay-transport`（冻结，F1）

**职责**
- 每核 worker 的收发循环骨架、`SO_REUSEPORT` 监听与绑定、per-worker rcvbuf、绑核。
- UDP 固定大小 buffer 收发、零拷贝发送。
- **长度前缀 framing**（16 位大端，RFC 4571 / RFC 6062 共用）：解码半包/粘包、发送时写前缀。这是 ICE-TCP 与 TURN over TCP 的**唯一** framing 实现。
- TCP listener、半开连接检测与超时回收。
- 出站零拷贝 relay socket 池（含源端口 0 的多 socket 池策略，按 `architecture.md` section 4.3）。
- TLS 记录层（Stage 4，RFC 8326 / 7635）。

**非职责（禁止放入）**
- 不做协议判定：**不得依赖 `quickrelay-binding`**。收到一个 STUN 消息后，`transport` 只知道「这是个 datagram」，语义交给 `server` 通过 `BindingHandler` 拿。
- 不实现 Binding 应答内容（回什么属性、什么码）。
- 不实现 allocation 状态（`quickrelay-core`）。
- 不做认证（`quickrelay-auth`）。
- 不做 CLI / 指标 / REST。

**允许依赖**：`socket2`、`mio`、`bytes`、`log`（+ Stage 4 的 `rustls`；`io-uring` 仅在 `transport-uring` feature 下）。

### 2.4 `quickrelay-server`（未冻结，F2）

**职责**
- 装配：构造 `protocol` 编解码器、`binding` 语义器、`transport` 的 `BindingHandler` 实现与 worker 池，启动与信号处理。
- **Binding 请求-响应链路**：transaction id 匹配、从请求事实提取语义输入、调用 `binding`、把决策翻译成 wire 字节并发出、`SO_REUSEADDR` 多地址监听下的响应源选择。
- 优雅退出（在途请求 drain）。
- Stage 4：CLI（clap）+ 配置文件（toml）解析与启动期校验。

**非职责**
- 不重复实现编解码（用 `protocol`）。
- 不重复实现语义判定（用 `binding`）。
- 不重复实现收发循环（用 `transport`）。
- 不写 `[[bin]]` 之外的 `src/bin/*` 多入口；只有一个二进制 `quickrelay`。

**允许依赖**：以上三个 crate + `clap` / `toml` / `serde` / `tracing` / `tracing-subscriber`。

### 2.5 Stage 3/4 保留名字（本轮不创建）

| crate | 唯一职责 | 新建单 |
| --- | --- | --- |
| `quickrelay-core` | `AllocShard` / `PeerShard` / `RelayPool` / 状态机 / time wheel / 限速桶 / 转发字节流决策。无 I/O | YEJ-143、144、145 |
| `quickrelay-auth` | nonce 生成与校验、凭证存取、`CredentialProvider` trait、鉴权决策。依赖 `protocol`（key 派生） | YEJ-146 |
| `quickrelay-metrics` | 指标注册表、`/metrics`/`/healthz`/`/readyz`、REST 动态变更端点。依赖 `config`（若拆出） | YEJ-147、149 |

若后续决定把配置拆成 `quickrelay-config`，允许新增；否则配置留在 `quickrelay-server`。**不允许**把配置逻辑散落到 `transport` 或 `core`。

---

## 3. 依赖方向（有向无环，禁止反向）

```
quickrelay-server ─┬──► quickrelay-protocol ◄──┐
                   ├──► quickrelay-binding     │ （只读 key 派生原语）
                   └──► quickrelay-transport ◄─┘
                              │
                              └──► quickrelay-protocol
```

- **唯一的边**：`transport → protocol`，`server → protocol`，`server → binding`，`server → transport`。
- **禁止的边**：`binding → transport`、`transport → binding`、`binding → server`、`protocol → *（除自身依赖）`。
- **`server` 是唯一允许同时引用 `binding` 与 `transport` 的 crate**，也是唯一允许装配 trait 实现的 crate。
- 无环性由 Cargo 在编译期强制；上表禁止边由评审按 section 7 检查（可用 `cargo tree -e normal` 复核）。

### 3.1 为什么 `binding` 与 `transport` 必须互不依赖

两条单（141/142）会并行开发、各自提交 PR。如果 `binding` 依赖 `transport` 或反之，两条单会产生必然的双向冲突（同一个 crate 两边都改），且 Stage 3 的 `core` 也要同时依赖两者，形成三角。互不依赖后：

- 141 只写 `transport` + `server`；142 只写 `binding`。两单**只可能在 `server` 上碰一次**，而 `server` 的 Binding 装配代码由 141 独占（见 section 7.3）。
- `binding` 是纯逻辑，可以在不启动任何 socket 的环境下 100% 单测（这也是 142 的验收要求）。

### 3.2 141 与 142 的边界线（对应本单问题 2）

**一句话**：141 写「包从哪进来、往哪出去、怎么匹配事务」；142 写「这个请求该不该回、回什么」。

| 层 | 归 141（`transport` / `server`） | 归 142（`binding`） |
| --- | --- | --- |
| UDP 接收、`SO_REUSEPORT` 分发、绑核、rcvbuf | ✅ | ❌ |
| TCP listener、16 位长度前缀 framing（解码/编码/半包/粘包） | ✅ | ❌ |
| 半开连接检测与回收、超时 | ✅ | ❌ |
| transaction id 生成与匹配（RFC 5389 section 6.2） | ✅ | ❌ |
| 请求→应答的 socket 路由（从哪个 socket 发出、源 IP/端口选择） | ✅ | ❌ |
| `CHANGE-REQUEST` 的 A/B 位判定与「该不该换地址」 | ❌ | ✅ |
| role conflict → 487 的判定 | ❌ | ✅ |
| ICE 属性校验（`ICE-CONTROLLED`/`CONTROLLING`/`ICE-PRIORITY` 的存在性与格式） | ❌ | ✅ |
| 是否回 `XOR-MAPPED-ADDRESS`（含 `?` 与 nonce 语义决策） | ❌ | ✅ |
| `ALTERNATE-SERVER` / `SOFTWARE` 应答内容与条件 | ❌ | ✅ |
| 错误码选择（400/388/437/438/486/487/500） | ❌ | ✅ |
| 把决策翻译成 wire 字节并发送 | ✅ | ❌ |

**API 层怎么切（可编译校验）**：`binding` 的输入/输出类型**必须是自带定义的值类型**，不允许出现 `quickrelay-protocol` 的任何类型。`server` 负责两侧的映射，映射代码只存在于 `server`：

```rust
// crates/quickrelay-binding/src/lib.rs —— 142 必须提供这些（签名冻结）
pub mod change_request;
pub mod error_codes;
pub mod ice;
pub mod response;

pub use change_request::{ChangeRequest, ChangeResponseAction};
pub use error_codes::{ErrorCode, ReasonPhrase};
pub use ice::{IceAttributes, IceTiebreaker, Role};
pub use response::{BindingResponsePlan, ResponseSink, ServerIdentity};

/// 服务端身份：多地址监听下「我从哪台设备上、用哪个地址说话」。
/// 142 只做判定，不触网；ServerIdentity 由 server 填充。
pub struct ServerIdentity { /* ... */ }

/// 141/142 边界的核心类型：输入是「已解析事实」，输出是「应答计划」。
pub struct BindingResponsePlan { /* 应回的 message type、要填的属性、是否换地址、错误码 */ }
```

`server` 侧（141 写）：

```rust
// crates/quickrelay-server/src/binding_chain.rs —— 141 独占
impl binding::ResponseSink for ServerBindingSink { /* 把 plan 渲成 wire 字节并 sendmsg */ }

// 映射方向 1（141 写，唯一一处）：protocol::Attribute -> binding 的输入值类型
fn extract_change_request(msg: &protocol::Message) -> Option<binding::ChangeRequest>;
fn extract_ice(msg: &protocol::Message) -> binding::IceAttributes;

// 映射方向 2（141 写，唯一一处）：binding::BindingResponsePlan -> protocol::Attribute 序列
fn render_plan(plan: &binding::BindingResponsePlan, txid: protocol::TransactionId) -> /* 字节 */;
```

**判定规则（防止重复实现）**：

1. `transport` 内**不得**出现任何 CHANGE 相关码点字面量；`0x0003` 的位语义判定只允许在 `binding::change_request`。
2. **framing 只允许存在于 `transport`**：`binding` 中不得出现 `u16::from_be` 长度前缀读写。
3. **错误码字面量只允许在 `binding::error_codes` 中出现**（`protocol::error_code` 的便捷构造函数保留，但不得在 `transport`/`server` 中散落裸数字）。
4. 142 **不得**创建 ICE-TCP shim（RFC 6544 的 shim = RFC 4571 shim = 与 TURN over TCP 同一套 16 位前缀，已在 `transport` 里）。142 的 ICE-TCP 交付物是「loopback 集成测试 + 语义校验」，不是新 framing。

---

## 4. `quickrelay-protocol` API 契约（冻结，F0）

来源：`agent/claude-01/yej-140` 工作树当前内容（11 个源文件，5888 行）。**140 合入 main 后，本节即为其 `src/lib.rs` 的 `pub use` 面**。

### 4.1 常量

| 常量 | 值 | 说明 |
| --- | --- | --- |
| `MAGIC_COOKIE` | `0x21_12_A4_42` | RFC 8489 section 5.1 |
| `HEADER_LEN` | `20` | 头固定长度 |
| `TRANSACTION_ID_LEN` | `12` | 96 bit |
| `MESSAGE_INTEGRITY_LEN` | `20` | HMAC-SHA1 |
| `MESSAGE_INTEGRITY_SHA256_LEN` | `32` | HMAC-SHA256 |
| `MAX_MESSAGE_LENGTH` | `65_535` | 16 位 message-length 上限 |
| `MAX_DATAGRAM` | `65_537` | 含头 |

### 4.2 消息类型（`message_type`）

- `Class`：`Request` / `Indication` / `SuccessResponse` / `ErrorResponse`；`from_bits` / `bits` / `code` / `is_request` / `is_indication` / `is_response`。
- `Method`：`Binding` / `Allocate` / `Refresh` / `Send` / `Data` / `CreatePermission` / `ChannelBind` / `Connect` / `ConnectionBind` / `ConnectionAttempt` / `Unknown(u16)` / `Reserved`；`bits` / `from_bits` / `is_registered` / `is_unknown` / `is_reserved`。
- `MessageType`：`new(method, class)` / `method()` / `class()` / `bits()` / `from_bits()` / `is_request` / `is_response` / `is_indication` / `success_response_type` / `error_response_type` / `can_reply_420` / `unknown_attribute_reply_type`；及命名常量 `BINDING_REQUEST` / `BINDING_SUCCESS` / `BINDING_ERROR` / `ALLOCATE_REQUEST` / … / `SEND_INDICATION`。

### 4.3 属性（`attribute`）

- `AttributeKind`：`Known(AttrCode)` / `Unknown(u16)`；`as_u16` / `code` / `from_code` / `is_known`。
- `AttrCode`：IANA 码点枚举（`MappedAddress` `0x0001`、`ChangeRequest` `0x0003`（RFC 5780 §2.1，须按 section 4.11 第 1 条补齐）、`Username` `0x0006`、`MessageIntegrity` `0x0008`、`ErrorCode` `0x0009`、`UnknownAttributes` `0x000A`、`ChannelNumber` `0x000C`、`Lifetime` `0x000D`、`XorPeerAddress` `0x0012`、`Data` `0x0013`、`Realm` `0x0014`、`Nonce` `0x0015`、`XorRelayedAddress` `0x0016`、`RequestedAddressFamily` `0x0017`、`EvenPort` `0x0018`、`RequestedTransport` `0x0019`、`DontFragment` `0x001A`、`AccessToken` `0x001B`、`MessageIntegritySha256` `0x001C`、`PasswordAlgorithm` `0x001D`、`UserHash` `0x001E`、`XorMappedAddress` `0x0020`、`ReservationToken` `0x0022`、`IcePriority` `0x0024`、`UseCandidate` `0x0025`、`Padding` `0x0026`、`ResponsePort` `0x0027`、`ConnectionId` `0x002A`、`AdditionalAddressFamily` `0x8000`、`AddressErrorCode` `0x8001`、`PasswordAlgorithms` `0x8002`、`AlternateDomain` `0x8003`、`Icmp` `0x8004`、`Software` `0x8022`、`AlternateServer` `0x8023`、`Fingerprint` `0x8028`、`IceControlled` `0x8029`、`IceControlling` `0x802A`、`OtherAddress` `0x802C`、`ThirdPartyAuthorization` `0x802E`、`ExtendedCandidate` `0x8038`、`ExtendedCandidateUfrag` `0x8039`、`Unknown(u16)`）。
- `Attribute`：解码后的值枚举（`MappedAddress(MappedAddress)`、`XorMappedAddress`、`Username(String)`、`ErrorCode(ErrorCode)`、`IceControlled([u8;8])`、`IceControlling([u8;8])`、`IcePriority(u32)`、`ChannelNumber(u16)`、`Data(Vec<u8>)`、`ConnectionId(Vec<u8>)`、`Unknown { kind: u16, value: Vec<u8> }` …）。
- 读：`parse_attribute_value(kind, buf, txid) -> Result<Attribute, Error>`。
- 写：`write_attribute_value(out, attr, txid)`、`emit_attribute(out, kind, value)`、`emit_attribute_value(out, attr, txid)`、`Attribute::to_value(txid)`、`Attribute::as_bytes_vec()`、`Attribute::needs_txid()`。
- 分类：`attribute_kind(attr)`、`is_comprehension_optional(kind)`、`is_registered(kind)`、`is_trailer_only(kind)`、`pad_len(value_len)`、`attr_size(value_len)`。
- `ErrorCode { code: u16, reason: Vec<u8> }`：`read_value` / `write_value` / `from_number` / `as_u16`；便捷构造函数在 `error_code` 子模块（`too_many_bindings`、`stale_nonce`、`bad_request`、`unknown_attribute`、`unauthorized`、`unsupported_address_family`、`role_conflict`、`allocation_mismatch`、`server_error`、`out_of_resources`、`forbidden`、`forwards_forbidden`、`connection_id_conflicts`、`stale_credentials`、`unsupported_transport`、`turn_unsupported_address_family`、`legacy_unknown_attribute`、`server_error`）。
- 长度常量：`USERHASH_LEN` = 32、`DATA_MAX_LEN` = 511、`ERROR_CODE_REASON_MAX_LEN` = 1024、`CONNECTION_ID_MAX_LEN` = 16。

### 4.4 地址（`address`）

- `AddressFamily`：`Ipv4` / `Ipv6`；`from_octet` / `to_octet` / `address_octets` / `value_len`。
- `MappedAddress`：`from_ipv4(a,b,c,d,port)` / `from_ipv6([u8;16], port)` / `ipv4()` / `ipv6()` / `read_value` / `write_value` / `Display`。
- 非 XOR 读取（`RELAYED-ADDRESS` / `ALTERNATE-SERVER`）：`read_relayed_address`、`read_alternate_server`。
- XOR 编解码：`write_relayed_address`、`write_alternate_server`、`read_xor_address(buf, txid)`、`write_xor_address(addr, txid, out)`。
- XOR key：`xor_key_v4()`（magic cookie 4 字节）、`xor_key_v6(txid)`（cookie 4 字节 + txid 8 字节）；`XOR_PORT_KEY = 0x2112`。
- 常量：`MAPPED_ADDRESS_IPV4_LEN` = 8、`MAPPED_ADDRESS_IPV6_LEN` = 20。

### 4.5 消息与头（`message`）

- 入口：`parse(&[u8]) -> Result<Message, Error>`、`parse_vec(Vec<u8>)`、`parse_bytes(Bytes)`。
- `Header { msg_type, message_length, txid }`：`Header::parse(datagram)`、`total_len()`、`msg_type()`、`message_length()`、`transaction_id()`。
- `Message`：`header()`、`msg_type()`、`transaction_id()`、`attributes()`、`get(i)`、`find(code)`、`has(code)`、`len()`、`is_empty()`、`datagram_bytes()`、`datagram_len()`、`integrity()`、`has_message_integrity()`、`has_integrity()`、`has_fingerprint()`、`fingerprint_offset()`、`fingerprint()`、`username()`、`realm()`、`nonce()`、`software()`、`xor_mapped_address()`、`xor_relayed_address()`、`error()`、`lifetime_secs()`、`data_bytes()`、`channel_number()`、`ice_priority()`、`unknown_optional()`、`unknown_optional_codes()`。
- 头内偏移常量：`LENGTH_OFFSET` = 2、`MAGIC_COOKIE_OFFSET` = 4、`TRANSACTION_ID_OFFSET` = 8。
- trailer 码点常量：`FINGERPRINT_CODE`、`MESSAGE_INTEGRITY_CODE`、`MESSAGE_INTEGRITY_SHA256_CODE`、`UNKNOWN_ATTRIBUTES_CODE`。
- `UnknownAttribute`：无法解析的可选属性（码点 + 原始字节）。

### 4.6 消息时序（RFC 8489 校验，`message` / `attribute`）

- `Message::integrity()` 返回 `Option<&AttributeLocation>`，`Message::fingerprint_offset()` 返回 trailer 偏移；`Message::has_fingerprint()` / `has_integrity()`。
- 写侧顺序：先 `emit_attribute_value` 追加全部属性 → `integrity::compute`（会先把 message-length 临时改到 HMAC 结束处再计算，计算后回填正确值）→ `fingerprint::compute`（CRC-32 覆盖含 FINGERPRINT 属性本身的字节，最后写入 value）。
- trailer 位置检查失败时报 `MessageIntegrityNotLast` / `FingerprintNotLast`。

### 4.7 transaction id（`transaction_id`）

- `TransactionId([u8; 12])`：`LEN = 12`、`from_bytes([u8;12])`、`as_bytes() -> &[u8; 12]`、`key_tail() -> [u8; 8]`（用于 long-term key 派生）、`random()`（**需 `rand` feature**）、`AsRef<[u8]>`、`From<[u8;12]>`、`Into<[u8;12]>`。

### 4.8 integrity（`integrity`）

- `IntegrityAlgorithm`：`Sha1` / `Sha256`；`attribute_code()`、`mac_len()`、`credential_names()`。
- `IntegrityKey`：`ShortTerm` / `LongTerm` / `Static`；`as_bytes(bytes)`。
- key 派生：`short_term_key(password) -> &[u8]`、`long_term_key(username, realm, password) -> [u8;16]`（MD5）、`static_key(user_at_realm, static_secret) -> [u8;20]`（SHA-1）。
- 计算与校验：`compute(datagram: &mut [u8], attr_off, algorithm, key) -> Result<[u8;32], Error>`、`verify(datagram, attr_off, algorithm, key) -> Result<(), Error>`、`compute_prefix(datagram, attr_off, mac_len, key)`（不落盘的预计算）、`mac_input(datagram, attr_off, mac_len) -> Result<Vec<u8>, Error>`（供 `server`/`core` 调试与测试比对）。
- 定位：`attribute_offset(datagram) -> Option<AttributeLocation>`；`AttributeLocation::algorithm()` / `is_last(datagram)`；`integrity_pad_value_len(value_len)`。
- 凭证类型常量：`CREDENTIAL_SHORT_TERM` = 1、`CREDENTIAL_LONG_TERM` = 2、`CREDENTIAL_STATIC` = 3。

### 4.9 fingerprint（`fingerprint`）

- `Fingerprint(u32)`：`bits()` / `from_bits()` / `to_bytes()` / `from_bytes()` / `from_bytes_opt()` / `over(&[u8])`（对给定字节算 CRC-32）/ `crc32_of(v)` / `LowerHex` / `Display`。
- `compute(datagram: &mut [u8], fp_off) -> Result<Fingerprint, Error>`、`verify(datagram, fp_off) -> Result<(), Error>`、`attribute_offset(datagram) -> Option<usize>`。
- 常量：`FINGERPRINT_XOR = 0x53_54_55_4E`、`FINGERPRINT_ATTR = 0x8028`、`FINGERPRINT_VALUE_LEN = 4`、`MAX_ATTRIBUTE_COUNT = 32_767`。

### 4.10 错误类型（`error`）

- `ErrorKind`：`MagicCookie`、`TooShort`、`LengthMismatch`、`LengthTooLarge`、`TruncatedAttribute`、`TrailingOctets`、`MalformedAttribute`、`MalformedAddress`、`UnsupportedAddressFamily`、`MalformedErrorCode`、`MalformedChannelNumber`、`MalformedAlternateServer`、`MalformedRelayedAddress`、`InvalidUtf8`、`DuplicateAttribute`、`UnknownRequired`、`MissingMessageIntegrity`、`MessageIntegrityMismatch`、`MessageIntegrityNotLast`、`MessageIntegritySha256Length`、`MessageIntegritySha256Mismatch`、`MissingFingerprint`、`FingerprintMismatch`、`FingerprintNotLast`、`MissingUsername`、`MissingRealm`、`MissingNonce`、`MissingUserHash`、`MissingNonceForUserHash`、`MissingPasswordAlgorithms`、`UnsupportedPasswordAlgorithm`、`DuplicatePasswordAlgorithm`、`ValueTooLong`、`TooManyUnknownAttributes`、`MalformedConnectionId`、`MissingPriority`、`MissingD4Limit`。
- `Error { kind: ErrorKind, attribute: Option<u16> }`：`Copy`、`Eq`、`Debug`、`std::error::Error`、`Display`、`new(kind)`、`attr(kind, code)`、`From<Error> for std::io::Error`（映射为 `InvalidData`）。
- **`Error` 不持有任何引用**（`Copy`），可以安全存入连接结构而不会延长 buffer 生命周期。

### 4.11 140 必须补齐的两处缺口（阻塞 141，须在 140 合入前完成）

1. **新增 `AttrCode::ChangeRequest = 0x0003` 与 `Attribute::ChangeRequest(u32)`**，并在 `attr_from_wire` / `as_u16` / `attribute_kind` / `parse_attribute_value` / `write_attribute_value` 五处接入，同时把它加进 `is_comprehension_optional`（0x0003 < 0x8000，因此是 comprehension-required）。理由：RFC 5780 section 2.1 与 RFC 8489 section 13.17 都把 CHANGE-REQUEST 定义为 `0x0003`，coturn 与 stun-rs 均按此收发；IANA 注册表把该值登记为 Reserved 属历史遗留，不影响互操作。142 需要按位语义解析它，不能走 `Attribute::Unknown`。

2. **新增响应构建器**（建议 `message::build_response(msg_type, txid, attrs) -> Vec<u8>`，内部完成 20 字节头拼装与 message-length 回填）。当前 crate 只有解析与 `emit_*` 追加，若不加，141 就必须在 `transport` 与 `server` 内各写一份 header 拼装。若 141 认为构建器应归 `server` 独占，需在本单回帖确认后由 `server` 实现，**但不得两处都有**。

以下顺序与 140 现有 RFC 8489 单测一致，构建器必须按此实现：

```rust
// 1) 20 字节头：message_type.bits() | message_length 占位 2 字节 | magic cookie | txid
let mut out: Vec<u8> = /* 20 bytes */;
// 2) 逐个属性
for a in attrs { attribute::emit_attribute_value(&mut out, a, txid.as_bytes()); }
// 3) 需要 HMAC 时（message_length 由 compute 自行临时改写并回填）
integrity::compute(&mut out, integrity_attr_offset, IntegrityAlgorithm::Sha1, key)?;
// 4) 需要 CRC 时（CRC 覆盖含 FINGERPRINT 属性本身的字节）
fingerprint::compute(&mut out, fingerprint_offset)?;
// 5) message_length = out.len() - HEADER_LEN（含 FINGERPRINT 属性本身）
out[2..4].copy_from_slice(&(out.len() - protocol::HEADER_LEN) as u16.to_be_bytes());
```

---
## 5. API 冻结等级与变更方式（对应本单验收 2）

| 等级 | crate / 面 | 含义 |
| --- | --- | --- |
| **F0 冻结** | `quickrelay-protocol` 全部 `pub` API（section 4 全节） | 不得改名、不得改签名、不得删项。任何改动视为破坏性变更 |
| **F1 冻结** | `quickrelay-binding` 全部 `pub` API（`BindingResponsePlan` / `Outcome` / `ChangeSource` / `ResponseSink` / `ServerIdentity` / `ChangeRequest` / `ChangeResponseAction` / `ErrorCode` / `ReasonPhrase` / `IceAttributes` / `IceRole` / `IceTiebreaker`，见 section 7.2）；`quickrelay-transport` 的 `BindingHandler` / `ConnectionId` / `FrameError` / `FRAME_PREFIX_LEN` / `MAX_FRAME_PAYLOAD`（长度前缀 2 字节大端） | 同上 |
| **F2 未冻结** | `quickrelay-server` 全部 API（含 `binding_chain`） | 本轮可自由调整，因为下游只有 CLI |

**允许变更的方式**（F0/F1 唯一合法路径）：

1. 在本单（或其后继的架构裁决单）回帖提出变更请求，写明：改动项、理由、下游（140/141/142）影响面。
2. 架构师回帖确认后，在 `workspace-layout.md` section 4/section 3 同步更新条目，再改代码。
3. 破坏性变更必须走 **bump crate 版本到 `0.2.0` + 迁移记录**，不得原地替换签名。
4. **只允许加法**：新增类型、新增 `pub fn`、新增枚举变体（且枚举变体新增对下游是破坏性的，需先确认下游 `match` 是否穷尽），都不算破坏性变更。

**评审检查项**（每个 PR 必查）：
1. 是否出现 section 3 禁止的依赖边。
2. 是否出现 `binding` 内的 framing 代码，或 `transport` 内的语义判定代码。
3. 是否出现 IANA Unassigned 的码点（尤其 430/390/370 三个错误码、0x0003 CHANGE-REQUEST）。
4. `protocol` 的 `src/lib.rs` 的 `pub use` 面是否与 section 4 一致。

---

## 6. 三条单的收敛动作清单（对应本单验收 3）

### 6.1 统一前提（三条单都先做）

```bash
git fetch origin
git reset --hard origin/main          # 骨架 commit 见 section 7.1
```

骨架已包含 4 个 crate 的 `Cargo.toml` 与占位 `src/lib.rs`。**三条单都不许再改 root `Cargo.toml` 的 `[workspace]` / `[profile.release]`**；需要新增 workspace 依赖时，只允许追加 `[workspace.dependencies]` 条目，并在回帖说明。

### 6.2 YEJ-140（消息编解码）

**保留**
- 9 个源文件的内容：`message.rs` / `attribute.rs` / `message_type.rs` / `address.rs` / `fingerprint.rs` / `integrity.rs` / `error.rs` / `transaction_id.rs` + `lib.rs`。
- crate 内所有 `#[cfg(test)]` 模块与 117 个 RFC 向量单测（含 RFC 5769 向量）。

**删除**
- 自己 worktree 里的 root `Cargo.toml`（以 main 骨架为准）。
- 脚手架垃圾：`fix_prefix.py`、`probe2.py`、`probe_out.txt`、`test_fail.txt`、`verify_crc.txt`、`verify_masks.py`、`verify_out.txt`、`vector-derivation/`。
- `.claude/vectors.py`（**必须迁到 `tests/rfc-vectors/` 或 `scripts/` 后再删**；迁移后单测从该处读取向量）。

**对齐**
1. 把源文件落到 `crates/quickrelay-protocol/src/`，`Cargo.toml` 以骨架为准（依赖 `bytes`/`crc32fast`/`hmac`/`md5`/`sha1`/`sha2`/`subtle` + 可选 `rand` feature）。
2. `src/lib.rs` 的 `pub mod` 列表与 `pub use` 面**必须与 section 4 完全一致**；模块路径不得移动。
3. **按 section 4.11 第 1 条新增 `AttrCode::ChangeRequest = 0x0003`**，并把 section 4.3 的码点表补上该变体。`0x8003` 保持解析为 `AlternateDomain`（IANA 中 0x8003 只有 ALTERNATE-DOMAIN 一个名字）——两者码点不同，不存在冲突。`CHANGE-ADDRESS` / `CHANGED-ADDRESS`（`0x0005`）同样已 Reserved，**不解析**。
4. `ERROR-CODE` 便捷构造函数中**不得**出现 Unassigned 码点；`role_conflict` 必须是 `487`。
5. `TransactionId::random()` 依赖 `rand` feature；141 会在 `[dependencies]` 里写 `quickrelay-protocol = { workspace = true, features = ["rand"] }`。

**不要做**：不要动 `crates/quickrelay-binding`、`crates/quickrelay-transport`、`crates/quickrelay-server` 下的任何文件。

### 6.3 YEJ-141（UDP/TCP 传输层 + Binding 链路）

**保留**
- 自己的 `quickrelay-transport/Cargo.toml` 与 `quickrelay-server/Cargo.toml` 结构（`transport` 与 `server` 两个 crate 名与本契约一致）。
- `order.rs` 的时序检查内容——但**只保留为测试或迁移**：FINGERPRINT/INTEGRITY 的时序校验已在 `quickrelay-protocol` 内实现并冻结，`transport` 侧不得再实现一份。

**删除**
- **整个 `crates/quickrelay-protocol/`**（`codec.rs` / `attr.rs` / `err.rs` / `method.rs` / `order.rs` / 该 crate 的 `Cargo.toml`）。141 对 `quickrelay-protocol` 的全部使用改为 section 4 的 API。
- 141 工作树里 root `Cargo.toml` 的 `[workspace.dependencies]` 中未被骨架收录的条目，需**追加**到 main 骨架，而不是替换骨架。
- 脚手架垃圾：`sweep.py`、`sweep2.py`、`sweep3.py`、`rfc5769_check.py`、`children.json`、`t1.json`、`err.txt`。
- `[[bin]]` 目标改为骨架中定义的 `src/main.rs`（骨架已写死 `path = "src/main.rs"`，141 不要再改成 `src/bin/quickrelay.rs`）。

**对齐**
1. `transport` 不得依赖 `quickrelay-binding`；收到 STUN 消息后通过 `BindingHandler` trait 上抛。
2. Binding 请求-响应链路的装配代码放 `quickrelay-server`（`binding_chain.rs`），映射代码只在此处（见 section 3.2）。
3. framing（16 位大端长度前缀）在 `transport` 内实现，**142 不需要也不得实现**。
4. `quickrelay-server` 必须能引用 `quickrelay-binding`（骨架已加该依赖），并在 `binding_chain.rs` 里实现 `binding::ResponseSink`。
5. `transport` 的 `src/lib.rs` 的 `pub use` 面须包含骨架中已声明的 `BindingHandler` trait、`ConnectionId`、`FrameError` 与 `FRAME_PREFIX_LEN` / `MAX_FRAME_PAYLOAD`，签名不得改。
6. 需要 transaction id 随机生成时：`quickrelay-protocol` 加 `features = ["rand"]`。

**不要做**：不要动 `crates/quickrelay-protocol/`、`crates/quickrelay-binding/`。

### 6.4 YEJ-142（Binding 语义 + ICE 校验）

**保留**
- `change_request.rs` / `error_codes.rs` / `ice.rs` / `ice_tcp.rs` / `response.rs` 五个模块与其内容。
- `yej142_note.md` 与 `yej142_verification.md` 的核验结论（其中关于 `protocol-matrix.md` 码点错乱的结论已部分由 140 修正）。

**删除**
- **整个 `crates/quickrelay-binding/` 下 142 自带的 root `Cargo.toml`**（以 main 骨架为准）。
- **`ice_tcp.rs` 中任何 framing 实现**（长度前缀读写、`FrameRead` / `FrameTransport` 若在 `binding` 里）：framing 归 `transport`。142 的 ICE-TCP 交付物是**语义校验 + loopback 集成测试**，测试中的 listener 由 141 的 `transport` 提供（若 141 未就绪，用 `socket2` dev-dependency 写 loopback 测试是可以的，但测试文件放 `crates/quickrelay-binding/tests/`，不得在 `src/` 里留 framing 代码）。
- 142 工作树内的所有临时文件：`.scratch/`、`.work/`、`cur.json`、`children.json`、`parent_comments.json`、`scratch_children.json`、`t3.json`、`y140.json`、`y140c.json`、`y141.json`、`err.txt`。
- `src/lib.rs` 中当前声明的 `ice_tcp::{FrameError, FrameRead, FrameTransport}` 与 `change_request`/`error_codes`/`ice`/`response` 的 `pub use` **必须逐字替换为骨架中的版本**（骨架已移除 `ice_tcp` 的 framing 导出）。

**对齐**
1. `quickrelay-binding` **不得依赖 `quickrelay-protocol`**（骨架 `Cargo.toml` 里没有任何依赖，别加）。所有输入/输出类型自带定义。
2. ICE 角色冲突的错误码用 **`487`**（RFC 8445 section 7.2.1.1）。**不得使用** `430`（Unassigned）。
3. STALE NONCE 用 **`438`**（RFC 8489 section 9.2.5）或 TURN 语境下的 **`372`**（RFC 6051）。**不得使用** `390`（Unassigned）。
4. `REQUEST ALREADY IN PROGRESS` **不存在**（`370` Unassigned，RFC 8656 已废弃）。142 在 issue 回帖中确认这一条验收无法按字面完成，改以「重复事务处理的既有事务拒绝语义」为准。
5. `CHANGE-REQUEST` 按 `0x0003`（RFC 5780 section 2.1 / RFC 8489 section 13.17）处理，位含义 A（change IP）/ B（change port），与 RFC 5780 section 6.1 Table 1 一致；RFC 8489 已废止 legacy 码点 `CHANGE-ADDRESS`（`0x0005` 亦为 CHANGED-ADDRESS 旧值），**两者都不解析**，收到时按「不认识的属性」处理。
6. ICE 属性码点：`ICE-CONTROLLED = 0x8029`、`ICE-CONTROLLING = 0x802A`、`ICE-PRIORITY = 0x0024`、`OTHER-ADDRESS = 0x802C`（与 140 的 `AttrCode` 一致）。
7. `ErrorCode` 与 `protocol::ErrorCode` 的映射代码放 `server`（141 写），不放 `binding`。

**不要做**：不要动 `crates/quickrelay-protocol/`、`crates/quickrelay-transport/`、`crates/quickrelay-server/`。

---

## 7. 骨架落地与合并顺序（对应本单问题 4、5 与验收 4）

### 7.1 骨架 commit

- **分支**：`main`
- **commit**：`874816100448821a4aa3c296250a978343c4e815`（fast-forward from `f8e6d10`，已推 `origin/main`）
- **内容**：`Cargo.toml`、`.gitignore`、`config.example.toml`、`docs/architecture/workspace-layout.md`、`crates/quickrelay-protocol/{Cargo.toml,src/lib.rs}`、`crates/quickrelay-binding/{Cargo.toml,src/lib.rs,src/change_request.rs,src/error_codes.rs,src/ice.rs,src/response.rs}`、`crates/quickrelay-transport/{Cargo.toml,src/lib.rs}`、`crates/quickrelay-server/{Cargo.toml,src/lib.rs,src/main.rs}`。
- **注意**：骨架中的 workspace 依赖声明包含**尚未被任何 crate 使用**的条目（如 `socket2`、`mio`、`clap` 等），Cargo 会忽略未引用的 workspace dep，不会报错；`quickrelay-binding` 与 `quickrelay-protocol` 当前无第三方依赖，可直接编译。

### 7.2 每个 crate 的 `lib.rs` 应保留的占位内容（供核对）

| crate | `src/lib.rs` 必须逐字保留的开头内容 |
| --- | --- |
| `quickrelay-protocol` | `//! # quickrelay-protocol` + `//! FROZEN API (F0) — see docs/architecture/workspace-layout.md section 4.` + `//! OWNED BY: YEJ-140. NO OTHER ISSUE MAY EDIT THIS CRATE.`（140 把自己的 `pub mod`/`pub use` 追加在此之后） |
| `quickrelay-binding` | `//! # quickrelay-binding` + `//! FROZEN API (F1) — see docs/architecture/workspace-layout.md section 3.2.` + `//! OWNED BY: YEJ-142. NO I/O, NO I/O DEPENDENCIES, NO PROTOCOL DEPENDENCY.` + 骨架已写死的 4 个 `pub mod` 与 `pub use` |
| `quickrelay-transport` | `//! # quickrelay-transport` + `//! FROZEN API (F1) — see docs/architecture/workspace-layout.md section 2.3.` + `//! OWNED BY: YEJ-141. DO NOT DEPEND ON quickrelay-binding.` + 骨架已写死的 `BindingHandler` trait、`ConnectionId`、`FrameError` 与 `FRAME_PREFIX_LEN` / `MAX_FRAME_PAYLOAD` |
| `quickrelay-server` | `//! # quickrelay-server` + `//! UNFROZEN (F2) — see docs/architecture/workspace-layout.md section 2.4.` + `//! OWNED BY: YEJ-141.` |

### 7.3 合并顺序

| 序 | 动作 | 阻塞关系 |
| --- | --- | --- |
| 1 | 本单骨架已推 `main`（已完成） | — |
| 2 | YEJ-140：rebase 到骨架 → 只动 `crates/quickrelay-protocol/` → PR → 合入 | — |
| 3 | YEJ-142：rebase 到骨架 → 只动 `crates/quickrelay-binding/` → PR → 合入 | 可与 2 并行 |
| 4 | YEJ-141：rebase 到骨架 → 只动 `crates/quickrelay-transport/` + `crates/quickrelay-server/` → PR → 合入 | `server` 的 `binding_chain.rs` 需要 142 的 API 已合入；若 142 未就绪，`binding_chain.rs` 先写映射骨架 + `#[cfg(feature = "binding")]`，不得 stub 出 `binding` 的语义 |
| 5 | Stage 3 新单（143/144/145/146）：在 `main` 上创建 `quickrelay-core` / `quickrelay-auth`，遵守 section 1.1 与 section 3 的依赖方向 | 依赖 4 |

**冲突处理规则**：三个 crate 目录之间**互不改**，因此 141/142 的 PR 互相无冲突；140 与其他两者也无冲突。唯一可能的冲突面是 root `Cargo.toml` 的 `[workspace.dependencies]`，处理方式是**追加而非替换**，冲突时保留两边新增条目。

---

## 8. 本契约未覆盖的事项

- `quickrelay-core` / `quickrelay-auth` / `quickrelay-metrics` 的内部结构（Stage 3/4 由各自 issue 定稿，但 crate 名与职责已锁定）。
- `config.example.toml` 的参数全集（Stage 4 的 YEJ-147 定稿；骨架只放骨架注释）。
- `protocol-matrix.md` 的码点勘误回填（142 的核验记录已指出三张表错乱；140 的 `AttrCode` 是正确值，由 140 或后续单回填该文档）。

---
