# 协议与消息格式矩阵

状态：定稿。本矩阵是 Stage 2/3 实现 issue 的裁剪依据，也是与 coturn 默认行为对齐的验收清单。

标记说明：**M = 必须支持**（coturn 默认启用，WebRTC 客户端普遍使用，或 RFC 强制）；**O = 可选支持**（RFC 定义但服务端可忽略，或不影响 WebRTC 主流链路）；**X = 不支持**（注明理由，并给出客户端可见行为）。

所有 `M` 项必须有 round-trip 测试 + 至少一条畸形输入测试；所有 `X` 项必须验证「不崩溃、不响应、客户端可优雅降级」。

> **编码号来源**：attribute code 以 IANA "STUN Codes" 注册表为准。本文档中的 RFC 章节号是设计期标注，实现阶段（YEJ-140）必须用 IANA 注册表交叉核对一次，发现偏差以注册表为准并回填本文档。

---

## 1. STUN / TURN Message Types

| Code | 名称 | RFC | 支持 | 说明 |
| --- | --- | --- | --- | --- |
| `0x0001` | Binding Request | 5389 §5.2 | **M** | ICE 核心；每个 STUN 客户端都会发 |
| `0x0101` | Binding Response | 5389 §5.2 | **M** | 应答 `XOR-MAPPED-ADDRESS` + `SOFTWARE` |
| `0x0002` | Shared Secret Request | 5389 §5.2 | **O** | ICE-TO-ICE 共享密钥，WebRTC NAT 穿透不用；仅解析与丢弃，避免误判为未知类型 |
| `0x0102` | Shared Secret Response | 5389 §5.2 | **O** | 同上 |
| `0x0003` | Shared Secret Error | 5389 §5.2 | **X** | 服务端不产生该响应；收到请求按「不响应」处理（coturn 默认也不响应） |
| `0x0004` | Error | 5389 §5.2 | **M** | STUN 通用错误响应载体，与 `ERROR-CODE` 属性配对 |
| `0x0006` | Allocate Request | 6051 §7 | **M** | TURN 核心 |
| `0x0106` | Allocate Success | 6051 §7 | **M** | 应答 `XOR-RELAYED-ADDRESS` + `LIFETIME` + `XOR-MAPPED-ADDRESS` + `XOR-PEER-ADDRESS` |
| `0x0007` | Refresh Request | 6051 §7 | **M** | 含 Refresh Lifetime 为 0 的「Stop」语义 |
| `0x0107` | Refresh Success | 6051 §7 | **M** | 应答 `LIFETIME` |
| `0x0008` | Send Request | 6051 §7 | **M** | TURN over TCP 的 peer-relay 载体（WebRTC TURN-over-TCP 场景需要） |
| `0x0009` | Data Indication | 6051 §7 | **M** | TURN over TCP 的 relayed 载体 |
| `0x000A` | CreatePermission Request | 6051 §7 | **M** | `XOR-PEER-ADDRESS` |
| `0x000B` | ChannelBind Request | 6051 §7 | **M** | 前置 permission 检查 |
| `0x0012` | ChannelData | 6051 §7 / 6062 | **M** | 承载 Data/Permission/CreatePermission 的通道数据 |
| `0x0013` | Stop Request | 6051 §7 | **M** | 立即停止 allocation |
| `0x0014` | Send Indication | 6051 §7 | **M** | 与 `Send Request` 配对，TURN over TCP 用 |
| `0x0015` | ChannelBind Success | 6051 §7 | **M** | |
| `0x0016` | Send Success | 6051 §7 | **M** | |
| `0x8001` | Unknown Attributes Request | 8489 §3.1 | **O** | 服务端不主动产生；**必须能识别**，以便把其作为「被请求的未知 attribute」来源（见下节） |
| `0x8101` | Unknown Attributes Response | 8489 §3.1 | **O** | 同上，不主动产生 |
| — | 任何未知 Message Type | — | **X** | 收到后**丢弃不响应**（RFC 5389 §5.1 规定服务端只响应它能处理的类型）；计数到 `quickrelay_packets_total{kind="unknown_type"}` |

---

## 2. STUN Attributes（RFC 5389 / RFC 8489）

| Code | 名称 | RFC | 支持 | 方向 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `0x8001` | MAPPED-ADDRESS | 5389 §13.1 | **M** | 应答 | RFC 5769/5389 兼容路径保留；coturn 默认应答同时带 `XOR-MAPPED-ADDRESS` |
| `0x8002` | RESPONSE-ADDRESS | 5389 §13.2 | **M** | 应答 | 与 `SOURCE-ADDRESS` 配对 |
| `0x8003` | CHANGE-REQUEST | 5389 §13.3 | **M** | 请求 | ICE 候选探测，`--listening-ip` 多地址场景关键 |
| `0x8004` | CHANGE-IP | 5389 §13.4 | **O** | 请求 | 依赖多 IP 监听；本设计支持多 `--listening-ip` 时启用 |
| `0x8005` | CHANGE-PORT | 5389 §13.5 | **M** | 请求 | ICE 候选探测核心 |
| `0x8006` | SOURCE-ADDRESS | 5389 §13.6 | **M** | 请求 | RFC 强制校验（否则 385 `ERROR_CODE` 触发条件） |
| `0x8007` | CHANGE-ADDRESS | 5389 §13.7 | **O** | 请求 | 依赖多地址监听，与 `CHANGE-IP` 同档 |
| `0x8008` | ALTERNATE-SERVER | 5389 §13.8 | **O** | 应答 | 多实例/高可用配置时启用；本设计预留 `--alternate-server` 配置项 |
| `0x8009` | SOFTWARE | 5389 §13.9 | **M** | 应答 | 客户端调试刚需，coturn 默认在 Binding/Allocate 应答中附带 |
| `0x800A` | HARDWARE-VERSION | 5389 §13.10 | **X** | — | RFC 5389 已明确标注 deprecated；**不产生**，收到也不作为未知错误处理 |
| `0x800B` | FINGERPRINT | 5389 §11 | **M** | 请求/应答 | `--fingerprint` 对齐 coturn；校验失败 → `400 BAD_REQUEST`（`INTEGRITY_CHECK` 类） |
| `0x800C` | PRIORITY | 5389 §13.12 | **X** | — | RFC 5389 deprecated（ICE 早期候选优先级），不产生；**收到需识别但不作为未知 attribute 上报** |
| `0x800D` | XOR-MAPPED-ADDRESS | 5389 §13.13 | **M** | 应答 | ICE 核心 |
| `0x800E` | XOR-MAPPED-ADDRESS-VPNV4 | 8489 §3.2 | **O** | 应答 | 仅在 `--vpn-mapping` 显式启用时产生 |
| `0x800F` | XOR-MAPPED-ADDRESS-VPNV6 | 8489 §3.2 | **O** | 应答 | 同上 |
| `0x8010` | DATA-IP | 5389 §13.16 | **X** | — | 仅用于 `Send Request`/`Data Indication` 的 legacy TURN over TCP 地址编码；本设计**不**支持旧版 DATA-IP 路径，TURN over TCP 走 `XOR-PEER-ADDRESS`。理由：RFC 6051 已把 peer 地址统一到 `XOR-PEER-ADDRESS`，`DATA-IP` 属 5769 兼容层，现代 WebRTC 栈不再发送 |
| `0x8011` | CHANNEL-CIPHER | 8489 §3.3 | **O** | 请求/应答 | 服务端**只支持 `default-cipher`**；`aescfb128` 等加密 channel 不实现（RFC 8489 §3.3 已建议服务端优先用默认 cipher；coturn 默认也不启用加密 channel）。理由：加密 channel 的 CPU 成本 + 与 TURN over TLS 的功能重叠（TLS 已提供通道级加密） |
| `0x8012` | CHANNEL-CIPHER-RECV | 8489 §3.4 | **O** | 请求 | 同上，仅识别 `default-cipher` |
| `0x8013` | CHANNEL-CIPHER-SEND | 8489 §3.4 | **O** | 请求 | 同上 |
| `0x8014` | MESSAGE-INTEGRITY | 5389 §11 | **M** | 请求/应答 | HMAC-SHA1 |
| `0x8015` | MESSAGE-INTEGRITY-256 | 8489 §3.5 | **O** | 请求/应答 | SHA-256 变体，配置项 `--alt-hmac-sha1` 开启；**RFC 6051 的标准 Message Integrity 只定义 SHA-1**，本项是 8489 引入的扩展，客户端默认不发。文档必须明确：不启用时该 attribute 按未知 attribute 上报 |
| `0x8016` | INVALID-CREDENTIAL | 8489 §3.6 | **O** | 请求/应答 | 仅识别与透传；本设计的认证实现用 `401 UNAUTHORIZED` + `ERROR-CODE` 表达凭证问题（对齐 coturn 默认），不主动产生该 attribute |
| `0x8017` | ERROR-CODE | 5389 §13.21 | **M** | 应答 | 全部错误响应必须携带 |
| `0x8018` | UNKNOWN-ATTRIBUTES | 5389 §13.4 | **M** | 请求/应答 | RFC 5389 §13.4 强制：客户端收到未知 attribute 时必须上报；服务端响应中回显已识别的未知项。coturn 默认启用 |

### ICE 相关属性（RFC 5389 §13.18-13.20，从 RFC 5245 迁移）

| Code | 名称 | RFC | 支持 | 方向 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `0x8019` | ICE-CONTROLLING | 5389 §13.18 | **O** | 请求 | 仅识别与透传；QuickRelay 是中间件不是 ICE agent，不产生 `430 ROLE CONFLICT` 的完整 ICE 逻辑 |
| `0x801A` | ICE-CONTROLLED | 5389 §13.19 | **O** | 请求 | 同上 |
| `0x801B` | SOFTWARE | 5389 §13.20 | **M** | 请求 | 已在 `0x8009` 行覆盖（ICE 客户端常发） |
| `0x801C` | ICE-LITE | 5389 §13.21 | **O** | 请求 | 仅识别 |
| `0x0024` | ICE-CONTROLLED（legacy） | 5245 | **O** | 请求 | 旧版编码，仅识别不产生；`turnutils_stun` 老版本会发 |
| `0x0025` | ICE-CONTROLLING（legacy） | 5245 | **O** | 请求 | 同上 |
| `0x0026` | ICE-LITE（legacy） | 5245 | **O** | 请求 | 同上 |
| `0x0027` | XOR-MAPPED-ADDRESS（legacy） | 5245 | **O** | 应答 | coturn 默认不产生 legacy 编码；本设计不产生 |
| `0x0028` | CHANNEL-CIPHER-RECV（legacy） | 5245 | **X** | — | 仅识别，本设计不支持加密 channel |
| `0x0029` | CHANNEL-CIPHER-SEND（legacy） | 5245 | **X** | — | 同上 |

---

## 3. TURN Attributes（RFC 6051）

| Code | 名称 | RFC | 支持 | 方向 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `0x8024` | XOR-PEER-ADDRESS | 6051 §13.1 | **M** | 请求 | `Allocate` / `CreatePermission` / `ChannelBind` 前置 |
| `0x8025` | XOR-RELAYED-ADDRESS | 6051 §13.2 | **M** | 应答 | `Allocate Success` 必带 |
| `0x8026` | LIFETIME | 6051 §13.3 | **M** | 请求/应答 | 含 `0` = Stop；含 `>max-alloc-lifetime` 裁剪 |
| `0x8027` | RELAYED-ADDRESS | 6051 §13.4 | **M** | 应答 | 旧版兼容，与 `XOR-RELAYED-ADDRESS` 同值同时返回 |
| `0x8028` | REQUESTED-ADDRESS-FAMILY | 6051 §13.5 | **M** | 请求 | IPv4 / IPv6 选择 |
| `0x8029` | EVEN-PEER-ADDRESS | 5128 | **M** | 请求 | RFC 5128 「EVEN-」前缀属性族，`turnutils_turn` 老版本发送；必须识别并按 `XOR-PEER-ADDRESS` 同义处理（RFC 6051 §13.1 明确映射关系） |
| `0x802A` | EVEN-RELAYED-ADDRESS | 5128 | **M** | 应答 | 与 `XOR-RELAYED-ADDRESS` 同值；`turnutils_turn --even` 模式需要 |
| `0x802B` | EVEN-SERVER-CREATE | 5128 | **O** | 应答 | 仅识别与透传 |
| `0x802C` | REASON-PHRASE | 5128 | **O** | 请求/应答 | 调试文本；本设计默认不产生 |
| `0x802D` | CHANNEL-NUMBER | 6051 §13.7 / 6062 | **M** | 请求 | ChannelData 打包核心 |
| `0x802E` | DATA | 6051 §13.8 / 6062 | **M** | 请求 | ChannelData 载荷 |
| `0x802F` | USERNAME | 6051 §13.9 | **M** | 请求 | 认证必需 |
| `0x8030` | REALM | 6051 §13.10 | **M** | 应答 | 401 响应必须携带 |
| `0x8031` | NONCE | 6051 §13.11 | **M** | 应答 | 401 响应必须携带；含时间戳 + 熵 + salt |
| `0x8032` | ERROR-CODE | 6051 §13.12 | **M** | 应答 | TURN 错误码全集见下节 |
| `0x8033` | UNKNOWN-ATTRIBUTES | 6051 §13.13 | **M** | 请求/应答 | 与 `0x8018` 同义，TURN 上下文的编码 |
| `0x8034` | D4-LIMIT | 6051 §13.14 / 6052 | **M** | 应答 | 限速上限对齐 coturn `--max-bps` / `--max-bw` |

### RFC 6062 扩展

| Code | 名称 | RFC | 支持 | 方向 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `0x8042` | FIVE-TUPLE-LIMIT | 6062 | **M** | 应答 | coturn 默认启用（`--five-tuple-limit` 相关）；WebRTC 客户端普遍读取 |

### 明确不支持的 attribute（含理由）

| Code | 名称 | 理由 |
| --- | --- | --- |
| `0x0017` | CHANNEL-CIPHER-RECV（legacy 编码） | RFC 8489 已用 `0x8012` 替代，仅识别 |
| `0x0018` | CHANNEL-CIPHER-SEND（legacy 编码） | 同上 |
| `0x8010` | DATA-IP | 旧版 TURN over TCP 载体，本设计 TURN over TCP 走 `XOR-PEER-ADDRESS` |
| `0x800A` | HARDWARE-VERSION | RFC 5389 deprecated |
| `0x800C` | PRIORITY | RFC 5389 deprecated |
| `0x8011`/`0x8012`/`0x8013` 的非 `default-cipher` 值 | 加密 ChannelData | CPU 成本 + 与 TURN over TLS 功能重叠；本设计只支持 `default-cipher` |

---

## 4. TURN 错误码（RFC 6051 §12 + RFC 5389 §13.21）

服务端必须能产生的错误码全集：

| Code | 名称 | 触发条件 |
| --- | --- | --- |
| `400` | Bad Request | 消息格式错误、attribute 长度非法 |
| `370` | Request Already in Progress | 同一 allocation 上重复 Refresh |
| `371` | Unsupported Address Family | `REQUESTED-ADDRESS-FAMILY` 与配置不符 |
| `372` | Stale Nonce | nonce 过期 / 重放 |
| `373` | Wrong Credentials | USERNAME/REALM/MESSAGE-INTEGRITY 校验失败 |
| `384` | Alternative Service | `ALTERNATE-SERVER` 场景 |
| `385` | Missing Required Attribute | `SOURCE-ADDRESS` 缺失等 |
| `437` | Allocation Misconfigured | 对未分配的 allocation 发 `Send`/`Refresh` |
| `438` | Allocation Mismatch | 同一 `XOR-RELAYED-ADDRESS` 用不同 key |
| `441` | Channel Already Exists | 重复 `ChannelBind` |
| `443` | Channel Forbidden | 无 permission 的 `ChannelBind` |
| `444` | Connection Forbidden | peer 地址被禁用 |
| `451` | Wrong Credentials | TURN 上次的凭证失败 |
| `487` | Insufficient Capacity | allocation 数达到上限 |
| `500` | Server Error | 内部错误 |
| `508` | Insufficient Capacity | 端口耗尽 / 资源不足 |

注：RFC 6051 §12.2 与 RFC 5389 §13.21 在 `401`/`437` 上有历史编码不一致，coturn 按 6051 语义处理；本设计对齐 coturn（用 `401` 表示认证失败，用 `437` 表示 allocation 未配置）。文档中明确标注此差异，供测试比对。

---

## 5. 与 coturn 默认行为的对齐清单

以下是 coturn `turnserver` **默认启用**的行为，QuickRelay 必须对齐：

| coturn 默认行为 | QuickRelay 对应 |
| --- | --- |
| UDP relaying 开启 | `quickrelay` 默认开启 |
| TCP relaying 开启 | 默认开启（WebRTC TURN over TCP 需要） |
| TLS relaying 需 `--use-tls` 显式启用 | 本设计：**TURN over TLS 是需求方确认的必须项，因此默认开启**，且支持 `--no-tls` 关闭。文档中明确标注此与 coturn 默认的差异 |
| peer relaying 默认开启 | 默认开启，`--no-peer` 关闭 |
| data relaying 默认开启 | 默认开启，`--no-data` 关闭 |
| channel relaying 默认开启 | 默认开启，`--no-channel` 关闭 |
| 不启用加密 ChannelData | 本设计仅支持 `default-cipher` |
| 不启用 multicast peer | 默认禁用，`--multicast-peers` 启用 |
| SHA-1 作为 Message Integrity 默认算法 | 本设计默认 SHA-1；`--hmac-sha256` 可选启用 `MESSAGE-INTEGRITY-256`（RFC 5769 §3.14 扩展，**coturn 不实现**，故默认关闭以保兼容） |
| 应答附带 `SOFTWARE` | 本设计默认附带 `quickrelay/<version>-<sha>` |
| `--min-timeout` 默认 60s、`--max-timeout` 默认 600s | 本设计同值默认 |
| `--max-alloc-lifetime` 默认 300s（RFC 6051 建议默认） | 本设计同值默认 |
| `--max-bps` 默认 0（不限速） | 本设计同值默认；启用时用 `D4-LIMIT` 响应 |
| `--no-quic-relaying` 默认 | 本设计不做 QUIC |
| Fingerprint 默认启用 | 本设计默认启用 |
| `--no-auth` 关闭认证 | 本设计同值 flag 保留，但生产配置默认 `--use-auth` |
| `--min-nonce-age` 默认 0、`--max-nonce-age` 默认 3600 | 本设计默认 nonce 过期窗口 60s（更保守），文档中标注差异 |

---

## 6. 时序规则（RFC 5389 §11）

Message Integrity 与 Fingerprint 的相对位置规则是硬约束：

1. `MESSAGE-INTEGRITY` 必须是消息中**除 `UNKNOWN-ATTRIBUTES` 外**的最后一个 attribute。
2. `FINGERPRINT` 必须是消息中的**最后一个** attribute。
3. 因此顺序为：`...业务 attribute... [MESSAGE-INTEGRITY] [UNKNOWN-ATTRIBUTES] [FINGERPRINT]`。
4. 服务端在计算 HMAC 时，必须**临时清零** `MESSAGE-INTEGRITY` 与 `FINGERPRINT` 的长度字段再计算，且计算的是清零后的字节流。

本设计的编解码器在写入路径上必须固化上述顺序，测试用例需断言字节序列。

---

## 7. 与 TLS 组合 / REST 口径的一致性复查（v2，[YEJ-167]）

本节是本矩阵与已确认口径的逐节对照结论，实现 issue 若发现不一致以本节为准并回填：

| 项 | 口径 | 本矩阵中的落点 |
| --- | --- | --- |
| **UDP-over-TLS / RFC 7635** | **必须**（WebRTC 客户端唯一实际使用的 TURN over TLS 路径，对齐 coturn `--use-tls`） | §5 的 `--use-tls` 行 |
| **TLS over TCP / RFC 8326** | **必须** | §5 的 `--use-tls` + TCP 行 |
| **RFC 6061（TURN over TLS over UDP）** | **仅接收兼容**，不作为主路径；已被 RFC 9263 标记 obsoleted | 架构文档 §0.1 勘误、§8.1 |
| **TURN over TCP（明文）** | **必须** | §1 的 `0x0008` / `0x0009` / `0x0014`（Send Request / Data Indication / Send Indication） |
| **ICE-TCP 协商** | **必须** | §1 / §3 的完整 attribute 支持面 |
| **REST 双鉴权头名** | Bearer token = `Authorization: Bearer <token>`；HMAC 签名 = `X-QuickRelay-Date` + `X-QuickRelay-Signature`；可各自开关、可同时启用，同时启用时 **Bearer 优先** | 架构文档 §9.5 |
| **REST HTTP 错误码** | `401` / `403` / `400` / `404` / `409`（含凭证类键 DELETE 与需重启项） | 架构文档 §9.5 |

**错误码命名空间区分（防止混淆）**：本矩阵 §4 的 `401` / `437` / `487` / `508` 等是 **TURN / STUN 协议错误码**（`ERROR-CODE` attribute，RFC 6051 §12 + RFC 5389 §13.21），出现在 STUN/TURN 消息体内；架构文档 §9.5 的 `401` / `403` / `409` 等是 **REST 端点的 HTTP 状态码**。两者编号相同但**不属于同一命名空间**，测试断言必须明确是哪种（协议码断言 `ERROR-CODE` 属性值，HTTP 码断言响应状态行）。
