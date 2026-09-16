# YEJ-142：本 turn 无代码产出 —— 依赖未就绪 + issue 验收面与 RFC 原文冲突

**状态**：保持 `in_progress`，未提交任何代码或测试到仓库。

先说结论，再说理由。这个 issue 按字面写的验收标准有两条现在**无法闭合**，另外范围描述里有三处与 RFC 原文冲突，需要先校准再开工，否则会把错误的前提固化进代码。以下是我核过一手来源（IANA STUN registry、RFC 5780 / 6544 / 4571 / 8445 / 8489 / 6051 / 6062 原文）后的记录。

---

## 一、依赖现状（阻塞点）

| 依赖 issue | 当前状态 | 我缺什么 |
| --- | --- | --- |
| YEJ-140 消息编解码 | `in_progress`（另一 agent 持有） | `quickrelay-protocol` 的 attribute codec API 与 golden vector 测试框架。430/390/370 的错误码承载结构（`ErrorCode` 枚举、`ERROR-CODE` attribute 构造）是 140 的产物，我先写就得自造接口，140 合入后大概率重写 |
| YEJ-141 UDP/TCP 传输层 | `todo`，未被启动 | TCP framing 与 loopback 集成测试脚手架。验收标准第 2 条「ICE-TCP Binding loopback 集成测试」需要真实 TCP listener |
| YEJ-138 架构 | `done`，已合 main | 无。§10.2 把 142 放在 G3，依赖 G2（141） |

所以验收标准 1、2 两条在当前依赖下**结构上不可达**，不是我没做，是没有可指向的 endpoint 与可复用的 codec。

---

## 二、issue 验收面与 RFC 原文冲突（需先校准）

这几条是我建议开工前必须改的，逐条给了原文依据：

**1. 「`turnutils_stun --change-addr` / `--change-port`」这个工具不存在。**
仓库自己的调研已经记录了（`docs/research/coturn-test-assets.md`、`docs/research/performance-baseline.md`）：coturn 上游当前树里没有 `turnutils_stun`，4.18.0 起改名为 `turnutils_stunclient`，且**没有任何 `--test` 自检模式**。`turnutils_stunclient` 的能力面只有 `-c`（连续 RTT）/`-i`/`-t`，它**不做 NAT 行为探测**，因此也**没有** CHANGE-IP/CHANGE-PORT 探测能力。
→ 要验证 CHANGE-IP/CHANGE-PORT 语义，唯一可行的是自写一个探测客户端（Rust 或 Python，直发 CHANGE-REQUEST 并断言响应源地址/端口）。这是真正对齐 RFC 5780 §6.1 Table 1 的做法，不是对齐 coturn 命令行。

**2. CHANGE-REQUEST 只有两个位，没有「CHANGE-ADDRESS 位」。**
RFC 5780 §7.2：CHANGE-REQUEST 是 32 位，只有 **A（change IP）** 和 **B（change port）** 两位。
`CHANGE-ADDRESS` = `0x0003`，IANA registry（stun-parameters，updated 2024-12-20）明确为 **Reserved**（`"Reserved; was CHANGE-REQUEST prior to RFC5389"`）；`CHANGED-ADDRESS` = `0x0005` 同样 Reserved（RFC 5780 把它改名为 OTHER-ADDRESS，编码 `0x802C`）。
→ issue 范围第 1 条把 CHANGE-IP / CHANGE-PORT / CHANGE-ADDRESS 并列成三个「位语义」，这个提法不成立。实际只有两个 flag 位 + 一个 legacy 已废弃编码。

**3. 430 / 390 / 370 三个错误码在 IANA registry 里都不存在。**
- `430` → Unassigned（IANA 记为 421–436 Unassigned）
- `390` → Unassigned（301–399 整段 Unassigned）
- `370` → Unassigned
- `385` → Unassigned；`400`/`401` 之外 402–419 整段 Unassigned

ROLE CONFLICT 在 RFC 8445 里的正式编码是 **`487`**（RFC 8445 §7.1.3.1 与 §7.2.1.1，IANA 引用 rfc8445）。STALE NONCE 在 IANA 是 **`438`**（RFC 8489 §9.2.5），TURN 语境下 RFC 6051 用的是 **`372`**。
→ issue 范围第 5 条要求的 430/390/370 三个码是 RFC 3489 时代（RFC 5389 前身）的旧码，RFC 8489 obsoletes RFC 5389 之后全部废弃。照旧码实现会产出不可兼容的应答。

**4. ICE-TCP 的 framing 不是 24/32 位长度前缀。**
issue 范围第 4 条写「framing + 长度前缀」。实际 RFC 6544 §3（RFC 8445 §1 明确「ICE has been extended to handle TCP [RFC6544]」）规定 ICE 运行在 **RFC 4571 framing shim** 之上；RFC 4571 §2 原文：

> "A 16-bit unsigned integer LENGTH field, coded in network byte order (big-endian), begins the frame. … Zero is a valid value for LENGTH, and it codes the null packet."

即 **16 位**，与 STUN 消息自身的 2 字节长度字段是**两套不同的长度**，且 shim 同时承载 STUN、媒体、TLS、DTLS 帧。而 RFC 6062（TURN over TCP）的控制连接**只**承载 STUN 消息，不走 4571。这两条路径经常被混为一谈。
→ 开工前需明确 142 走哪条：WebRTC 的 ICE-TCP 是 RFC 6544/4571 路径；issue 范围第 4 条写的是 RFC 6062 路径。两者 framing 完全不同。

**5. ICE-CONTROLLED/CONTROLLING 的角色语义（这是唯一可以直接开工的部分）。**
RFC 8445 §7.1.3 是明确的 MUST：
> "The controlling agent MUST include the ICE-CONTROLLING attribute in a Binding request. The controlled agent MUST include the ICE-CONTROLLED attribute in a Binding request."

两者内容是 tiebreaker，用于 §7.3.1.1 / §7.2.1.1 的 role conflict 检测。IANA 编码：`0x802A` = ICE-CONTROLLING，`0x8029` = ICE-CONTROLLED。
→ 这部分与依赖无关，纯语义校验，可以独立成 PR。

---

## 三、CHANGE-REQUEST 的正确语义（RFC 5780 §6.1 Table 1）

```
Flags                Source Address   Source Port
none                 Da               Dp
Change IP (A)        Ca               Dp
Change port (B)      Da               Cp
Change IP + port     Ca               Cp
```

Da/Dp 是收到 Binding Request 的目的地址/端口；Ca/Cp 是另一组。**前提**：服务端必须同时持有两对 (IP, port)。RFC 5780 §6 原文：
> "If a server cannot allocate the same ports on two different IP address, then it MUST NOT include an OTHER-ADDRESS attribute in any Response and MUST respond with a 420 (Unknown Attribute) to any Request with a CHANGE-REQUEST attribute."

另外：
- 响应**必须**带 `MAPPED-ADDRESS` **和** `XOR-MAPPED-ADDRESS` 两者（RFC 5780 §6.1）。
- 支持 CHANGE-REQUEST 时响应**必须**带 `RESPONSE-ORIGIN`（记录实际源地址）+ `OTHER-ADDRESS`。
- 若请求同时含 `RESPONSE-PORT` 与 `PADDING` → 返回 `400`。

QuickRelay 是中间件，多监听地址靠 `SO_REUSEADDR`（非 `SO_REUSEPORT`，后者是同一进程多 worker 共享一个 socket）。因此 CHANGE-IP 的支持与否取决于运维是否配了双 `--listening-ip`，单地址部署下必须按 5780 返回 420。

---

## 四、建议

**不要现在就开工 142 的代码部分**，除非接受「自造 codec 接口 → 140 合入后重写」的确定成本。架构文档 §10.2 的原始排期（142 在 G3，依赖 G2=141）是对的。

可先拆出的独立子任务（零依赖、可立即开工）：
1. ICE-CONTROLLED/CONTROLLING 属性校验与透传 + 487 role conflict 响应组装（RFC 8445 §7.1.3 / §7.2.1.1）
2. CHANGE-REQUEST 位解析 + 420 兜底逻辑 + 5780 §6.1 Table 1 的响应源选择函数（纯函数，I/O 无关，可用 stub 的发送地址集单测）

**需要先拍板的问题**（否则实现方向会错）：
1. 错误码用 RFC 8489/8445 现行码（437/438/487/420/400），还是保留 issue 里写的 430/390/370？我强烈建议前者。
2. ICE-TCP 走 RFC 6544/4571（16 位 shim，WebRTC 实际用的路径），还是 RFC 6062（TURN over TCP，只承载 STUN）？issue 范围写的是后者，但验收标准第 2 条说的是 WebRTC 场景。
3. CHANGE-REQUEST 双地址能力是 142 交付，还是放到 Stage 4 的多监听配置里？
