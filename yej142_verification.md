# YEJ-142 核验记录 —— issue 验收面 vs RFC/IANA 权威值

- 核验日期：2026-09-16
- 核验人：代码高手Codex-02（YEJ-142）
- 一手来源（本次全部实际拉取成功，无缓存推断）：
  - IANA `stun-parameters` registry：`https://www.iana.org/assignments/stun-parameters/stun-parameters.xml`，注册表内自述 `updated=2024-12-20`
  - RFC 5780：`https://datatracker.ietf.org/doc/html/rfc5780.txt`
  - RFC 3489：`https://datatracker.ietf.org/doc/html/rfc3489.txt`
  - RFC 4571：`https://datatracker.ietf.org/doc/html/rfc4571.txt`
  - RFC 6062：`https://datatracker.ietf.org/doc/html/rfc6062.txt`
  - RFC 8445：`https://datatracker.ietf.org/doc/html/rfc8445.txt`
- 复现方式：`curl -sL <url> -o <file>`，再按 `record/definition` 元素或 `grep -n` 定位。
- 注意：`https://www.iana.org/assignments/stun-codes/stun-codes.xml` 与 `stun-codes-0.xml` 现在返回 **404（Page not found）**，IANA 已把 STUN Error Codes 合并进 `stun-parameters` 注册表，`stun-codes.xml` 不再存在。任何引用它的旧脚本/CI 步骤都会静默拿到 HTML 404 页——这是个已失效的引用。

## 0. 结论

1. 本 turn **不提交代码**：YEF-140（编解码）/ YEJ-141（传输）未就绪，实现 142 的语义层等于自造 codec 接口，140 合入后必然重写。
2. issue 验收标准里 **3 条不可达/不成立**：`turnutils_stun` 工具不存在；430/390/370 三个码在 IANA 全部 Unassigned；ICE-TCP 的 framing 前提（6062 = TURN over TCP，不走 shim）写错了 RFC。
3. **发现一个比验收标准更严重的问题**：`docs/architecture/protocol-matrix.md` 的编码表整体错乱（§2 ICE 属性、§3 全部 TURN 属性、§4 全部 TURN 错误码），而它自称是 Stage 2/3 实现 issue 的裁剪依据。**这个必须在 YEJ-140 合入前修掉**，否则错误编码会直接进协议栈。

---

## 1. protocol-matrix.md 与 IANA 的偏差（最重要）

`docs/architecture/protocol-matrix.md` 第 9 行自己写着：

> 编码号来源：attribute code 以 IANA "STUN Codes" 注册表为准。实现阶段（YEJ-140）必须用 IANA 注册表交叉核对一次，发现偏差以注册表为准并回填本文档。

本次就是这次交叉核对。结论：**偏差不止「个别」，是三张表整体错位**。

### 1.1 §2 末尾「ICE 相关属性」表 —— 8 个码错 7 个

| 文档写的码 | 文档写的名字 | IANA 实际值（2024-12-20） |
| --- | --- | --- |
| `0x8019` | ICE-CONTROLLING | **Unassigned**。ICE-CONTROLLING = `0x802A` |
| `0x801A` | ICE-CONTROLLED | **Unassigned**。ICE-CONTROLLED = `0x8029` |
| `0x801B` | SOFTWARE | **Unassigned**。SOFTWARE = `0x8022` |
| `0x801C` | ICE-LITE | **Unassigned**（RFC 8445 已删除该属性；文档正文说「仅识别」，但码不对） |
| `0x0024` | ICE-CONTROLLED (legacy) | **Unassigned**。`0x0024` = PRIORITY |
| `0x0025` | ICE-CONTROLLING (legacy) | **Unassigned**。`0x0025` = USE-CANDIDATE |
| `0x0026` | ICE-LITE (legacy) | **Unassigned**。`0x0026` = PADDING |
| `0x0027` | XOR-MAPPED-ADDRESS (legacy) | **Unassigned**。`0x0027` = RESPONSE-PORT |

文档 §2 前半段（§5389/8489 属性）也有同类偏差：`CHANGE-REQUEST`/`CHANGE-IP`/`CHANGE-PORT`/`CHANGE-ADDRESS` 在文档里写成 `0x8003`–`0x8007`，实际分别为 **`0x0003`（IANA 现标 Reserved，pre-5389）** / `0x0004`（Reserved）/ `0x0005`（Reserved）/ `0x0005`（Reserved，was CHANGED-ADDRESS）；`RESPONSE-ADDRESS` `0x8002`→`0x8000`；`SOURCE-ADDRESS` `0x8006`→`0x0007`；`FINGERPRINT` `0x800B`→`0x8028`；`XOR-MAPPED-ADDRESS` `0x800D`→`0x0020`；`ERROR-CODE` `0x8017`→`0x0009`；`UNKNOWN-ATTRIBUTES` `0x8018`→`0x000A`。

### 1.2 §3 TURN Attributes —— 码号整体 +0x000C 错位

RFC 6051/6062 的 TURN 属性是 **低值区间**（`0x000C` 起），文档写成了 `0x8024` 起的 comprehension-optional 区间。逐条：

| 文档写的码 | 名字 | IANA 实际值 |
| --- | --- | --- |
| `0x8024` | XOR-PEER-ADDRESS | `0x0012` |
| `0x8025` | XOR-RELAYED-ADDRESS | `0x0016` |
| `0x8026` | LIFETIME | `0x000D` |
| `0x8027` | RELAYED-ADDRESS | **Reserved** |
| `0x8028` | REQUESTED-ADDRESS-FAMILY | `0x0017` |
| `0x802D` | CHANNEL-NUMBER | `0x000C` |
| `0x802E` | DATA | `0x0013` |
| `0x802F` | USERNAME | `0x0006` |
| `0x8030` | REALM | `0x0014` |
| `0x8031` | NONCE | `0x0015` |
| `0x8032` | ERROR-CODE | `0x0009`（TURN/STUN 共用） |
| `0x8033` | UNKNOWN-ATTRIBUTES | `0x000A`（TURN/STUN 共用） |
| `0x8042` | FIVE-TUPLE-LIMIT | **Unassigned** |
| `0x802A` | CONNECTION-ID | `0x002A`（RFC 6062） |

EVEN- 系列（`EVEN-PEER-ADDRESS` / `EVEN-RELAYED-ADDRESS` / `EVEN-SERVER-CREATE` / `REASON-PHRASE` / `D4-LIMIT`）在 IANA 注册表里**没有任何条目**——RFC 5128 已被 RFC 8656 obsoleted，这些属性没有留下注册码。文档把它们标成 `0x8029`–`0x8034`，这些码分别是 `ICE-CONTROLLING` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `ECN-CHECK STUN` / `THIRD-PARTY-AUTHORIZATION`——**也就是说按文档实现，QuickRelay 会把 ICE-CONTROLLING 当成 EVEN-PEER-ADDRESS 解析**。

### 1.3 §4 TURN 错误码 —— 整表错

文档 §4 列的是 RFC 5128（pre-6051）时代的码，不是 RFC 6051。IANA `STUN Error Codes` 注册表现值：

| Code | IANA 现值 | 文档 §4 写的名字 | 偏差 |
| --- | --- | --- | --- |
| 300 | Try Alternate | — | 缺 |
| 301–399 | Unassigned | — | 文档的 370/371/372/373/384/385 全落在此区间 |
| 400 | Bad Request | Bad Request | ✔ |
| 401 | Unauthenticated | — | 缺 |
| 403 | Forbidden | — | 缺 |
| 420 | Unknown Attribute | — | 缺 |
| 421–436 | Unassigned | — | — |
| 437 | Allocation Mismatch | Allocation Misconfigured | 名字错 |
| 438 | Stale Nonce | Allocation Mismatch | 错 |
| 440 | Address Family not Supported | — | 缺 |
| 441 | Wrong Credentials | Channel Already Exists | 错 |
| 442 | Unsupported Transport Protocol | — | 缺 |
| 443 | Peer Address Family Mismatch | Channel Forbidden | 错 |
| 446 | Connection Already Exists | — | 缺（RFC 6062） |
| 447 | Connection Timeout or Failure | — | 缺（RFC 6062） |
| 486 | Allocation Quota Reached | — | 缺 |
| 487 | Role Conflict | Insufficient Capacity | 错 |
| 500 | Server Error | Server Error | ✔ |
| 508 | Insufficient Capacity | Insufficient Capacity | ✔ |
| — | 401/437 历史不一致 | 文档注脚说「coturn 按 6051 语义」 | 该注脚本身不可核验，建议删除，以 IANA 为准 |

RFC 6051 的 §12 错误码表在 IANA 之外的引用（RFC 5128 §12）用的是 `370–385 / 437–444 / 451 / 508` 这一套旧值，文档 §4 完全照抄了它。RFC 8489 obsoletes RFC 5389 并重新编号了 300/400 以上的大部分码，RFC 8656 进一步 obsoleted RFC 6051。

### 1.4 影响面

`protocol-matrix.md` 是 Stage 2/3 的裁剪依据，YEJ-140（消息编解码，`in_progress`）正在按它实现 attribute code 表。按当前文档实现，QuickRelay 上线后会：

- 把 ICE-CONTROLLED（`0x8029`）当作 UNKNOWN-ATTRIBUTES（`0x8033` 位置）之外的东西解析；
- 把 REALM/NONCE（`0x0014`/`0x0015`）当未知属性上报；
- 用 `487` 回「容量不足」而 ICE 客户端把它当 Role Conflict；
- CHANGE-REQUEST 探测完全失效（`0x8003` 不是 CHANGE-REQUEST 的码）。

这些都是协议级不可兼容，不是「优化」。

---

## 2. issue 验收标准核验

### 2.1 「turnutils_stun --change-addr / --change-port」—— 工具不存在

仓库自己的调研文档已经记了：coturn 当前树里没有 `turnutils_stun`（4.18.0 起改名 `turnutils_stunclient`），且没有 `--test` 自检模式。`turnutils_stunclient` 的能力面只有 `-c`/`-i`/`-t`（连续 RTT 测量），**不做 NAT 行为探测，没有 CHANGE-IP/CHANGE-PORT 探测选项**。

→ 这条验收面在 coturn 上无法执行。要验证 RFC 5780 §6.1 Table 1，唯一可行的是自写探测客户端（Python 或 Rust 直发 Binding Request + `CHANGE-REQUEST`，断言响应源地址/端口 + `RESPONSE-ORIGIN` + `OTHER-ADDRESS`）。

### 2.2 「430 / 390 / 370 三类错误码」—— 三个码全部 Unassigned

IANA `STUN Error Codes`（见 §1.3）：301–399 Unassigned、421–436 Unassigned。

- `430`：当前 Unassigned。RFC 3489 §11.2 里 `430 (Stale Credentials)`，RFC 5389 起废弃。
- `390`：当前 Unassigned。RFC 3489 §11.2 里是 `390 (Role Conflict)`；**Role Conflict 现行码是 `487`**（RFC 8445 §16.2、IANA 引 rfc8445）。
- `370`：当前 Unassigned。`370 (Request In Progress)` 属 RFC 5128 TURN 错误码；RFC 6051 未定义 370，**Request Already in Progress 现行码是 `437`（Allocation Mismatch，RFC 8656 重编号）**。

→ 单元测试断言 430/390/370 会产出协议不兼容应答。应改为断言 **487（Role Conflict）/ 438（Stale Nonce）/ 437（Request Already in Progress）/ 420（Unknown Attribute）/ 400（Bad Request）**，并在 issue 里保留一行「legacy 370/390/430 不产生」的说明。

### 2.3 「ICE-TCP = RFC 6062，framing + 长度前缀」—— 前提写反了

RFC 6062 §2（data connections）原文：

> "Any data received by the TURN server from the client over the client data connection is forwarded to the peer, again without encapsulation or framing of any kind. Once a connection has been bound using the ConnectionBind request, TURN messaging is no longer permitted on the connection."

即 **RFC 6062 的 TURN over TCP 控制连接直接承载裸 STUN 消息，不加任何 framing**；只有 data connection 是纯字节流。

RFC 4571 §2（真正的「长度前缀」shim）：

> "A 16-bit unsigned integer LENGTH field, coded in network byte order (big-endian), begins the frame. … The value coded in the LENGTH field MUST equal the number of octets in the RTP or RTCP packet. Zero is a valid value for LENGTH, and it codes the null packet."

RFC 6544（TCP Candidates with ICE）§3 规定 ICE-over-TCP **MUST** 用这个 4571 shim；RFC 8445 只在「STUN 可跑在 TCP 上 [RFC 6544]」处引用它，本身不定义 STUN framing。

→ 所以有两条互不相同的路径，issue 把名字和性质混了：
1. **TURN over TCP（RFC 6062）**：控制连接 = 裸 STUN，无 framing。QuickRelay 的 TURN 控制面走这条。
2. **ICE over TCP（RFC 6544）**：走 RFC 4571 的 16-bit big-endian LENGTH 前缀，STUN 是其中一个 frame payload。WebRTC 的 ICE-TCP 候选走这条。

RFC 6062 另外定义了 control-connection 上的两个连接管理错误码，协议矩阵 §4 里没有：`446 Connection Already Exists`、`447 Connection Timeout or Failure`。

### 2.4 「ICE-CONTROLLED / ICE-CONTROLLING」—— 可执行，但码要按 §1.1 修

RFC 8445 §7.3.1.1 原文（tiebreaker 比较逻辑）：

- 本端 controlling 且请求含 ICE-CONTROLLING：本端 tiebreaker **≥** 对方 → 回 487，保留角色；< 对方 → 切换为 controlled。
- 本端 controlled 且请求含 ICE-CONTROLLED：本端 tiebreaker **≥** 对方 → 切换为 controlling；< 对方 → 回 487，保留角色。
- controlled 收到 ICE-CONTROLLING（或反之）→ **无冲突**（正常路径）。

`487` 的定义（RFC 8445 §16.2）：Binding request 里带的 ICE 角色与 server 冲突，server 比较 tiebreaker 后判定 client 需要切换角色。

QuickRelay 是中间件不是 ICE agent（不产生自己的 tiebreaker、不参与 nomination），所以语义层只能做**校验 + 透传**：
- 结构校验：ICE-CONTROLLED / ICE-CONTROLLING 内容必须是 **8 字节**（RFC 8445 §15：64-bit unsigned integer，network byte order）。长度不对 → `400 Bad Request`。
- 互斥校验：同一消息里同时出现两者 → `400`。
- 校验通过后**原样透传**到响应（或按 RFC 5389 语义忽略），不产生 487（487 需要 server 自己有 ICE role，QuickRelay 没有）。

这条与 140/141 依赖无关，是**唯一可以立即独立开工**的部分。

### 2.5 「CHANGE-IP / CHANGE-PORT / CHANGE-ADDRESS」—— 只有两个位

RFC 5780 §7.2 原文位布局（A/B 是仅有的两位，最低位保留）：

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
A = change IP   B = change port
```

A = `0x40`，B = `0x02`。**不存在 CHANGE-ADDRESS 位**：`CHANGE-ADDRESS`（`0x0005`，曾叫 CHANGED-ADDRESS）是 RFC 3489 的独立属性，RFC 8489 起 IANA 标 Reserved（RFC 5780 把它改名为 `OTHER-ADDRESS`，码 `0x802C`）。issue 把三个「位语义」并列，提法不成立。

RFC 5780 §6.1 Table 1（源地址/端口选择）：

| Flags | Source Address | Source Port | OTHER-ADDRESS |
| --- | --- | --- | --- |
| none | Da | Dp | Ca:Cp |
| Change IP | Ca | Dp | Ca:Cp |
| Change port | Da | Cp | Ca:Cp |
| Change IP and Change port | Ca | Cp | Ca:Cp |

同一节的其它硬约束：

> "If the Request contains the CHANGE-REQUEST attribute and the server does not have an alternate address and port as described above, the server MUST generate an error response of type 420."

> "The server MUST include both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS in its Response."

> "If the Request contained a PADDING attribute … If the Request also contains the RESPONSE-PORT attribute the server MUST return an error response of type 400."

> "An ALTERNATE-SERVER attribute MUST NOT be included with any other attribute defined in this specification."

另外 §6 的前提条件值得单独摘出来，因为它直接决定 QuickRelay 的能力边界：

> "If a server cannot allocate the same ports on two different IP address, then it MUST NOT include an OTHER-ADDRESS attribute in any Response and MUST respond with a 420 (Unknown Attribute) to any Request with a CHANGE-REQUEST attribute."

→ **`SO_REUSEADDR` 不能给 CHANGE-IP 提供第二组地址**：CHANGE-IP 要求两个不同的 IP 各绑定同一组端口。双 `--listening-ip` 配置才有能力，单地址部署必须无条件回 420。这个能力归 Stage 4 的多监听配置，不该塞进 142。

---

## 3. 本 turn 未产代码，原因

- YEJ-140（消息编解码）`in_progress`，未交付 attribute codec API 与 `ERROR-CODE` 承载结构。142 的语义层输入是解析后的 attribute，输出是响应 attribute 计划——两头都挂在 140 的类型上，先写就是自造接口。
- YEJ-141（UDP/TCP 传输）未启动。验收标准第 2 条「ICE-TCP Binding loopback 集成测试」需要真实 listener。
- 架构文档 §10.2 把 142 放在 G3（依赖 G2 = 141），排期本身是对的。
- 额外因素：protocol-matrix 的码表错误（§1）意味着即使 140 接口就绪，实现目标值也是错的。

## 4. 需要需求方 / 架构师拍板

1. **要不要现在修 `protocol-matrix.md`？** 这是唯一会阻断整个 Stage 2/3 的问题，但它属于架构文档（Stage 1 已完成，`done`），不在 Codex-02 的岗位边界内（不接文档编写/架构跨岗工作）。建议：拆一个 Stage 1 回填子任务，按本附件 §1 的三张表整表替换，并同步给 YEJ-140。
2. **错误码口径**：确认改用现行码 487/438/437/420/400/401/508（本附件 §1.3），430/390/370 降级为「legacy 不产生」注释。
3. **ICE-TCP 范围**：确认 142 走 RFC 6544 / RFC 4571（16-bit big-endian LENGTH，WebRTC 实际路径），而不是 RFC 6062（TURN over TCP，裸 STUN，无 framing）。RFC 6062 的 446/447 是否要进协议矩阵也一并定。
4. **CHANGE-REQUEST 双地址能力**：属 142 交付还是 Stage 4 多监听配置？按 §6 前提，单地址部署下 142 只能无条件回 420，功能价值很薄，建议放 Stage 4。
5. **验收手段**：`turnutils_stun` 不存在，是否接受自写探测客户端（Python，约 80 行）作为 CHANGE-IP/CHANGE-PORT 的可复现验收载体？

## 5. 可立即开工（零依赖）

1. ICE-CONTROLLED / ICE-CONTROLLING 结构校验（8 字节 tiebreaker）+ 互斥校验 + 原样透传，用 `0x8029` / `0x802A`（不是文档 §2 写的 `0x801A` / `0x8019`）。
2. CHANGE-REQUEST 位解析（`0x40` / `0x02`，忽略其余位）+ §6.1 Table 1 源地址选择纯函数 + 420 兜底，用「服务端持有的监听槽位集合」做 stub，不需要 socket。
3. protocol-matrix §1 的整表修正（需授权）。
