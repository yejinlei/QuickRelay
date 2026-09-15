# QuickRelay

基于 Rust 的超高性能 STUN/TURN 服务器，对标 [coturn](https://github.com/coturn/coturn)，主要面向 WebRTC 场景。

需求总览见 Multica issue [YEJ-128](https://api.multica.ai)。

## 需求要点

1. 实现类似 coturn 的超高性能 STUN/TURN 服务器
2. 主要支持 WebRTC
3. 使用 stun-rs / turn-rs 等 Rust 库
4. 参考 coturn 实现，通过所有 coturn 用例（如果有的话）
5. 超高性能

## 当前状态

仓库已初始化，具体 issue 拆解与实现计划由 Multica 看板管理。技术选型（自研 vs `turn` 库）在 Stage 1 架构设计中定稿。

## 技术选型（待 Stage 1 定稿）

- 语言：Rust
- 协议：STUN RFC 5389 / 8489、TURN RFC 6051、ICE-TCP
- 性能对标：coturn 官方 benchmark 数据

## 许可证

待定。注意 coturn 为 GPL-2.0，若复用其代码或测试脚本需先明确 licensing。
