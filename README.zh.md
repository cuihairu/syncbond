[English](README.md) | [中文](README.zh.md)

<p align="center"><img src="assets/icon.svg" width="64" height="64" alt="SyncBond logo"></p>

[![Status](https://img.shields.io/badge/status-in%20development-orange)](https://github.com/cuihairu/syncbond/releases)
[![CI](https://github.com/cuihairu/syncbond/actions/workflows/ci.yml/badge.svg)](https://github.com/cuihairu/syncbond/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **syncbond 是临时开发名，最终品牌待定。**

# syncbond

无账号、可嵌入、端到端加密的设备配对与数据同步基础设施 SDK，Rust 核心 + TypeScript 绑定。

SDK 不理解、不解释、不决定业务数据的含义：载荷是不透明字节，合并行为是可插拔策略。核心里没有词库、笔记、密码等任何应用概念——数据模型和合并策略由应用自带。

密码学组件全部来自维护中的审计库——RustCrypto `p256`、`sha2`/`hkdf`/`hmac`/`scrypt`、`chacha20poly1305`、`ed25519-dalek`——配对协议严格按 RFC 9382 组装，并用其全部四组官方测试向量验证。本仓库不自行实现任何密码学原语。

## 提供什么

- **配对** — 两台设备各显示一个短码，经 SPAKE2（RFC 9382，`SPAKE2-P256-SHA256-HKDF-HMAC`）派生共享密钥；双向密钥确认、绑定转录的 Ed25519 身份交换、每帧携带协议版本字节，码策略为单次使用 + TTL + 限次。
- **身份与组** — 每设备长期 Ed25519 密钥；确定性组 id；通过组密钥纪元（keyEpoch）实现设备撤销。
- **加密** — XChaCha20-Poly1305 信封，除密文外全部字段进入 AEAD 关联数据；篡改、重放、跨组投递、错误纪元一律拒绝。`keyEpoch` 从 v1 即存在。Schema：[`schemas/envelope.schema.json`](schemas/envelope.schema.json)。
- **复制** — oplog + 游标 + 去重；乱序与重复投递收敛到同一状态。
- **冲突** — 可插拔 `MergeStrategy`；内置（HLC-LWW + 因果墓碑、OR-Set、PN-Counter）只是可选便利，不强加。见 [`docs/design/merge.md`](docs/design/merge.md)。
- **存储** — 可替换持久化 trait；身份、游标、oplog 必须在崩溃重启后保持一致（发布阻断测试）。
- **传输** — 现有内存回环实现；WebSocket / LAN / P2P 预留接口。

## 当前状态

Rust 核心已实现，35 个测试全绿，含 RFC 9382 附录 B 全部四组向量，以及跑在同一核心上的三个互不相关的示例应用（通用 KV、笔记文档、任意二进制记录）。TypeScript 绑定目前是类型骨架；napi-rs 实现尚未开始。

进度与待拍板项：[`todo.md`](todo.md)。协议契约：[`docs/design/PROTOCOL.md`](docs/design/PROTOCOL.md)。合并设计：[`docs/design/merge.md`](docs/design/merge.md)。语言决策：[`docs/design/language.md`](docs/design/language.md)。需求基线：[`docs/zh/requirements.md`](docs/zh/requirements.md)。现状调研：[`docs/zh/research/survey-2026-10-21.md`](docs/zh/research/survey-2026-10-21.md)。

## 目录

```
crates/syncbond-core/   Rust 核心（pairing、crypto、replication、conflict、storage、transport）
packages/ts-bindings/   TypeScript 绑定骨架（类型化 API，napi-rs 实现待做）
schemas/                线上格式（信封）
docs/design/            协议、合并、语言决策文档
```

## 开发

需要 Rust 工具链（1.85+ / edition 2021）与 Node 24 + pnpm。

```sh
cargo test                 # 核心测试套件
cargo clippy --all-targets # lint
pnpm install && pnpm -r typecheck   # 绑定骨架类型检查
```

## 许可

[MIT](LICENSE)
