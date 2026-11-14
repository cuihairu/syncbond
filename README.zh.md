[English](README.md) | [中文](README.zh.md)

<p align="center"><img src="assets/icon.svg" width="64" height="64" alt="SyncBond logo"></p>

<p align="center"><a href="https://cuihairu.github.io/syncbond/zh/"><img src="https://img.shields.io/badge/%E6%96%87%E6%A1%A3-blue" alt="docs"></a> <a href="https://github.com/cuihairu/syncbond/releases"><img src="https://img.shields.io/badge/status-in%20development-orange" alt="Status"></a> <a href="https://github.com/cuihairu/syncbond/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/syncbond/actions/workflows/ci.yml/badge.svg" alt="CI"></a> <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a> <a href="crates/syncbond-core"><img src="https://img.shields.io/badge/内核-Rust-000000?logo=rust&logoColor=white" alt="Rust 内核"></a> <a href="packages/ts-bindings"><img src="https://img.shields.io/badge/绑定-TypeScript-3178C6?logo=typescript&logoColor=white" alt="TypeScript 绑定"></a> <a href="docs/zh/design/PROTOCOL.md"><img src="https://img.shields.io/badge/配对-SPAKE2%20RFC9382-2c6e63" alt="配对: SPAKE2 RFC9382"></a></p>


> **syncbond 为正式产品名**（2026-11-05 拍板；crates.io 上 `syncbond` / `-core` / `-ffi` / `-python` / `-wasm` / `-napi` 六个名字在最近一次查询时均未占用，但 crates.io 按先到先得分配，该查询不保证这些名字仍可用）。

# syncbond

无账号、可嵌入、端到端加密的设备配对与数据同步基础设施 SDK，Rust 核心 + C/C++/Python/Go/Java/C#/TypeScript/浏览器 WASM 绑定，全部走同一条 C ABI。

SDK 不理解、不解释、不决定业务数据的含义：载荷是不透明字节，合并行为是可插拔策略。核心里没有词库、笔记、密码等任何应用概念——数据模型和合并策略由应用自带。

密码学组件全部来自维护中的审计库——RustCrypto `p256`、`sha2`/`hkdf`/`hmac`/`scrypt`、`chacha20poly1305`、`ed25519-dalek`——配对协议严格按 RFC 9382 组装，并用其全部四组官方测试向量验证。本仓库不自行实现任何密码学原语。

## 提供什么

- **配对** — 两台设备各显示一个短码，经 SPAKE2（RFC 9382，`SPAKE2-P256-SHA256-HKDF-HMAC`）派生共享密钥；双向密钥确认、绑定转录的 Ed25519 身份交换、每帧携带协议版本字节，码策略为单次使用 + TTL + 限次。
- **身份与组** — 每设备长期 Ed25519 密钥；确定性组 id；通过组密钥纪元（keyEpoch）实现设备撤销。
- **加密** — XChaCha20-Poly1305 信封，除密文外全部字段进入 AEAD 关联数据；篡改、重放、跨组投递、错误纪元一律拒绝。`keyEpoch` 从 v1 即存在。Schema：[`schemas/envelope.schema.json`](schemas/envelope.schema.json)。
- **复制** — oplog + 游标 + 去重；乱序与重复投递收敛到同一状态。
- **冲突** — 可插拔 `MergeStrategy`；内置（HLC-LWW + 因果墓碑、OR-Set、PN-Counter）只是可选便利，不强加。见 [`docs/zh/design/merge.md`](docs/zh/design/merge.md)。
- **存储** — 可替换持久化 trait；身份、游标、oplog 必须在崩溃重启后保持一致（发布阻断测试）。
- **传输** — 内存回环 + 可持久化、可续传的中继存储（文件落盘，oplog 游标断点续传）；传输本身由应用经 `Transport` trait 注入（核心不含 WebSocket 实现）。LAN（mDNS）发现在默认关闭的 `lan` feature 后。P2P 已完成评估，见调研文档。

## 当前状态

Rust 核心已实现，由 workspace 测试套件覆盖（当前 75+ 测试），含 RFC 9382 附录 B 全部四组向量，以及跑在同一核心上的三个互不相关的示例应用（通用 KV、笔记文档、任意二进制记录）。C/C++/Python/Go/Java/C#/TypeScript(napi)/浏览器 WASM 绑定全部逐字节跑同一条跨语言 conformance fixture。

进度与待拍板项：[`todo.md`](todo.md)。协议契约：[`docs/zh/design/PROTOCOL.md`](docs/zh/design/PROTOCOL.md)。合并设计：[`docs/zh/design/merge.md`](docs/zh/design/merge.md)。语言决策：[`docs/zh/design/language.md`](docs/zh/design/language.md)。需求基线：[`docs/zh/requirements.md`](docs/zh/requirements.md)。现状调研：[`docs/zh/research/survey-2026-10-21.md`](docs/zh/research/survey-2026-10-21.md)。

## 默认服务器规划

目前没有可直接部署的默认服务器；`FileRelayStore` 是保存明文 `Operation` 的存储原型。计划在 `apps/syncbond-server/` 实现可选自托管的密文中继，在 `crates/syncbond-transport-ws/` 实现客户端网络接入，并以 `crates/syncbond-relay-protocol/` 共享传输契约。目录与部署文件尚未实现。

职责、信任边界与验收标准见 [默认中继服务器设计](docs/zh/design/default-server.md)；原子任务及依赖见 [todo.md](todo.md#默认服务器实施计划2026-11-14全部待实现)。复制恢复与收敛修复是交付前置阻断项；现有中继存储测试或多语言 conformance 通过不代表真实跨设备同步已完成。

## 每日构建

`main` 有滚动 nightly 预发布（定时触发时要求 48 小时内有新提交，也可手动触发），且仅在 fmt + clippy + 完整 workspace 测试套通过后出包。nightly 只是构建产物分发，**不是稳定版**：版本号正式发布与 npm/crates.io 上架仅由维护者手动执行。

从 [nightly release](https://github.com/cuihairu/syncbond/releases/tag/nightly) 下载，再用 `SHA256SUMS` 校验：

```sh
sha256sum -c --ignore-missing SHA256SUMS   # 先下载所需资产
```

- **C / C++** — `syncbond-nightly-<target>.tar.gz`（Linux x86_64 / aarch64，musl 静态）：`include/syncbond.h` + `libsyncbond_ffi.a`；链接静态库并包含头文件。
- **Python** — `syncbond-*.whl`（Linux x86_64 / aarch64）：`pip install <对应 .whl 文件>`。
- **Node.js** — `syncbond-nightly-napi-<arch>.tar.gz`（Linux glibc）：解包后 import 内含的 `binding.js`（自动加载同目录预编译 `index.<platform>.node`）。
- **浏览器 WASM** — `syncbond-nightly-wasm.tar.gz`：`syncbond_wasm.js` + `syncbond_wasm_bg.wasm`（wasm-pack `web` target）。

每个压缩包内的 `BUILD_INFO` 记录确切源提交。

## 目录

```
crates/syncbond-core/   Rust 核心（pairing、crypto、replication、conflict、storage、transport）
crates/syncbond-ffi/    C ABI（cdylib + 头文件）+ C++/Go/Java/C# 绑定与 conformance fixture
crates/syncbond-napi/   Node.js TypeScript 绑定（napi-rs over C ABI）
crates/syncbond-wasm/   浏览器 WASM 绑定（wasm-bindgen over 核心）
crates/syncbond-python/ Python 绑定（PyO3 over C ABI）
packages/ts-bindings/   TypeScript 绑定包（napi + WASM 包装）
schemas/                线上格式（信封）
docs/design/            协议、合并、语言决策文档
```

## 开发

需要 stable Rust 工具链（edition 2021；未钉 MSRV）与 Node 24 + pnpm。

```sh
cargo test                 # 核心测试套件
cargo clippy --all-targets # lint
pnpm install && pnpm -r typecheck   # 绑定骨架类型检查
```

## 许可

[MIT](LICENSE)
