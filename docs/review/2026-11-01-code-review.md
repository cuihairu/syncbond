# 代码深审报告（syncbond，2026-11-01）

> 范围：全量（`/home/cui/workspaces/syncbond`）。方法：安全静态扫描（硬编码密钥 / shell 注入 / SQL 拼接 / eval / 反序列化 / 路径穿越）+ 隐藏 bug 猎捕（错误处理 / 竞态 / 越界 / 资源泄漏 / off-by-one / 并发）+ 质量门（lint / 类型检查 / 测试基线）。严重度按 P0–P3：P0/P1 当场修（一问题一 commit，测试绿），P2/P3 记 `todo.md` 第九节。
> 依据：`security-audit` 技能严重度口径（CRITICAL/HIGH→P0/P1，MEDIUM/LOW→P2/P3）与用户六步流程。本报告属仓库内部文档，不置于公开站点（与 `docs/审计-文档一致性.md` 同理）。

---

## 一、范围与盘点

| 面 | 位置 | 规模 |
|---|---|---|
| 核心 | `crates/syncbond-core/src/` | 14 文件（crypto/pairing/spake2/replication/conflict/hlc/relay/discovery/identity/storage/transport/codes/member_crypto/lib） |
| FFI | `crates/syncbond-ffi/src/` | 5 文件（abi/handles/error/scenario/lib） |
| 绑定 | `syncbond-napi`、`syncbond-python`、`syncbond-wasm` | 各 1–2 文件 |
| 语言绑定 | C/C++（examples+header）、Go、Java、C#、Python、TS/JS | 七语言源码 + 头文件 |

**审查路径**：全仓静态扫描六类模式 → 逐文件深读（核心与 FFI 全读，绑定层全读）→ 质量门实测。

## 二、质量门（实测）

| 门 | 结果 |
|---|---|
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 warning |
| `cargo fmt --all -- --check` | 干净 |
| `cargo test --workspace` | **76 passed / 0 failed**（基线 75，新增 1 测试） |
| TS：`packages/ts-bindings` test | 9 passed / 0 failed |
| Go：`go test ./...` | ok |
| docs：`pnpm docs:build` | 绿（14 HTML） |
| docs：`node scripts/verify-docs-links.mjs` | 绿（14 文件） |

## 三、发现（按严重度排序）

### P0（1 条，已修）

**CR-001 — README/todo 称「durable WebSocket relay / 断线重连」，源码无任何 WebSocket 实现（文档超前于码，A 桶）**

- **页/行**：`README.md:36`、`README.zh.md:36`、`todo.md:27`
- **主张**：「an in-memory loopback plus a durable **WebSocket relay** with resumable oplog cursors」；todo「WebSocket 持久中继：断线重连 + 游标续传」。
- **源码证据（否定性先验路径）**：全仓 `grep -rniE 'websocket|tungstenite|ws://|wss://'`（排除 node_modules/target/dist）仅命中注释——`transport.rs:3`「WebSocket/LAN/P2P transports are **planned**」；`discovery.rs:5-6`「Core paths never create network I/O; applications inject discovery providers and transport factories」；`syncbond-wasm/src/lib.rs:9-11`「WebSocket … are the application's job」。任何 Cargo.toml 无 `tungstenite`/ws 依赖。`relay.rs:89-95` 是**持久化存储**（Memory/File + `pull_after` 游标），非中继服务器。提交 `27c139d`「add durable resumable relay」仅新增 `relay.rs` 存储 + 测试；测试 `relay_persistence_tests.rs:18` 名为「resumes across **server restart**」（持久化恢复），非断线重连。
- **桶**：A（文档超前于码，最危险）
- **修法**：改为「durable, resumable relay store (file-backed); transports are application-provided behind the `Transport` trait (no WebSocket in the core)」；todo 改为「持久化可续传中继存储：跨重启恢复 + 游标续传」。
- **状态**：已修（commit `84f9162`）。

### P1（1 条，已修）

**CR-002 — SPAKE2 未按 RFC 9382 §3.2 检查共享点 K 是否为无穷远点**

- **位置**：`pairing_spake2.rs:270`（`process_response`，K = (pB − w·N)·x）、`:343`（`process_intro`，K = (pA − w·M)·y）
- **描述**：RFC 9382 §3.2 要求「If K is the identity element, abort」；实现直接编码 K 进入 transcript，未检查 `K == IDENTITY`。持有 w（码派生标量）的对端可构造 `pB = w·N`（或 `pA = w·M`）令 K 坍缩到无穷远点，从而导出攻击者已知的密钥材料。
- **可利用性评估**：构造 K=identity 需先知道 w = derive_w(码)。配对码 6 字符 ≈ 27.3 bits 熵、单次使用 + TTL + 3 次限次——**持码者本就可配对**，故不构成超越码本身的机密性突破；且错误码猜测（w'≠w）时 K=y·((w'−w)·N) 为有效随机点，确认必然失败，不放大猜码空间。属协议规范偏差 + 潜在正确性缺陷，非活跃漏洞。
- **修法**：两处 `if k == ProjectivePoint::IDENTITY { return Err(Spake2Error::IdentitySharedSecret) }`；新增变体 + 测试 `identity_shared_secret_is_rejected`（构造 pB=w·N / pA=w·M 断言拒绝）。
- **状态**：已修（commit `47539b3`；`cargo test` 76/0）。

### P2（3 条，已修 1 条注释、其余记 todo）

**CR-003 — 时间阈值墓碑 GC 经公开 `conformance_run` 可达，与「不开放给应用」决策矛盾**

- **位置**：`scenario.rs:148-150`（fixture `gc` 步骤 `mode:"time_only"` → `gc_tombstones_time_only`）；`replication.rs:43-47` 原注释「never reachable from the public API or the FFI surface」。
- **描述**：`conformance_run(fixture_json)` 是公开 API（C ABI `sb_conformance_run`、python、wasm、napi 均暴露）；fixture 的 `gc` 步骤可带 `mode:"time_only"`，故降级（可复活）GC 路径经公开面可达，与 2026-10-28 决策「墓碑仅时间阈值裁剪——不开放给应用，保留内部/测试专用」口径相抵。
- **影响**：降级模式的复活风险局限于 fixture 自身的内存副本（`conformance_run` 只驱动其创建的节点），不触及应用真实存储，实际风险低。
- **修法**：注释已更正（`a7f9966`，改述「C ABI 与绑定仅暴露 dominance；time_only 仅经 conformance fixture runner 到达」）。**拍板点（是否对应用收紧）记 todo**。
- **状态**：注释已修；行为决策记 `todo.md` 第九节 P2。

**CR-004 — `HybridClock::receive()` 死公开 API，`remote.ct = u64::MAX` 时 `+1` 溢出**

- **位置**：`hlc.rs:96-121`（`self.ct.max(remote.ct) + 1`，`receive` 全仓零调用者——`grep .receive(` 仅命中定义）
- **描述**：公开方法但内部不可达；构造恶意 stamp（pt≈now、ct=u64::MAX）触发 debug panic / release 静默回绕。merge 路径的 skew 防护实际由 `LwwHlc::merge`（`conflict.rs:177`，`saturating_sub`）独立实现，`receive` 冗余。
- **修法**：saturating 加法或删除该方法。记 todo。

**CR-005 — 会话/中继接收无帧大小上限，认证对端可致 OOM**

- **位置**：`pairing.rs:94-103`（`recv_and_open` → `serde_json::from_slice` 无上限）；`replication.rs:532-543`（`sync_over` decode 无上限）
- **描述**：解码前不设长度上限；恶意的组成员可发巨帧驱动无界分配（OOM DoS）。当前无真实网络传输（仅内存回环 + 应用注入 transport），暴露面为应用自有传输。
- **修法**：解码前按上限校验帧长/oplog 长。记 todo（硬化项）。

### P3（6 条，全部记 todo）

**CR-006** — `crypto.rs:145-147`：`open` 在 AEAD 校验**前**插入 `message_id`；损坏帧被拒后其 id 永久烧掉，同 id 合法重传被判重放。id 每次 seal 随机生成，实际影响极小。
**CR-007** — `codes.rs:58`：`generate_code` 用 `*b % 30`（256 % 30 ≠ 0），前 16 符号概率略高（模偏差），熵 27.3→约 27.2 bits。
**CR-008** — `codes.rs:101-110` vs `114-131`：`validate_format` 经 `to_ascii_uppercase` 收小写，但 `consume`/`register_failure` 按原文查 `issued`（键为大写）——小写码校验通过却必报 `Unknown`，口径不一致。
**CR-009** — `syncbond-napi/src/lib.rs:57`：`cstr()` 用 `CString::new(value).unwrap_or_default()`，内嵌 NUL 的字符串静默变空串，报「key must not be empty」误导；应显式报错。
**CR-010** — `replication.rs:553-570`：`sync_over` 的 `SyncStats.received_ops`/`applied_ops` 恒为 0（`:588-590` 注释已承认「callers should read convergence from the store」）；字段语义误导。
**CR-011** — `identity.rs:20-27` + `storage.rs:48-59`：长期 Ed25519 私钥随 `SyncState.identity` 明文序列化落盘。设计如此（应用自有存储），但无风险标注/可选加密。

## 四、未发现问题的面（正向结论）

- **FFI 边界安全**：`abi.rs:30` `call()` 用 `catch_unwind` 兜住 panic 返回 fallback + 记录错误，panic 永不 unwind 进 C；句柄 `Box::into_raw`/`drop(Box::from_raw)` 单所有权 + null 检查；`sb_free_buffer` 的 `Vec::from_raw_parts(data, len, cap)` 与 `into_buffer`（`abi.rs:96-106`，`ManuallyDrop` + 真实 `capacity()`）精确匹配，无 UB。
- **无注入面**：shell/exec 全部命中均为 `std::thread::spawn`（合法并发），无 `Command`/`system`/`popen`/`eval`/SQL（全仓零 SQL）；无硬编码密钥（所有 secret/key 命中均为加密变量名或 RFC 测试向量）；`identity.rs`/`crypto.rs`/`member_crypto.rs` 的 hex 解析均强制长度（`try_into`），无路径穿越（仅 `relay.rs` 用文件系统，路径由应用提供，原子写 temp+rename）。
- **错误处理**：锁毒化全部映射为错误或 `into_inner` 恢复；`page_after`/`op_json` 有边界守卫；`expect` 均在不变式保证下（如 `pairing.rs:196` 由 `payload.len() < 65` 守卫保证 64 字节切片、HKDF 32 字节长度合法）。
- **并发**：会话重放 `seen_message_ids` 为 `Mutex`、失效标志 `AtomicBool`、transport 锁/条件变量配对正确（`transport.rs:33-38` 注释明示 Condvar 与 mutex 一一对应）；python `sync_pair` GIL 处理（`py.detach` + worker 线程 join 捕获 panic）正确。
- **密钥管理**：`KeyRing` 单调 epoch、`rotate` 拒绝重放、成员轮换 `verify_rotation` 全链校验（版本/组/重放/来源/epoch/ed25519 签名/MAC），`constant_eq`（`member_crypto.rs:434`）常数时间比较。
- **畸形载荷**：`MergeStrategy::merge` 可失败化，OR-Set/PN-Counter 畸形载荷七语言一致显式报错不 panic（已在前次 `e75cb2e` 处理）。
- **协议版本**：版本不匹配一律硬失败（按已记录决策），无静默降级。

## 五、处置汇总

| 项 | 值 |
|---|---|
| 发现总数 | **11**（P0×1，P1×1，P2×3，P3×6） |
| 当场修复 | **3**（CR-001 文档修正、CR-002 SPAKE2、CR-003 注释更正） |
| 记 todo | **9**（CR-003 行为拍板 + CR-004、CR-005 + CR-006…CR-011） |
| 提交 | `84f9162`（docs: correct websocket relay claim in readme and todo）；`47539b3`（fix: reject identity shared secret in spake2 per rfc 9382）；`a7f9966`（docs: correct time-only gc reachability comment） |
| 门禁 | `cargo test` 76/0；clippy `-D warnings` 0；fmt 干净；TS 9/0；go ok；docs build + 链路校验绿 |

## 六、与文档审计的关系

本报告 CR-001 是 `docs/审计-文档一致性.md` D-03 的**回归**：上轮审计将「WebSocket/LAN/P2P 接口预留」过度修正为「WebSocket 中继已实现」，而核心只有持久化可续传中继存储。已在该审计文件「六、后续更正」记录，并把 D-03 重新划入 A 桶后修复。教训：否定性结论须先验证搜索树（本报告对 WebSocket 全仓 grep 确认无实现后才下结论），且「有同名模块 ≠ 实现了声称的能力」。
