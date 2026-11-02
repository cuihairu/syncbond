# todo

来源：用户 2026-10-21 立项令及同日两次修正。定位：accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure SDK。核心原则：SDK 不理解、不解释、不决定业务数据含义。需求基线：`docs/requirements.md`（R1.1–R11.4）。

优先级：协议安全与收敛正确性 → 可嵌入 API → WebSocket 中继 → LAN 发现 → P2P/Iroh → 平台集成。

## P1 — 协议安全与收敛正确性（完成）

- [x] R1.1–R1.3, R1.5 SPAKE2 配对，RFC 9382 四组官方向量全过（证据：commit 3cc3859；tests 5）
- [x] R1.3 配对码策略：单次使用 + TTL + 限次 + 格式校验（证据：commit 3cc3859；tests 3）
- [x] R1.4 双向密钥确认 + 错码双侧拒绝 + abort 防死锁（证据：commit 3cc3859；tests 1）
- [x] R1.6–R1.7, R2.1–R2.3 长期设备公钥交换、签名绑定转录、确定性 groupId（证据：commit 3cc3859；tests 1）
- [x] R1.5, R9.1–R9.2 每帧版本字节，不兼容消息拒绝（证据：commit 3cc3859；tests 2）
- [x] R3.1–R3.5, R8.1, R8.3 信封 9 字段 + 除密文外全 AAD + keyEpoch 自 v1（证据：commit 3cc3859；tests 9）
- [x] R2.4, R3.3–R3.4 撤销 = keyEpoch 轮换，旧纪元解不开新信封（证据：commit 3cc3859；tests 1）
- [x] R2.5 会话失效与重放保护（证据：commit 3cc3859；tests 2）
- [x] R5.1–R5.4 可插拔合并策略 + LWW(HLC)/OR-Set/PN-Counter 内置（证据：commit 3cc3859；tests 7）
- [x] R5.5 大幅时钟偏移不无声覆盖（证据：commit 3cc3859；tests 1）
- [x] R4.1–R4.4 乱序 + 重复投递终态一致（证据：commit 3cc3859；tests 1）
- [x] R6.1–R6.3 崩溃重启后身份/游标/oplog 一致（证据：commit 3cc3859；tests 1）
- [x] R10.3 通用性验收：三个互不相关示例进仓进测试（证据：commit 3cc3859；tests 3）
- [x] R10.2 语言决策落档：Rust core + TS binding（证据：`docs/design/language.md`）
- [x] 首推单 commit 门禁全绿（证据：commit 3cc3859；tests 35）

## P2 — 传播与集成

- [x] 持久化可续传中继存储：跨重启恢复 + 游标续传，两端经中继收敛（证据：commit 27c139d；tests 37）
- [x] napi-rs TypeScript 绑定：TS 侧 pair/sync 全流程（证据：commit d946274；cargo tests 37；TS tests 4）
- [x] 成员移除触发 keyEpoch 轮换 + 新钥分发，被移除设备解不开任何轮换后信封（证据：commit 9839ccc；tests 8）
- [x] 墓碑 GC：时间阈值 + 因果支配，GC 后旧写入不复活删除（证据：commit 3fdc056；tests 8）
- [x] 跨版本协商——不支持，维持精确版本匹配硬失败（证据：已代决 2026-10-28，见 docs/review/2026-10-30-decisions.md）
- [x] LAN 发现（mDNS）：feature 门控默认 off，mock 可测（证据：commit 91471b3；tests 4）
- [x] P2P/Iroh 传输评估：打洞成功率与中继回退路径（证据：commit a202763；docs/research/p2p-iroh-assessment-2026-10-28.md）
- [x] 墓碑仅时间阈值裁剪——不开放给应用，保留内部/测试专用（证据：已代决 2026-10-28，见 docs/review/2026-10-30-decisions.md）

## P3 — 发布（阻断项未清不动）

- [ ] 最终品牌名——BLOCKED：用户输入（候选由用户核验；crates.io 五个包名已实测未占用；定名后开启改名工作线）
- [ ] npm 发布——BLOCKED：用户输入（维持不发布稳定包；`npm whoami` ENEEDAUTH，`@cuihairu` scope 待用户登录确认；发布令+版本号只能由用户给）

## 待拍板项（用户决策）

1. npm 发布策略——已代决：维持不发布，待用户输入（2026-10-30）
2. 最终品牌名——已代决：待用户定名（2026-10-30）
3. 跨版本协商——已代决：不支持/不开放（2026-10-28）
4. 墓碑降级 GC——已代决：不开放，内部/测试专用（2026-10-28）
5. 自动轮换触发——已代决：维持应用显式 `rotate_for_removal`，不改核心自动（2026-10-30，docs/review/2026-10-30-decisions.md）

## 七、多语言 SDK（R10.3）

架构：`syncbond-core` → `syncbond-ffi`（C ABI）→ 各语言 binding。binding 只做序列化与资源管理，不得含协议逻辑。

- [x] R10.3.1 C ABI（cdylib + 头文件），纯 C 跑通 pair/sync（证据：commit 4776e5e；tests 48）
- [x] R10.3.2 C++ SDK（RAII 包装，零告警）（证据：commit ff157b8；tests 2）
- [x] R10.3.3 Python SDK（PyO3，pip 可装，三平台 wheel）（证据：commit 36fb405；tests 51）
- [x] R10.3.4 Go SDK（cgo，CGO_ENABLED=0 显式报错）（证据：commit 82be1fa；go tests 8）
- [x] R10.3.5 Java SDK（JNI + Cleaner，Gradle 可拉）（证据：commit 5a45cbf；JUnit tests 13）
- [x] R10.3.6 C# SDK（P/Invoke + IDisposable，NuGet 可拉）（证据：commit a5a5a83；xUnit tests 13）
- [x] R10.3.7 TS/JS：napi 消费 C ABI + 浏览器 WASM（无 IndexedDB 显式降级）（证据：commit adc454a；tests 70）
- [x] R10.3.8 跨语言一致性：同一 fixture 七语言字节一致（证据：commit 1601b2c；含 `crates/syncbond-ffi/fixtures/conformance.json`）

## 八、binding 层畸形载荷显式报错

- [x] `MergeStrategy::merge` 可失败化，畸形 OR-Set/PN-Counter 载荷七语言一致显式报错不 panic（证据：commit e75cb2e；cargo tests 75；TS tests 9；conformance 新增 2 场景）

## 九、代码深审遗留（2026-11-01，P2/P3）

审计报告：`docs/review/2026-11-01-code-review.md`（11 条发现，当场修复 3 条）。

P2：

- [ ] 会话/中继接收路径加帧大小上限，防认证对端巨帧 OOM（`pairing.rs` `recv_and_open`、`replication.rs` `sync_over` decode 无上限）
- [ ] `HybridClock::receive` 死代码处置：`ct` 加法改 saturating 或删除该公开方法（`hlc.rs:96`，`remote.ct = u64::MAX` 时溢出）
- [ ] 拍板：conformance fixture 的 `time_only` GC 模式是否对应用收紧（现经公开 `conformance_run` 可达，2026-10-28 决策口径为内部/测试专用）
- [ ] `max_stamp` 比较反转：a>b 时返回较小戳，合并记录携带较早时间戳（`conflict.rs:88`，交换分支 + 加钉子测试）

P3：

- [ ] `crypto::open` AEAD 失败时不记录 `message_id`，避免损坏帧永久烧掉同 id 重传（`crypto.rs:145`）
- [ ] `generate_code` 消除模偏差（`codes.rs:58`，256 % 30 ≠ 0，前 16 符号概率偏高）
- [ ] 配对码小写不一致：`validate_format` 收小写，`consume`/`register_failure` 按原文匹配必报 Unknown（`codes.rs`）
- [ ] napi `cstr` 内嵌 NUL 静默截断为空串（`unwrap_or_default`），改为显式报错（`syncbond-napi/src/lib.rs:57`）
- [ ] `SyncStats` 的 `received_ops`/`applied_ops` 恒为 0：补实际计数或删字段（`replication.rs` `sync_over`）
- [ ] 身份私钥随 `SyncState` 明文落盘（设计为应用自有存储）：文档标注风险或提供可选加密封装（`identity.rs`/`storage.rs`）
- [ ] `transport::try_recv` 空队列返回 `Closed`，调用方易误判为对端关闭（`transport.rs:104`）
- [ ] `transport::recv` 锁中毒时 panic，改为中毒恢复（`transport.rs:91`）
- [ ] `relay::persist` 写后未 fsync，崩溃可能丢续传状态（`relay.rs:123`）
- [ ] `scalar_from_hex` 奇长十六进制串 panic（`pairing_spake2.rs:53`）
- [ ] `b64url_decode` 接受非规范填充，应拒绝（`crypto.rs`）
- [ ] `sb_last_error` 成功路径返回悬垂非空指针（0x1）：文档标注或返回空（`syncbond-ffi`）
- [ ] `MergeStrategy::delete` 在 OR-Set/PN-Counter 下的语义未文档化（`conflict.rs`）

## 审核发现（2026-11-03 复核，处置中）

- [x] 审核发现：1fae572 让 `MemberKeyRing::open` 把 message_id 持久写入 `seen_message_ids`，但 `crypto::open` 在 AEAD 校验之前就 `insert`，损坏/篡改帧会永久烧掉该 id，之后合法重传同 id 信封被拒为 Replay——此前克隆后丢弃使该烧 id 仅瞬时，此修复将其激活为持久（证据：commit 0c7892e `fix: record envelope id only after authentication`；改 `crypto::open` 为「contains 前置检查、AEAD 成功后才 insert」，新增 `tampered_frame_does_not_consume_message_id` 钉子测试；tests 10/0）
- [ ] 审核发现：`seen_message_ids` 现随每次成功 open 无界增长且从不清理（含跨密钥轮换），旧 epoch 的 id 本可在轮换时清空（旧 epoch 信封先被 epoch 检查拒绝），否则长驻成员内存无界增长（crates/syncbond-core/src/member_crypto.rs:92）
- [ ] 审核发现：replication.rs 的 GcMode 文档与 merge.md 声称 time-only GC「仅经 conformance runner 可达」「不属于公共 API/FFI 表面」，但 `Replicator::gc_tombstones_time_only` 是 `pub` 且类型经 lib.rs:34 重导出，任何 Rust 下游可直接调用——文档与代码不符（crates/syncbond-core/src/replication.rs:42；docs-site/src/design/merge.md:78）
- [x] 审核发现：README 徽章重排后残留孤立 `</p>` 与空 `<div align="center">…</div>`，HTML 结构畸形（证据：commit bc5b67f `docs: badge row layout and locale links`，已清除残留并恢复 logo 独立行块）
- [ ] 审核发现：测试缺口——无并发 `open`（本次引入 Mutex 的动机）测试；无「Replay 拒绝后新 id 信封仍可开」测试（「AEAD 失败不烧 id」已随 0c7892e 补上；crates/syncbond-core/tests/member_rotation_tests.rs:146）
