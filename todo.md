# todo

来源：用户 2026-10-21 立项令及同日两次修正（定位收窄为通用基础设施 + 语言决策改 Rust core）。定位：accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure SDK。核心原则：SDK 不理解、不解释、不决定业务数据含义。需求基线：`docs/requirements.md`（小节号 R1.1–R11.4 即本清单引用的需求项）。

优先级顺序（用户 2026-10-21 令）：协议安全与收敛正确性 → 可嵌入 API → WebSocket 最小持久中继 → LAN 发现 → P2P/Iroh → 平台集成。

## P1 — 协议安全与收敛正确性（本轮完成）

- [x] R1.1–R1.3, R1.5 SPAKE2 配对，RFC 9382 选型落地（`SPAKE2-P256-SHA256-HKDF-HMAC`），4 组 RFC 附录 B 测试向量全过（证据：`crates/syncbond-core/tests/rfc9382_vectors.rs`，5 tests ok）
- [x] R1.3 配对码策略：单次使用 / TTL / 失败限次 / 格式校验（证据：`tests/pairing_tests.rs` 3 个码策略测试 ok；30 字母表 ≈10^9 码 + 3 次/120s 窗口，在线猜测不可行）
- [x] R1.4 双向密钥确认 + 错码拒绝（双侧）+ abort 帧防死锁（证据：`mismatched_codes_reject_on_both_sides_without_deadlock` ok）
- [x] R1.6–R1.7, R2.1–R2.3 配对后交换长期设备公钥，签名绑定转录哈希；groupId 由双方公钥确定性派生（证据：`session_keys_and_group_ids_match_on_both_sides` ok）
- [x] R1.5, R9.1–R9.2 协议版本协商：每帧版本字节，不兼容消息拒绝（证据：`protocol_version_mismatch_is_rejected`、`unsupported_protocol_version_is_rejected` ok）
- [x] R3.1–R3.5, R8.1, R8.3 信封定型：9 字段 + 除密文外全 AAD + keyEpoch 自 v1；篡改/重放/跨组/错纪元拒绝（证据：`tests/crypto_envelope_tests.rs` 9 tests ok；schema 同步落 `schemas/envelope.schema.json`）
- [x] R2.4, R3.3–R3.4 撤销 = keyEpoch 轮换：旧纪元设备解不开新纪元信封（证据：`revoked_device_cannot_open_next_key_epoch` ok）
- [x] R2.5 会话失效与重放保护（证据：`session_invalidation_blocks_further_traffic`、`replayed_message_is_rejected` ok）
- [x] R5.1–R5.4 可插拔合并策略 + 内置 LWW(HLC)/OR-Set/PN-Counter；墓碑带因果元数据，旧设备重连不复活删除（证据：`tests/replication_tests.rs` 7 tests ok；全 stamp witness 修复跨秒边界因果丢失）
- [x] R5.5 大幅时钟偏移不无声覆盖：HLC 拒绝采纳 + 保留并发版本并标记（证据：`large_clock_skew_does_not_silently_overwrite` ok）
- [x] R4.1–R4.4 乱序 + 重复投递终态一致（证据：`out_of_order_and_duplicate_delivery_converge` ok）
- [x] R6.1–R6.3 崩溃重启后身份/游标/oplog 一致：可替换持久化接口 + 内存实现自测（证据：`crash_restart_restores_identity_cursor_and_oplog` ok）
- [x] R10.3 通用性验收 P3：三个互不相关示例（通用 KV / 笔记文档 / 任意二进制）全部进仓进测试（证据：`tests/examples_tests.rs` 3 tests ok）
- [x] R10.2 语言决策落档：Rust Core + TS Binding，对比表进 `docs/design/language.md`；TS 核心实现已撤，转为 crates workspace + TS 绑定骨架
- [x] 单 commit 首推，门禁全绿（证据：cargo fmt/clippy 0 warning、cargo test 35 passed；commit 见 git log）

## P2 — 传播与集成（待排期，按优先级顺序）

- [x] WebSocket 最小持久中继（P2 首项）：跨设备、断线重连、异步上线验证；oplog 增量拉取按游标续传。验收口径：两端经中继收敛；中途掉线端重连后追平且不重复。证据：commit `27c139d`；cargo fmt/clippy/test 全绿（37 tests passed）；`crates/syncbond-core/src/relay.rs:21`、`crates/syncbond-core/tests/replication_tests.rs:247`、`crates/syncbond-core/tests/relay_persistence_tests.rs:18`。来源：用户 2026-10-21 优先级令
- [x] napi-rs TypeScript 绑定实现（对应 `packages/ts-bindings` 骨架类型）。验收口径：TS 侧跑通 pair/sync 全流程。证据：commit（本条所在 commit）；TS e2e `packages/ts-bindings/src/index.test.js` 4/4 绿（pair → 双向 sync → 双端收敛 → 删除/墓碑传播 → 失效会话拒绝）；Rust 侧 cargo clippy 0 warning、cargo test 37 passed；实现在 `crates/syncbond-napi`（会话走 Arc，无 unsafe 提取）。来源：同上（语言决策）
- [ ] 成员移除触发自动 keyEpoch 轮换 + 新钥分发协议。验收口径：被移除设备无法解任何轮换后信封。来源：用户 2026-10-21 修正令
- [ ] 墓碑 GC 落地：时间阈值 + 因果支配判定（设计见 docs/design/merge.md），依赖中继的副本向量心跳。验收口径：GC 后旧写入仍不能复活删除。来源：同上
- [ ] 跨版本协商（接受旧版本对端）是否支持——待拍板项，见下
- [ ] LAN 发现（mDNS）传输。验收口径：同网段零配置配对。来源：同上
- [ ] P2P/Iroh 传输评估。验收口径：打洞成功率与中继回退路径。来源：同上
- [ ] tombstone 仅时间阈值裁剪（无支配判定的降级模式）是否开放给应用——待拍板项，见下

## P3 — 发布（阻断项未清不动）

- [ ] 最终品牌名（用户另行核验候选，暂用 syncbond 开发名）
- [ ] npm 发布：**不发布任何 npm 稳定包**；且作用域 `@cuihairu/syncbond` 发布前需确认 scope 权限——待拍板项，见下

## 待拍板项（用户决策）

1. **npm 发布策略**：是否发布、何时发布、scope `@cuihairu/syncbond` 权限确认（用户已令：不发布任何 npm 稳定包；scope 权限需确认）。
2. **最终品牌名**：用户另行核验候选后定（README 已置顶「temporary dev name」）。
3. **跨版本协商**：协议 v2 出现后是否兼容旧对端（当前 v1 仅拒绝不协商）。
4. **墓碑降级 GC**：是否给应用开放「仅时间阈值」的不安全裁剪模式。
5. **自动轮换触发**：成员移除是否由核心自动 rotate（当前 rotate 是应用手动调用）。
