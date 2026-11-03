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

- [x] 会话/中继接收路径加帧大小上限，防认证对端巨帧 OOM（证据：commit efec3ea；`MAX_FRAME_BYTES = 16 MiB` 于 `recv_and_open` 收帧即拒，`sync_over` 数据流经该入口故一并覆盖；新增 `oversized_app_frames_are_rejected` 测试）
- [x] `HybridClock::receive` 死代码处置：`ct` 加法改 saturating 或删除该公开方法（证据：`receive` 三处 `+1` 改 `saturating_add(1)`，保留公开 API 不破坏下游；新增 `receive_saturates_at_max_counter` 钉子测试；`hlc.rs:96`）
- [x] 拍板：conformance fixture 的 `time_only` GC 模式是否对应用收紧（已代决：维持现状——`time_only` 仅经 conformance fixture 的 `gc` 步骤驱动（测试专用），只作用于 `conformance_run` 内部创建的内存副本节点，不触及应用真实存储；公开 `conformance_run` 是跨语言一致性验证入口而非应用功能面；Rust 公开方法已 `#[doc(hidden)]` 且发现2一致化文档。维持 2026-10-28 决策口径）
- [x] `max_stamp` 比较反转：a>b 时返回较小戳，合并记录携带较早时间戳（证据：交换 `max_stamp` 分支——`compare_stamps(a,b)==Greater` 时返回 `a`（较大戳）而非 `b`；新增 `max_stamp_returns_the_later_stamp` 钉子测试；`conflict.rs:88`）

P3：

- [x] `crypto::open` AEAD 失败时不记录 `message_id`，避免损坏帧永久烧掉同 id 重传（证据：commit 0c7892e `fix: record envelope id only after authentication`——`open` 现于 AEAD 校验成功后 `insert`，`map_err` 提前返回不记录；钉子测试 `tampered_frame_does_not_consume_message_id`；`crypto.rs:145`）
- [x] `generate_code` 消除模偏差（证据：改用拒绝采样——丢弃 `>=240` 字节重取（30×8=240），30 符号各 1/30 等概率；`codes.rs:58`）
- [x] 配对码小写不一致：`validate_format` 收小写，`consume`/`register_failure` 按原文匹配必报 Unknown（证据：`consume`/`register_failure` 入口把输入 `to_ascii_uppercase()` 后查表，与 `validate_format` 口径一致；新增 `lowercase_code_matches_stored_uppercase` 钉子测试；`codes.rs`）
- [x] napi `cstr` 内嵌 NUL 静默截断为空串（`unwrap_or_default`），改为显式报错（证据：`cstr` 改返回 `Result<CString>`，`CString::new` 失败时 `map_err` 报 `InvalidArg`（"string contains an embedded NUL byte"），5 处调用点加 `?`，`pairing.rs` 的 `Option` 用 `transpose()?`；`cargo check -p syncbond-napi` 通过；`syncbond-napi/src/lib.rs:57`）
- [x] `SyncStats` 的 `received_ops`/`applied_ops` 恒为 0：补实际计数或删字段（证据：`sync_over` 的 `receive` 闭包现返回 `(received, applied)`——`received` 为收到的 op 数、`applied` 为 `apply_remote` 返回 true 的合并数，两方向均正确填入 `SyncStats`；文档注释同步；`replication.rs` `sync_over`）
- [x] 身份私钥随 `SyncState` 明文落盘（设计为应用自有存储）：文档标注风险或提供可选加密封装（证据：`DeviceIdentity::secret_key` 与 `SyncState` 均新增风险标注——SDK 从不自行加密存储，应用必须将快照置于受保护后端或在 `SyncStorage` 层加密，否则泄露可被伪造身份；选择文档标注而非加密封装以保 API 稳定；`identity.rs`/`storage.rs`）
- [x] `transport::try_recv` 空队列返回 `Closed`，调用方易误判为对端关闭（证据：`TransportError` 新增 `Empty` 变体（"no frame available"），`try_recv` 空队列返回 `Empty`、对端关闭返回 `Closed`；新增 `try_recv_empty_is_distinct_from_closed` 测试；`transport.rs:104`）
- [x] `transport::recv` 锁中毒时 panic，改为中毒恢复（证据：`recv` 的 `lock()` 与 `condvar.wait()` 均改 `unwrap_or_else(|poisoned| poisoned.into_inner())` 中毒恢复；`transport.rs:91`）
- [x] `relay::persist` 写后未 fsync，崩溃可能丢续传状态（证据：`persist` 改 `File::create+write_all+sync_all` 后 rename，再对父目录 `sync_all` 保证 rename 持久；`relay.rs:123`）
- [x] `scalar_from_hex` 奇长十六进制串 panic（证据：`hex_to_bytes`/`scalar_from_hex` 改返回 `Result<_, String>`，奇长十六进制显式 `Err` 不再越界 panic，内部调用改 `expect`，测试向量调用改 `expect`；新增 `odd_length_hex_is_rejected_instead_of_panicking` 测试；`pairing_spake2.rs:53`）
- [x] `b64url_decode` 接受非规范填充，应拒绝（证据：`rem==2` 时校验末符号低 4 位为 0、`rem==3` 时校验低 2 位为 0，非规范填充显式 `Err`；新增 `non_canonical_padding_is_rejected` 测试；`crypto.rs`）
- [x] `sb_last_error` 成功路径返回悬垂非空指针（0x1）：文档标注或返回空（证据：`last_error_ptr` 在 `Vec` 为空时返回 `std::ptr::null()`，成功路径不再返回悬垂非空指针；napi/wasm 侧已有 null 检查；`syncbond-ffi`）
- [x] `MergeStrategy::delete` 在 OR-Set/PN-Counter 下的语义未文档化（证据：`merge.md` 新增「`deleted` flag semantics per strategy」——仅 `LwwHlc` 将 `deleted:true` 转为因果墓碑；OR-Set/PN-Counter 的 merge 硬编码 `deleted:false` 忽略该标志，删除须经 payload 语义表达（OR-Set 退役 tag），PN-Counter 无内建删除；`conflict.rs`）

## 审核发现（2026-11-03 复核，处置中）

- [x] 审核发现：1fae572 让 `MemberKeyRing::open` 把 message_id 持久写入 `seen_message_ids`，但 `crypto::open` 在 AEAD 校验之前就 `insert`，损坏/篡改帧会永久烧掉该 id，之后合法重传同 id 信封被拒为 Replay——此前克隆后丢弃使该烧 id 仅瞬时，此修复将其激活为持久（证据：commit 0c7892e `fix: record envelope id only after authentication`；改 `crypto::open` 为「contains 前置检查、AEAD 成功后才 insert」，新增 `tampered_frame_does_not_consume_message_id` 钉子测试；tests 10/0）
- [x] 审核发现：`seen_message_ids` 现随每次成功 open 无界增长且从不清理（含跨密钥轮换），旧 epoch 的 id 本可在轮换时清空（旧 epoch 信封先被 epoch 检查拒绝），否则长驻成员内存无界增长（证据：`apply_rotation`/`install_local_rotation` 现于轮换时清空 `seen_message_ids` 并保留轮换标记 id；新增 `rotation_drops_old_epoch_seen_ids` 单元测试；crates/syncbond-core/src/member_crypto.rs:92）
- [x] 审核发现：replication.rs 的 GcMode 文档与 merge.md 声称 time-only GC「仅经 conformance runner 可达」「不属于公共 API/FFI 表面」，但 `Replicator::gc_tombstones_time_only` 是 `pub` 且类型经 lib.rs:34 重导出，任何 Rust 下游可直接调用——文档与代码不符（证据：`gc_tombstones_time_only` 加 `#[doc(hidden)]` 标注非稳定/内部专用面并改述为「Rust 下游可显式 opt-in，C ABI/稳定绑定仅暴露 dominance」，`merge.md` 同步；crates/syncbond-core/src/replication.rs:42；docs-site/src/design/merge.md:78）
- [x] 审核发现：README 徽章重排后残留孤立 `</p>` 与空 `<div align="center">…</div>`，HTML 结构畸形（证据：commit bc5b67f `docs: badge row layout and locale links`，已清除残留并恢复 logo 独立行块）
- [x] 审核发现：测试缺口——无并发 `open`（本次引入 Mutex 的动机）测试；无「Replay 拒绝后新 id 信封仍可开」测试（证据：新增 `concurrent_open_accepts_each_unique_envelope_once`（32 线程并发唯一 id 全开）与 `replay_rejected_then_fresh_id_still_opens`（Replay 拒绝后新 id 仍可开）；tests 11/0；crates/syncbond-core/tests/member_rotation_tests.rs:146）

## 审核发现（2026-11-03 第三轮，diff 7737b0d3..HEAD 共 19 提交/29 文件）

覆盖范围：全部代码变更逐文件审毕（crypto.rs、member_crypto.rs、pairing.rs、pairing_spake2.rs、codes.rs、replication.rs、tests/×3）；文档类（README×2、docs/、docs-site/、todo.md/.bak 删除）按抽样核对一致性；`cargo test -p syncbond-core` 65/65 通过。已记录于上文的发现（seen_message_ids 无界增长、GcMode 文档与 pub API 不符、无并发 open 测试）不重复列出。以下为本轮新发现：

- [x] 审核发现：efec3ea 的 16 MiB 帧上限只加在 `recv_and_open`（配对完成后的应用帧），配对握手期帧（pA/pB/cA/cB/identity）经 `expect_frame`→`transport.recv()` 无任何大小上限，identity 帧随后还对未限长 payload 做 `serde_json::from_slice` 解析——这是**未认证**阶段（威胁强于注释所称「认证对端」）可触发的无界分配/解析；测试缺口：无握手路径巨帧测试（证据：`expect_frame` 现于 `transport.recv()` 后立即按 `MAX_FRAME_BYTES` 拒巨帧（任何握手帧都经此）；新增 `oversized_handshake_frames_are_rejected` 测试；crates/syncbond-core/src/pairing.rs:164-181、195-211）
- [x] 审核发现：MAX_FRAME_BYTES 检查位于 `transport.recv()` 返回完整缓冲帧之后，未来网络传输实现（WebSocket/LAN/P2P，计划中）在检查触发前已完成对恶意巨帧的整块内存分配——上限挡住的是解码而非收包侧 OOM；Transport trait 未约定大小契约（证据：`Transport` trait 文档新增显式 MUST 契约——网络实现收包阶段不得组装超过 `MAX_FRAME_BYTES` 的帧，核心检查为协议兜底而非分配守卫；`PROTOCOL.md` 第7节同步；crates/syncbond-core/src/pairing.rs:98-104、transport.rs:16-23）
- [x] 审核发现：同一区间为 `MemberKeyRing` 确立锁中毒恢复惯例（`unwrap_or_else(|poisoned| poisoned.into_inner())`），但 `PairingSession::recv_and_open` 仍 `seen_message_ids.lock().unwrap()`——持有锁的线程一旦 panic，该会话后续所有收包永久 panic，同库两处行为不一致（证据：`recv_and_open` 改 `unwrap_or_else(|poisoned| poisoned.into_inner())`，与 `MemberKeyRing::open` 恢复惯例一致；crates/syncbond-core/src/pairing.rs:114，对比 member_crypto.rs:227-230）
- [x] 审核发现：0c7892e 之后 `crypto::open` 的 Replay 前置检查仍先于 AEAD 校验执行，错误类型区分（Replay vs AuthenticationFailed）向能投递帧并观察错误的一方泄漏「该 message_id 是否已被成功打开」的接收方状态；影响低，属顺序权衡，建议在 docs/design/PROTOCOL.md 注明（证据：`PROTOCOL.md` 第4节新增顺序权衡说明——泄漏仅限接收方内部 seen-state 且能投递帧的对端本可推断，AEAD 通过后才记录 id 防烧 id；crates/syncbond-core/src/crypto.rs:149-151）

## 审核发现（2026-11-03 第四轮，diff efec3eab..HEAD 共 26 提交/21 文件）

覆盖范围：逐提交逐文件审毕（codes.rs、conflict.rs、crypto.rs、hlc.rs、identity.rs、member_crypto.rs、pairing.rs、pairing_spake2.rs、relay.rs、replication.rs、storage.rs、transport.rs、tests/×3、syncbond-ffi/error.rs、syncbond-napi/lib.rs、syncbond-napi/pairing.rs、merge.md、PROTOCOL.md）；`cargo test -p syncbond-core` 全绿、`cargo check` 四绑定 crate 通过。已记录于上文各轮的发现在此轮 diff 内未见复发（max_stamp 交换分支、轮换清空 seen、握手帧上限、并发 open 测试均已按证据闭合）。以下为本轮发现：

- [x] 审核发现：`generate_code` 拒绝采样阈值 240=30×8 按「30 符号」计算，但 `CODE_ALPHABET` 实为 31 符号（`23456789`+`ABCDEFGH`+`JKMNPQRSTUVWXYZ`，36−{0,1,I,L,O}=31）；`240 % 31 = 23 ≠ 0`，故索引 0..22（`'2'..'R'`，23 个）以 8/240、索引 23..30（`'S'..'Z'`，8 个）以 7/240 概率出现，前 23 个约高 14%，模偏差**未消除**；正确阈值应为 31×8=248（丢弃 ≥248）。注释「256 % 30」「30×8=240」、模块注释「30 symbols」「30^6≈29.4 bits」及 todo.md 所述「30 符号各 1/30 等概率」均与实际不符；无分布测试覆盖（证据：阈值改 `b < 248`、注释/模块文档修正为 31 符号 31^6；新增 `rejection_threshold_is_multiple_of_alphabet`/`alphabet_is_unambiguous_and_31_symbols` 测试；cargo test 77 全绿；commit 97ba6e2）
- [x] 审核发现：18f2bbd 只给 `consume`/`register_failure` 加 `to_ascii_uppercase()` 归一，`is_accepting` 仍 `issued.get(code)` 原文查表——合法未消费码的小写形式 `is_accepting` 返回 false 而 `consume` 成功，同库三方法大小写口径不一致；新测试 `lowercase_code_matches_stored_uppercase` 仅在消费后断言 `is_accepting(&lower)==false`（因 used 为假因），掩盖该不一致（证据：`is_accepting` 改 `issued.get(&code.to_ascii_uppercase())`；测试在消费前补断言 `is_accepting(&lower)==true`；cargo test 77 全绿；commit 9aa3850）
- [x] 审核发现：bd9787a 将 `transport::recv` 改锁中毒恢复（`unwrap_or_else(|poisoned| poisoned.into_inner())`），但同实现 `send`（transport.rs:88）与 `try_recv`（transport.rs:118）仍 `lock().unwrap()`——持锁线程 panic 后这两路径永久 panic，同文件内中毒处理不一致（证据：`send`/`try_recv` 均改 `unwrap_or_else(|poisoned| poisoned.into_inner())` 与 `recv` 一致；新增 `send_and_try_recv_recover_poisoned_lock` 测试（无修复时确会 panic 于两处锁，修复后通过）；cargo test 78 全绿；commit d0f5b08）
- [x] 审核发现：`HybridClock::receive` 改 `saturating_add(1)` 未真正堵住溢出——skew 检查只限 `remote.pt` 跑前、不限 `ct`，恶意/异常对端可发 `(pt≈now, ct=u64::MAX)` 令 `self.ct=MAX`；随后本地 `issue()`（`self.ct += 1`，hlc.rs:81）在 `wall<=self.pt`（同 ms 内）仍溢出（debug panic / release 回绕破坏 HLC 单调唯一），溢出仅从 receive 移到 issue；新测试 `receive_saturates_at_max_counter` 只断言 receive 返回值，未覆盖后续 `issue()`（证据：`issue()` 的 `self.ct += 1` 改 `saturating_add(1)`；新增 `issue_after_saturated_receive_does_not_overflow` 测试（无修复时 panic「attempt to add with overflow」，修复后通过）；cargo test 79 全绿；commit e0727b2）
- [x] 审核发现：`relay::persist` 新增目录 fsync `File::open(parent)`（relay.rs:148），但当 `self.path` 为裸相对路径（如 `"state.json"`）时 `parent()` 返回 `Some("")`，`File::open("")` 报 NotFound，`append` 整体失败——e11824f 前该路径可正常落盘（`create_dir_all("")` 为 no-op），属回归；测试仅用 `env::temp_dir().join(...)`（父目录 /tmp），未覆盖裸路径；另 `File::open` 打开目录在 Windows 失败（可移植性）（证据：`parent()` 改用 `.filter(|p| !p.as_os_str().is_empty())`，裸相对路径跳过目录 fsync；新增 `durable_relay_accepts_bare_relative_path` 测试（无修复时确报 NotFound，修复后通过）；cargo test 80 全绿；commit b658a99）
- [x] 审核发现：`concurrent_open_accepts_each_unique_envelope_once`（member_rotation_tests.rs:166）让 32 线程各开一个**不同** id 信封，未让两线程竞争**同一** id（应恰一次成功、另一次 Replay），故 Mutex 对「同 id 去重」的并发正确性未验证——仅覆盖不同 id 并行可开（证据：新增 `concurrent_open_same_envelope_accepts_exactly_once`——32 线程竞争同一 id，断言恰一次成功、其余均 Replay（连跑 5 次稳定）；cargo test 81 全绿；commit 4a51021）
- [ ] 审核发现：`sync_over` 发送侧无帧大小守卫——`seal_and_send(encode(&oplog))` 将整段 oplog 打包为一帧，oplog 超过 `MAX_FRAME_BYTES`（16 MiB）时本端无检查即发出、对端 `recv_and_open` 必拒「frame too large」，功能级失败且错误信息误导（对端视角），无分块/发送侧上限检查；帧上限仅收侧守卫（crates/syncbond-core/src/replication.rs:546-549）
