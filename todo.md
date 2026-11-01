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

- [x] WebSocket 持久中继：断线重连 + 游标续传，两端经中继收敛（证据：commit 27c139d；tests 37）
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
