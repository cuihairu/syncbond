[English](../requirements.md)

# 需求基线

状态：需求基线，由 2026-10-21 调研（见 [`../research/survey-2026-10-21.md`](../research/survey-2026-10-21.md)）与用户立项评审推导。每条映射到代码与测试；`todo.md` 的 P1 项引用本清单小节编号。

指导原则：**SDK 不理解、不解释、不决定业务数据的含义。** 载荷是不透明字节，合并语义由应用决定。

## 1. 配对

- 短码生成：无歧义字母表（不含 0/O/1/I/L）、固定长度（R1.1）。
- PAKE 配对：SPAKE2，RFC 9382（`SPAKE2-P256-SHA256-HKDF-HMAC`），以 RFC 附录 B 全部测试向量验证（R1.2）。
- 码的熵、TTL、单次使用、失败限次为强制策略，约束在线猜测（R1.3）。
- 双向密钥确认：任一方未验证对端转录 MAC 前不得完成（R1.4）。
- 转录 + 协议版本 + 应用域隔离：每帧带版本字节；HKDF info 绑定应用名与版本（R1.5）。
- 角色绑定：发起方/接受方由谁发起决定，映射到 SPAKE2 A/B 角色与身份签名（R1.6）。
- 配对成功后交换长期设备公钥，签名绑定转录哈希（R1.7）。

实现：`crates/syncbond-core/src/{pairing,pairing_spake2,codes}.rs`；测试 `tests/pairing_tests.rs`、`tests/rfc9382_vectors.rs`。契约：`docs/design/PROTOCOL.md`。

## 2. 身份

- 每设备长期 Ed25519 密钥对（R2.1）。
- 由公钥确定性派生设备 ID（R2.2）。
- 成员邀请即配对流程；配对完成即入组（R2.3）。
- 撤销传播：组密钥纪元轮换；被撤销设备打不开后续纪元信封（R2.4）。
- 重放保护：每消息独立 id + 会话已见集合；失效会话拒绝一切流量（R2.5）。

实现：`src/identity.rs`、`src/crypto.rs`（KeyRing）、`src/pairing.rs`（PairingSession）。测试：`revoked_device_cannot_open_next_key_epoch`、`replayed_message_is_rejected`、`session_invalidation_blocks_further_traffic`。

## 3. 加密

- 九字段信封；除密文外全部字段进入 AEAD 关联数据（R3.1）。
- 会话密钥与确认密钥的 HKDF 域分离（R3.2）。
- keyEpoch 自 v1 存在；轮换即撤销原语（R3.3）。
- 新纪元信封无法被任何旧纪元密钥打开（R3.4）。
- v1 套件固定；套件协商属于版本决策，不做逐消息协商（R3.5）。

实现：`src/crypto.rs`。线上 schema：`schemas/envelope.schema.json`。测试：`tests/crypto_envelope_tests.rs`。

## 4. 复制

- 记录操作的 oplog + 每节点单调游标（R4.1）。
- 按游标增量同步；快照用于追赶与持久化（R4.2）。
- 按消息/操作 id 去重（R4.3）。
- 乱序与重复投递收敛到一致状态（R4.4）。
- 离线追赶：掉线设备重连后应用对端 oplog（R4.5）。

实现：`src/replication.rs`。测试：`out_of_order_and_duplicate_delivery_converge` 及示例测试。

## 5. 冲突

- 可插拔 `MergeStrategy` trait；核心不强加语义（R5.1）。
- 内置：HLC-LWW + 因果墓碑、OR-Set、G-/PN-Counter（R5.2）。
- 删除是带因果 witness 元数据的墓碑；旧设备无法复活删除（R5.3）。
- 并发版本保留给应用裁决，不静默丢弃（R5.4）。
- 大幅时钟偏移不无声覆盖：超前时间戳按并发处理、标记并保留（R5.5）。
- 墓碑 GC 设计：时间阈值 + 因果支配（`docs/design/merge.md`）；实现待中继心跳（R5.6）。

实现：`src/conflict.rs`、`src/hlc.rs`。测试：`tests/replication_tests.rs`。

## 6. 存储

- 可替换持久化 trait（`SyncStorage`）（R6.1）。
- 快照保存在调用方视角为原子替换（R6.2）。
- 崩溃重启一致性：身份、游标、oplog 全部幸存（发布阻断）（R6.3）。
- 静态加密交由存储后端；SDK 以字节暴露状态（R6.4）。

实现：`src/storage.rs`。测试：`crash_restart_restores_identity_cursor_and_oplog`。

## 7. 传输

- 抽象 `Transport` 接口（帧收发）（R7.1）。
- 内存回环实现用于测试（R7.2）。
- P2 首项：WebSocket 最小持久中继（跨设备、断线重连、异步上线）（R7.3）。
- LAN 发现（mDNS）与 P2P 随后；中继按构造只见密文（E2EE 在信封层）（R7.4）。

实现：`src/transport.rs`。

## 8. 组与命名空间

- 组授权：组 id 由成员公钥派生；信封携带组 id 并在接收端校验（R8.1）。
- 每设备多数据集：命名空间/集合是应用层对记录键空间的划分；核心保证组隔离，不定义数据集语义（R8.2）。
- 跨组投递在信封层拒绝（R8.3）。

实现：`src/crypto.rs`（组校验）、`src/identity.rs`（组 id）。测试：`cross_group_delivery_is_rejected` 及经由组校验的空间隔离语义。

## 9. 版本协商

- 每帧与每个信封带协议版本；不兼容版本显式拒绝（R9.1）。
- 扩展字段：v1 信封 schema 封闭（`additionalProperties: false`）；扩展随版本升级引入（R9.2）。

测试：`protocol_version_mismatch_is_rejected`、`unsupported_protocol_version_is_rejected`。

## 10. SDK 面

- 公开 API：`pair(displayCode)` / `accept(code)` / 经 `Transport` 的 `sync`（R10.1）。
- 语言路线：Rust 核心 + TypeScript 绑定（napi-rs）；决策见 `docs/design/language.md`（R10.2）。
- 通用性门禁：三个互不相关示例（通用 KV、笔记文档、任意二进制）跑在同一核心上并有测试（R10.3）。
- 默认无服务器；中继可选且只见密文（R10.4）。

实现：`src/lib.rs`、`packages/ts-bindings`（骨架）。测试：`tests/examples_tests.rs`。

## 11. 安全工程

- 协议一致性以官方 RFC 测试向量证明（R11.1）。
- 秘密比较用常量时间比较（HMAC 校验路径；需逐一复核全部秘密比较）（R11.2）。
- 运行时允许范围内密钥清零；绑定层不得把密钥复制进 GC 托管内存（R11.3）。
- 威胁模型文档：码猜测（在线受策略约束、离线受熵 + 单次使用约束）、敌意中继（只见密文）、恶意对端（PAKE + 确认）、失窃设备（keyEpoch 轮换）（R11.4）。

状态：R11.1/R11.2 已完成（`tests/rfc9382_vectors.rs`、HMAC 校验路径）；R11.3 部分完成（尚无 zeroize——待办）；R11.4 由 `docs/design/PROTOCOL.md` §2–§5 覆盖，完整威胁模型页待建。
