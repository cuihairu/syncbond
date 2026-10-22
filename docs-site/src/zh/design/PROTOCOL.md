[English](../../design/PROTOCOL.md)

# 协议规范（v1）

状态：已在 `crates/syncbond-core/src/`（pairing、crypto、identity 模块）中实现。本文档是冻结的 v1 协议契约。

## 1. 配对协议：SPAKE2（RFC 9382）

### RFC 9382 与 RFC 9383 —— 选了什么、为什么

| | SPAKE2（RFC 9382） | SPAKE2+（RFC 9383） |
|---|---|---|
| 模型 | 对称 PAKE（口令认证密钥交换）：双方都持有口令 | 增强 PAKE：一方只存一个 verifier（验证器） |
| 防御对象 | 服务器/对端静态持有码时的泄露——**不适用**：没有任何一方存储码 | 服务器数据库中 verifier 被窃 |
| 对设备配对的适配 | 配对窗口内两台设备都合法持有同一个显示码；不存在"服务器" | 解决一个 syncbond 并不存在的问题，代价是流程更复杂 |

选定：**SPAKE2，RFC 9382**，密码套件 `SPAKE2-P256-SHA256-HKDF-HMAC`（RFC 9382 表 1）。一致性已对照 RFC 9382 附录 B 全部四组测试向量验证（`crates/syncbond-core/tests/rfc9382_vectors.rs`，由 RFC 原文生成）。

**不自研密码学**：P-256 运算来自 RustCrypto `p256` 0.13（持续维护，RustCrypto 技术栈成员），SHA-256/HKDF/HMAC 来自 `sha2`/`hkdf`/`hmac`，口令→标量的 MHF（内存困难函数）来自 `scrypt`（RustCrypto），身份密钥来自 `ed25519-dalek`，AEAD（认证加密）来自 `chacha20poly1305`。本 crate 只负责按 RFC 9382 的步骤组装。（2026 年 10 月调研过的先行工作：npm `spake2` 针对 draft-08 且未经审计——否决；CrossPaste pairing v3 在 Kotlin 中使用相同的 RFC 9382 P-256 组合，但它是应用内嵌的，不是可嵌入内核。）

### 口令 → 标量（w）

`w = OS2IP(scrypt("syncbond/w1/v1" || code, N=2^14, r=8, p=1, 64)) mod n` —— 64 字节输出避免模偏差（NIST SP 800-56Ar3 建议）；scrypt 是 RFC 推荐的 MHF。诚实的边界：短码的熵是有上限的，因此码必须单次使用、短时效且均匀随机（见 §3）；SPAKE2 保护交换过程，策略约束在线猜测，而录制的转录只允许以码的熵为界的离线猜测（6 字符约 27 比特——这正是 TTL 与单次使用为强制项的原因）。

### 握手流程与身份绑定

帧格式：`[type: u8][protocol_version: u8][payload]`；顺序遵循 RFC 9382 §3.1：

```
A (initiator, pair())                    B (responder, accept())
  pA = w*M + x*P  ──────── 0x01 ─────────▶
                         ◀──── 0x02 ────  pB = w*N + y*P
  K, TT, Ke||Ka, cA ────  0x03 ─────────▶  check cA
                         ◀──── 0x04 ────  cB            (mutual key confirmation)
  identity_A + sig ─────  0x05 ─────────▶  verify sig
                         ◀──── 0x06 ────  identity_B + sig
```

- **角色绑定**：发起方扮演 A（使用 M），接受方扮演 B（使用 N）；角色由谁发起交换决定，双方无需协商即达成一致。
- **双向密钥确认**：`cA = HMAC(KcA, TT)`、`cB = HMAC(KcB, TT)`；A 在验证 cB 之前不得完成，B 在验证 cA 之前同样不得完成（RFC 9382 §3.1）。码不匹配在此处失败；失败方发送 `abort` 帧（0x07），对端因此不会阻塞等待。
- **身份绑定**：确认完成后，双方各自发送长期 Ed25519 公钥及对 `SHA-256("syncbond/identity/v1" || role || TT)` 的签名——身份绑定到已认证的转录上，中间人无法替换密钥。
- **组 ID**：`SHA-256("syncbond/group/v1" || sorted member public keys)[..24]` —— 与顺序无关，为双方派生同步组。
- **应用域分离**：会话密钥为 `HKDF-SHA256(Ke, nil, "syncbond/v1/session-key", 32)`；`syncbond` 前缀把 HKDF 输出绑定到本应用与本版本。确认密钥用 RFC 的 `"ConfirmationKeys"` info 串单独派生。
- **转录**：`TT` 严格遵循 RFC 9382 §3.3（8 字节小端长度前缀；w 为大端）。每个派生密钥都覆盖 TT。

## 2. 配对码策略（猜测限制）

字母表：30 个无歧义符号（`23456789ABCDEFGHJKMNPQRSTUVWXYZ`，不含 0/O/1/I/L），长度 6 → 字母表熵约 29.5 比特（30^6 ≈ 0.87 × 10^9）。默认值（`crates/syncbond-core/src/codes.rs`）：

| 规则 | 取值 | 理由 |
|---|---|---|
| 单次使用 | 已消费的码永远不能再配对 | 重放已配对的码毫无价值 |
| TTL | 默认 120 s（应用可设置） | 限定在线猜测窗口 |
| 失败次数 | 每个码窗口最多 3 次，之后锁定 | 在 30^6 个码中，每 120 s 窗口 3 次猜测使在线猜测可忽略不计 |
| 格式检查 | 交换前、双方各自执行 | 在任何密码学运算之前拒绝垃圾输入 |

在线攻击者每 2 分钟对约 10^9 个码只有 ≤3 次机会：期望成功时间为数个世纪。录制转录带来的离线猜测风险以码的熵为界，这就是 §3 的规则是强制而非可选的原因。

## 3. 协议版本化

- 版本字节位于每一帧内；不匹配即中止配对（`protocol version mismatch`）。信封携带 `protocolVersion`，接收方拒绝不匹配。
- v1 → v2 的变更必须递增该常量并保留中止路径；跨版本协商（接受较旧对端）是已规划但未实现的决策（见 todo.md）。

## 4. 加密信封

线上格式：`schemas/envelope.schema.json`。AEAD：XChaCha20-Poly1305（192 位 nonce，每消息随机）。

```
interface EncryptedEnvelope {
  protocolVersion: u16; groupId: string; senderDeviceId: string;
  keyEpoch: u64; messageId: string; nonce: [u8; 24]; ciphertext: bytes;
}
```

除 `ciphertext` 外的所有字段都是 AEAD 关联数据（稳定的字节编码）。接收方按顺序拒绝：协议版本不匹配 → 跨组投递 → 错误密钥纪元 → 重放的 `messageId` → 任何 AEAD 失败。`messageId` 为每消息随机的 16 字节；会话维护已见集合，已失效的会话拒绝一切后续流量（重放帧无法使其复活）。

## 5. 密钥纪元与撤销

组持有一个带单调递增 `keyEpoch` 的 `KeyRing`。`rotate()` 铸造纪元 N+1；新密钥只分发给仍是成员的设备。只持有纪元 N 密钥的被撤销设备无法读取纪元 N+1 信封（密钥错误导致 AEAD 失败；且纪元检查先行拒绝）。会话失效加轮换即撤销配方；成员移除时自动轮换是 P2 决策（todo.md）。

## 6. 复制

记录是带有 HLC（混合逻辑时钟）戳与因果见证（witness，即每节点最后见到的完整戳）的不透明载荷。同步通过加密会话交换 oplog；操作按 id 去重，因此乱序与重复投递都能收敛。合并行为是可插拔的 `MergeStrategy`（见 docs/design/merge.md）。完整的协议日志/游标语义在 `crates/syncbond-core/src/replication.rs`。
