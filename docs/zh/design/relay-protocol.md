[English](../../design/relay-protocol.md)

# 中继协议 v1（网络契约）

状态：**2026-11-14 冻结**（todo.md DSR-07）。这是 syncbond 客户端与默认自托管中继之间的线上契约。共享 DTO、错误码与大小上限实现于 `crates/syncbond-relay-protocol`（DSR-09）；执行该契约的服务为 `apps/syncbond-server`（DSR-11+，规划中）。架构与信任边界见[默认服务器设计](default-server.md)；端到端协议见 [PROTOCOL.md](PROTOCOL.md)。

本契约只承载**不透明的加密信封**。中继永不解密、合并或解释信封；信封自身的 JSON 形态另行冻结于 `schemas/envelope.schema.json`（PROTOCOL.md §4）。中继契约版本与信封版本相互独立：任一升 v2 都不影响另一个。

## 1. 传输与编码

- 所有请求/响应路由走 HTTP/1.1；配对房间帧转发与通道更新通知走 WebSocket（RFC 6455）。公开部署经 TLS 反向代理；明文仅限本地开发。
- 每个 HTTP body 都是 UTF-8 JSON，`Content-Type: application/json`。
- 每个请求 body 与每个成功响应都携带：
  - `protocolVersion`（整数，必须为 `1`）——**中继契约**版本；
  - `requestId`（字符串，1–64 字符，客户端自选）——原样回显在响应中。
  失败响应在请求可解析时回显 `requestId`，否则为 `null`。
- 未知 JSON 字段一律拒绝（HTTP 400，码 `bad_request`）——与信封 schema 的 `additionalProperties: false` 同一封闭形态策略。
- `protocolVersion` 非 `1` 一律 400 `version_unsupported`。**无协商**，与 PROTOCOL.md §3 一致：将来的 v2 契约对 v1 客户端硬拒绝，反之亦然。每个信封内嵌的端到端 `protocolVersion` 是另一个无关字段，遵循同样的硬拒绝规则。

## 2. 鉴权

- `Authorization: Bearer <token>`。token 为 32 随机字节的 base64url（43 字符）。服务端只存 token 的 SHA-256 摘要；token 永不入日志、永不出现在 URL 中。
- 三类 token：
  | 类别 | 持有者 | 授权范围 |
  |---|---|---|
  | 管理凭证 | 部署者（引导文件，DSR-15） | 通道创建、凭证签发/撤销 |
  | 通道凭证 | 一台设备 × 一个通道 | 该通道的 `append` 和/或 `pull` 权限 |
  | 房间能力 | 一个配对房间的 ≤ 2 名参与者 | 仅该房间内的帧转发 |
- token 有效但角色/权限/通道不符是 403 `forbidden`；token 缺失或未知是 401 `unauthorized`。组 id 与设备 id **不是**凭证。
- 权限校验：`/append` 需 `append` 权限；`/pull` 与通道事件流需 `pull` 权限；管理路由需管理凭证。持有效他通道凭证的跨通道访问返回 403，而非 404。
- 管理凭证在服务首次初始化时生成（32 随机字节，写为数据库旁的 `0600` 文件），部署者须移入受保护配置。不存在硬编码或开发默认密钥。

## 3. HTTP 路由

| 方法 | 路径 | 鉴权 | 用途 |
|---|---|---|---|
| `POST` | `/v1/channels` | 管理 | 创建通道 |
| `POST` | `/v1/channels/{channelId}/credentials` | 管理 | 签发通道凭证 |
| `GET` | `/v1/channels/{channelId}/credentials` | 管理 | 列出凭证（仅摘要与元数据，永不含 token） |
| `DELETE` | `/v1/channels/{channelId}/credentials/{credentialId}` | 管理 | 撤销凭证 |
| `POST` | `/v1/channels/{channelId}/append` | `append` 权限 | 批量追加加密信封 |
| `POST` | `/v1/channels/{channelId}/pull` | `pull` 权限 | 分页读取 |
| `GET` | `/v1/health` | 无 | 存活检查 |
| `POST` | `/v1/pairing/rooms` | 无（限流） | 创建配对房间 |
| `GET`（升级） | `/v1/pairing/{roomId}` | 房间能力 | WebSocket 配对房间帧转发 |
| `GET`（升级） | `/v1/channels/{channelId}/events` | `pull` 权限 | WebSocket 更新通知 |

`channelId` 是服务端分配的不透明字符串，1–128 字符。pull 用 `POST`（游标与限制放在 body 而非 URL；pull 无副作用且幂等）。

### 3.1 通道管理

创建通道——请求 `{"protocolVersion":1,"requestId":"c7f3a91d2b8e4f06a5c7d9e0b1a2c3d4"}`。权限是每份凭证的属性，不是通道的属性。

响应 `201 Created`：
```json
{"protocolVersion":1,"requestId":"c7f3a91d2b8e4f06a5c7d9e0b1a2c3d4","channelId":"ch_9f8e7d6c5b4a3f2e1d0c"}
```

签发凭证——请求：
```json
{"protocolVersion":1,"requestId":"aa11bb22cc33dd44ee55","scopes":["append","pull"],"label":"phone"}
```
响应 `201 Created`——token **仅此一次**可见：
```json
{"protocolVersion":1,"requestId":"aa11bb22cc33dd44ee55","credentialId":"cred_1a2b3c4d5e6f","token":"7JeZ9xK2mQ4vN8sT1wY6uB3cD5fH0gLpR2aVbCxz9kM","scopes":["append","pull"],"label":"phone"}
```

撤销——`DELETE /v1/channels/{channelId}/credentials/{credentialId}` → `200 {"protocolVersion":1,"requestId":"…","revoked":"cred_1a2b3c4d5e6f"}`。撤销跨重启有效，且对已建立的连接同样生效（该凭证的下一个请求或 WS 帧即 401）。

## 4. 追加：提交 ACK 与幂等

请求 `POST /v1/channels/{channelId}/append`：
```json
{"protocolVersion":1,"requestId":"req_5f6e7d8c9b0a1f2e3d4c","envelopes":[
  {"protocolVersion":1,"groupId":"g_ab12…","senderDeviceId":"dev_phone","keyEpoch":3,"messageId":"m_0192f3e4d5c6b7a8","nonce":"7Je…22chars","ciphertext":"9hK2xQ…"}
]}
```
数组每个元素都是端到端 `EncryptedEnvelope` JSON 对象，形态由 `schemas/envelope.schema.json` 冻结。中继只校验外层形态：必需字段齐全、尺寸在上限内；永不解释 `groupId` 语义——路由由路径上的 `channelId` 决定。

约束（任一违反即拒绝**整批**，什么都不提交）：
- 每请求 1–16 个信封；信封序列化总字节 ≤ 8 MiB；单信封 ≤ 4 MiB。
- 信封 JSON 必须能解析为冻结形态（封闭、无未知字段）。

成功 `200 OK`——提交 ACK，**仅在事务持久之后**返回（SQLite WAL 提交；被确认的序号重启后绝不消失）：
```json
{"protocolVersion":1,"requestId":"req_5f6e7d8c9b0a1f2e3d4c","channelId":"ch_9f8e7d6c5b4a3f2e1d0c","acks":[
  {"messageId":"m_0192f3e4d5c6b7a8","seq":42,"duplicate":false}
]}
```
`seq` 是通道级单调服务端序号（u64，从 1 起，已提交数据无间隙，在追加事务内分配）。

幂等，以 `(channelId, messageId)` 为键：
- 以**字段完全相同**的信封重试（解析后对象相等；JSON 键序无关）：返回原 `seq`，`"duplicate":true`。丢 ACK 后重试安全。
- 同 `messageId` 但任一字段不同：`409 Conflict` `idempotency_conflict`，整批拒绝。批内含冲突信封时整批不提交。

失败示例（`409`）：
```json
{"protocolVersion":1,"requestId":"req_5f6e7d8c9b0a1f2e3d4c","error":{"code":"idempotency_conflict","message":"messageId m_0192f3e4d5c6b7a8 already committed with different content","retryable":false}}
```

## 5. 拉取：分页与游标

请求 `POST /v1/channels/{channelId}/pull`：
```json
{"protocolVersion":1,"requestId":"req_aa00bb11cc22dd33ee44","after":41,"limit":16,"maxBytes":4194304}
```
`after` 是客户端游标（最后持久送达的 `seq`）。`limit` 默认 16，最大 64。`maxBytes` 默认 4 MiB，最大 16 MiB。

成功 `200 OK`：
```json
{"protocolVersion":1,"requestId":"req_aa00bb11cc22dd33ee44","channelId":"ch_9f8e7d6c5b4a3f2e1d0c","entries":[
  {"seq":42,"envelope":{"protocolVersion":1,"groupId":"g_ab12…","senderDeviceId":"dev_phone","keyEpoch":3,"messageId":"m_0192f3e4d5c6b7a8","nonce":"7Je…22chars","ciphertext":"9hK2xQ…"}}
],"nextCursor":42,"hasMore":false}
```

语义：
- `entries` 按 `seq` 升序且**连续**：`entries[0].seq == after + 1`，且每项 seq 为前项 + 1。客户端观察到任何其他排列都视为协议违规：停止、保留持久游标、重新拉取（出现间隙意味着服务端损坏或伪造响应，绝非"可跳过"的数据）。
- `nextCursor` 是最后送达条目的 `seq`；客户端**仅在本地持久应用这些条目之后**才持久化它。
- 空页：`entries: []`、`nextCursor == after`（输入游标不变）、`hasMore: false`。
- `hasMore: true` 表示 `nextCursor` 之后至少还有一条已提交条目；客户端继续拉取。
- `maxBytes` 限制响应的序列化尺寸。若**首个**候选条目单独超限：`400 item_too_large`——显式失败，绝不在空页上循环。
- `limit > 64`：`400 page_too_large`。
- 游标有效性：`after > 末端 seq` → `400 cursor_invalid`（超前于日志的游标意味着数据丢失或伪造游标；服务端绝不静默重置）。畸形游标（非整数、负数）→ `400 cursor_invalid`。"过期游标"在 v1 不可能出现（全量保留、不裁剪）；该码保留给将来的保留/快照引导协议。

失败示例（`400`）：
```json
{"protocolVersion":1,"requestId":"req_aa00bb11cc22dd33ee44","error":{"code":"cursor_invalid","message":"cursor 99999 is ahead of channel head 42","retryable":false}}
```

## 6. 错误模型

所有失败响应都是同一形态：
```json
{"protocolVersion":1,"requestId":"…|null","error":{"code":"…","message":"…","retryable":true|false}}
```

稳定错误码、HTTP 状态与可重试性（冻结；客户端只 switch `code`，绝不依赖 `message`）：

| 码 | HTTP | 可重试 | 含义 |
|---|---|---|---|
| `version_unsupported` | 400 | 否 | `protocolVersion` ≠ 1（请求层或信封层） |
| `bad_request` | 400 | 否 | JSON 畸形、未知字段、缺失字段 |
| `unauthorized` | 401 | 否 | token 缺失/未知 |
| `forbidden` | 403 | 否 | token 有效但角色/权限/通道不符 |
| `channel_not_found` | 404 | 否 | 路径上的通道不存在 |
| `payload_too_large` | 413 | 否 | 单信封超过 4 MiB |
| `batch_too_large` | 413 | 是 | 批内数量 > 16 或总量 > 8 MiB |
| `idempotency_conflict` | 409 | 否 | 同 `(channel, messageId)`、内容不同 |
| `cursor_invalid` | 400 | 否 | 游标畸形或超前于日志 |
| `page_too_large` | 400 | 否 | `limit` > 64 |
| `item_too_large` | 400 | 否 | 首条目超过 `maxBytes` |
| `quota_exceeded` | 507 | 是 | 通道或磁盘预算用尽；读取不受影响 |
| `rate_limited` | 429 | 是 | 请求过频；响应携带 `Retry-After` |
| `room_not_found` | 404 | 否 | 配对房间不存在 |
| `room_full` | 409 | 是 | 房间已有 2 名参与者 |
| `room_expired` | 410 | 否 | 配对房间 TTL 已过 |
| `internal` | 500 | 是 | 服务端未预期错误 |

## 7. WebSocket：配对房间

配对房间让持有同一短码的两台设备经中继交换配对握手帧。中继不透明转发；永不接触短码（短码策略留在设备侧，见 PROTOCOL.md §2）。

创建房间——`POST /v1/pairing/rooms`，无需凭证，按来源 IP 限流：
```json
{"protocolVersion":1,"requestId":"req_room_create_0011"}
```
响应 `201 Created`——能力（capability）仅此一次可见：
```json
{"protocolVersion":1,"requestId":"req_room_create_0011","roomId":"rm_5a6b7c8d9e0f","capability":"7JezN-xQt0Wm9cLpA2bV_w","expiresAt":"2026-11-14T12:02:00Z"}
```
- `capability` 是 128 位新鲜随机数（base64url），**独立于短码**——知道或猜中短码推不出能力，观测到能力也推不出短码。
- 房间 TTL：120 秒（与短码 TTL 默认一致）。至多 2 名参与者。每房间至多 16 次加入尝试，之后房间死亡（`room_expired`）。过期房间被清扫。

加入——`GET /v1/pairing/{roomId}`，`Authorization: Bearer <capability>`，WebSocket 升级。能力**只**走 header，不进 URL。服务端首条消息：
```json
{"protocolVersion":1,"type":"room.joined","roomId":"rm_5a6b7c8d9e0f","peerJoined":false}
```
第二名参与者连上时 `peerJoined` 翻转为 `true`（**不会**重发 `room.joined`）。

帧转发——任一参与者发送：
```json
{"protocolVersion":1,"type":"pairing.frame","data":"<原始配对帧的 base64url>"}
```
服务端以同形态原样转发给另一名参与者。帧是不透明字节 ≤ 16 MiB（core 的 `MAX_FRAME_BYTES`；中继在读取时、分配前执行上限）。其他任何 `type`、未知字段或超限帧以 1008 关闭连接。

关闭码（冻结）：`4401` 能力无效；`4404` 房间不存在；`4409` 房间已满（第三名参与者）；`4410` 房间过期或尝试次数用尽；`1011` 内部错误。以 44xx 关闭前，服务端先发一条 `error` 消息（`{"protocolVersion":1,"type":"error","code":"room_expired","message":"…"}`）。

心跳：服务端每 30 秒 ping；连接空闲 > 90 秒（无 pong、无帧）以 1001 关闭。退出时在排空在途帧后以 1001 关闭房间。

## 8. WebSocket：通道更新通知

`GET /v1/channels/{channelId}/events`，持 `pull` 权限凭证，WebSocket 升级。服务端首条消息：`{"protocolVersion":1,"type":"events.subscribed","channelId":"…"}`。该通道每次提交追加后，服务端推送一条**提示**：
```json
{"protocolVersion":1,"type":"channel.appended","channelId":"ch_9f8e7d6c5b4a3f2e1d0c","seq":43}
```
通知按设计可有损：丢失或漏掉提示毫无损失——客户端将其视为"可能有变化，从游标拉取"。（重）连后客户端总是按游标拉取；订阅本身不携带状态。被撤销凭证的事件流在下次心跳或推送尝试时被服务端以 4401 关闭。心跳/空闲规则同 §7。

浏览器客户端必须携带与所配 `allowedOrigins` 匹配的 `Origin` 头；其他来源在升级时以 403 拒绝。非浏览器客户端（无 Origin）不受影响。

## 9. 上限与默认值（v1 冻结）

服务端可配置更低值；超过最大值的一切不被接受。

| 项 | 默认 | 最大 | 说明 |
|---|---|---|---|
| 单信封 | — | 4 MiB 序列化 | `payload_too_large` |
| 追加批数量 | — | 16 | `batch_too_large` |
| 追加批字节 | — | 总计 8 MiB | `batch_too_large` |
| pull `limit` | 16 | 64 | `page_too_large` |
| pull `maxBytes` | 4 MiB | 16 MiB | 首条目超限时 `item_too_large` |
| 请求 body | — | 16 MiB | 服务级上限，增量读取 |
| `requestId` | — | 64 字符 | ≥ 1 字符 |
| `channelId` | — | 128 字符 | 服务端分配 |
| 房间能力 | 128 位 | — | base64url，仅此一次可见 |
| 房间 TTL | 120 秒 | — | 固定，与短码 TTL 默认一致 |
| 房间参与者 | — | 2 | 超出 `room_full` |
| 房间加入尝试 | — | 每房间 16 次 | 之后 `room_expired` |
| 房间创建速率 | 16 次/分/IP | — | `rate_limited` |
| 配对帧 | — | 16 MiB | core `MAX_FRAME_BYTES`，读取时执行 |
| WS 心跳 | 30 秒 ping | — | 空闲 > 90 秒 → 关闭 |
| 追加速率 | 每凭证 32 req/s | 突发 64 | `rate_limited` + `Retry-After` |
| 拉取速率 | 每凭证 32 req/s | 突发 64 | `rate_limited` + `Retry-After` |
| 通道配额 | 1 GiB | — | `0` 关闭；仅追加报 `quota_exceeded` |
| 磁盘配额 | 8 GiB | — | `0` 关闭；配额永不阻断读取 |
| 保留策略 | 全量保留 | — | v1 不裁剪；保留策略需要新的游标/引导协议 |
| 序号 | 每通道 u64 | — | 从 1 起、无间隙、追加事务内分配 |
| 监听地址 | `127.0.0.1:8080` | — | 公开暴露须经 TLS 反向代理 |
| 数据库 | SQLite WAL，`synchronous=NORMAL` | — | ack ⇒ 已提交 |

## 10. 场景示例

**追加、丢失 ACK、安全重试。**
1. 客户端 POST 一个 3 信封批 → 响应返回前连接断开。
2. 客户端逐字节重发同一请求（`requestId` 相同无妨；信封相同）。
3. 服务端：每个信封命中 `(channel, messageId)` 幂等记录 → `200`，原三个 seq，全部 `duplicate: true`。不会重复存储；读取者看不到重复（pull 每个信封只在其原 seq 返回一次）。

**客户端落后，追平。**
1. 客户端持久游标 41；末端 87；`after: 41, limit: 16` 拉取 → 条目 42–57，`nextCursor: 57`，`hasMore: true`。
2. 客户端持久应用条目、持久化游标 57、再拉 → 58–73……直到某页 `hasMore: false`。
3. 追平途中到达的通知提示不改变任何行为：下一次 pull 已覆盖它。

**被篡改的批次被原子拒绝。**
1. 2 信封批，其中 #2 形态校验失败（未知字段 `ttl`）。
2. 服务端整请求拒绝 `400 bad_request`；信封 #1 **不**提交——不存在部分提交的批。

**被撤销的设备。**
1. 管理员撤销 `cred_phone`；该设备已建立的事件流在下次推送尝试时以 4401 关闭。
2. 该设备的下一次 `/append` → `401 unauthorized`（摘要已删）。其他设备凭证不受影响；其事件流与追加照常。

## 11. v1 范围之外

服务端合并、明文可见性、租户/计费模型、中继间联邦、P2P 传输、保留/裁剪、多通道扇出都在本契约之外。变更任何冻结字段、错误码、路由或上限都需要中继契约 v2 并遵循同样的硬版本拒绝规则。
