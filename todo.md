# todo

来源：用户 2026-10-21 立项令及同日两次修正。定位：accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure SDK。核心原则：SDK 不理解、不解释、不决定业务数据含义。需求基线：`docs/requirements.md`（R1.1–R11.4）。

优先级：协议安全与收敛正确性 → 可嵌入 API → WebSocket 中继 → LAN 发现 → P2P/Iroh → 平台集成。

## P1 — 协议安全与收敛正确性（初始基线完成）

以下勾选记录原始验收范围，不表示覆盖全部恢复/收敛情形。2026-11-14 复核新增的阻断项 DSR-01–DSR-06 已全部关闭（见「默认服务器实施计划」）。

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

- [x] 持久化可续传中继存储：跨重启恢复 + 游标续传，两端经中继收敛（证据：commit 27c139d；tests 37）。范围为明文 Operation 存储原型；不包含可部署网络服务器，默认服务器另见 DSR 计划。
- [x] napi-rs TypeScript 绑定：TS 侧 pair/sync 全流程（证据：commit d946274；cargo tests 37；TS tests 4）
- [x] 成员移除触发 keyEpoch 轮换 + 新钥分发，被移除设备解不开任何轮换后信封（证据：commit 9839ccc；tests 8）
- [x] 墓碑 GC：时间阈值 + 因果支配，GC 后旧写入不复活删除（证据：commit 3fdc056；tests 8）
- [x] 跨版本协商——不支持，维持精确版本匹配硬失败（证据：已代决 2026-10-28，见 docs/review/2026-10-30-decisions.md）
- [x] LAN 发现（mDNS）：feature 门控默认 off，mock 可测（证据：commit 91471b3；tests 4）
- [x] P2P/Iroh 传输评估：打洞成功率与中继回退路径（证据：commit a202763；docs/research/p2p-iroh-assessment-2026-10-28.md）
- [x] 墓碑仅时间阈值裁剪——不开放给应用，保留内部/测试专用（证据：已代决 2026-10-28，见 docs/review/2026-10-30-decisions.md）

## 默认服务器实施计划（2026-11-14，全部待实现）

设计：[默认中继服务器](docs/zh/design/default-server.md)（[English](docs/design/default-server.md)）。关联需求 R4/R6/R7.3–R7.4/R9/R10/R11。目标为可选自托管服务器，不是官方公共托管服务；已有 nightly/npm 发布约束不变。

每个任务对应一个可独立评审的结果；括号内为前置任务与验收条件。编号用于追踪，不要求没有依赖的任务串行。完成时在该条补提交与验证证据，不只勾选。新增目录均为规划，不在本次文档更新中创建实现。

### A. P0 — 复制正确性前置阻断项

- [x] **DSR-01** 修复普通远端操作持久化遗漏（无前置；验收：接收远端 put/delete 后保存并恢复，值、墓碑及去重结果完整保留；回归用例进仓库）（证据：crates/syncbond-core/tests/dsr_data_integrity_tests.rs:55；tests 1）。
- [x] **DSR-02** 明确并实现远端操作转发日志（依赖 DSR-01；验收：A→B→C 传播保留原 op_id，重复转发幂等，B 重启后仍可转发）（证据：crates/syncbond-core/tests/dsr_data_integrity_tests.rs:100；tests 1）。
- [x] **DSR-03** 在复制接收路径接入 HLC 推进（无前置；验收：接收合法远端戳后的本地写入在因果后继上严格递增，异常未来戳不污染本地时钟）（证据：crates/syncbond-core/tests/dsr_data_integrity_tests.rs:139；tests 1）。
- [x] **DSR-04** 持久化并恢复 HLC 高水位（依赖 DSR-03；验收：同毫秒重启及墙钟回拨后戳不重复，新写入成功可读，兼容旧快照或显式拒绝不兼容版本）（证据：crates/syncbond-core/tests/dsr_data_integrity_tests.rs:193,215,258；tests 3）。
- [x] **DSR-05** 修复 LWW 因果合并的顺序依赖（依赖 DSR-03；验收：A=1000、B=900 且 B 观察 A、C=950 独立写入的所有投递排列得到同一主值及规范化冲突集合；加入同 key 多节点性质测试）（证据：crates/syncbond-core/tests/dsr_data_integrity_tests.rs:296,423；tests 2）。
- [x] **DSR-06** 修复时钟偏移处理的顺序依赖（依赖 DSR-05；验收：异常未来操作先到/后到结果一致，空记录路径同样执行策略，异常记录保持可追踪而不静默覆盖）（证据：crates/syncbond-core/tests/dsr_data_integrity_tests.rs:459,505；tests 2）。

### B. P1 — 冻结契约与目录边界

- [x] **DSR-07** 冻结 relay v1 传输契约（无前置；验收：在设计文档列出准确 HTTP 路由、WebSocket 消息、鉴权、版本、错误码、提交 ACK、分页/幂等/游标语义和各类默认/最大限制，并附成功与失败示例）（证据：docs/design/relay-protocol.md + docs/zh/design/relay-protocol.md（路由/WS/鉴权/版本/错误码/ACK/分页/幂等/游标/§9 上限表/§10 示例）；docs-site 导航接入；default-server.md §4 指向该契约）。
- [x] **DSR-08** 对齐加密信封实际 JSON 与 Schema（依赖 DSR-07；验收：命名与未知字段策略一致，真实序列化信封通过 Schema 检查，记录旧 snake_case 格式的迁移/版本处理，更新双语协议文档）（证据：crates/syncbond-core/src/crypto.rs:36（camelCase + deny_unknown_fields + snake_case 别名）；crates/syncbond-core/tests/envelope_wire_tests.rs:29 等 5 测试（真实信封过 schemas/envelope.schema.json、旧格式兼容、未知/缺失字段拒绝）；PROTOCOL.md §4 双语迁移记录）。
- [x] **DSR-09** 创建 `crates/syncbond-relay-protocol`（依赖 DSR-07、DSR-08；验收：共享 DTO/错误/大小上限及契约 fixture 可编译测试，不依赖应用服务器、合并实现或异步运行时）（证据：crates/syncbond-relay-protocol（src/lib.rs:33 版本、src/limits.rs:36 上限与校验、src/error.rs 错误码映射、src/dto.rs 闭形状 DTO、fixtures/ 11 份契约 fixture）；19 测试（11 lib + 8 fixture，含真实 core 信封往返与 schema 校验），仅依赖 serde/thiserror）。
- [x] **DSR-10** 定义密文中继存储接口（依赖 DSR-09；验收：仅接收信封和路由元数据，明确事务/幂等/分页错误语义，Memory/FileRelayStore 原型不被误用于默认网络服务）（证据：apps/syncbond-server/src/storage.rs:1-18 模块文档钉死「仅 channel id + [Envelope]、不得解密/合并/解释，Memory/FileRelayStore 为明文原型不可作默认网络服务存储」；:32 StorageError 唯一错误面（RelayErrorCode 新类型，Display/Error 手工实现）、:69 RelayStorage trait（head/append/pull 三签名，事务全有或全无、字节与条数双界分页、游标仅推进到实际交付末项）；tests 2（storage.rs:102,114））。
- [x] **DSR-11** 创建 `apps/syncbond-server` 独立 binary crate（依赖 DSR-09；验收：注册 workspace，启动/配置校验/退出入口可运行，记录网络库选择与锁定版本，core 无反向网络或运行时依赖）（证据：Cargo.toml:4 已注册 workspace member；apps/syncbond-server/src/main.rs:33-48 启动→run→退出码（无参数打印 usage 并返回 2，配置失败返回 FAILURE）；网络库选择记录于 src/main.rs 模块文档 axum 0.8(ws)/tokio 1.x/rusqlite 0.42(bundled, WAL)，版本锁定于 workspace Cargo.toml（Cargo.lock 钉 1.54.1/0.42.0/0.8）；apps/syncbond-server/src/config.rs:12-31 Config 闭形状 camelCase+deny_unknown_fields、:80-118 validate（loopback 默认 127.0.0.1:8080、dataDir 空/根目录拒绝、配额 0 或非<4MiB 拒绝、allowedOrigins 空白拒绝）；core 无反向依赖（crates/syncbond-core/Cargo.toml 无 syncbond-server/axum/tokio）；tests 6（config.rs:122,135,145,184 + storage.rs:102,114）+1 集成（main.rs:59））。

### C. P1 — 服务器存储与访问控制

- [x] **DSR-12** 实现 SQLite 初始化与版本迁移（依赖 DSR-10、DSR-11；验收：通道、凭证摘要、密文、序号/幂等索引落盘；空库初始化及重复启动成功，损坏/未知版本启动失败且不清空数据）（证据：apps/syncbond-server/src/sqlite.rs:40-61 SCHEMA v1（channels 注册表 / credentials 仅 SHA-256 摘要+scope+revoked_at / envelopes (channel,seq) 主键 + UNIQUE(channel,message_id) 幂等索引 + payload 原样密文 JSON）；:38 SCHEMA_VERSION=1 + PRAGMA user_version 严格上迁（:127-148 migrate：0=建库置版本、>1=UnknownVersion 硬拒、永不删改既有库）；:66-83 StoreOpenError 三变体（Io/Sqlite 损坏/UnknownVersion，全部不触碰库文件）；:88-95 SqliteRelayStore=Mutex<Connection>（rusqlite Connection Send 非 Sync，RelayStorage 要求 Send+Sync 供 DSR-19+ axum 多线程共享）；:109-121 open=WAL+foreign_keys ON+fail-closed；storage.rs head() 真实现（COALESCE(MAX(seq),0)，i64→u64 防负值腐败）；main.rs run() 装配序 config→storage（dataDir/relay.db）；tests 4（sqlite.rs:236 fresh+重复启动+user_version=1、:254 落盘跨重启、:270 损坏拒绝且文件字节不变、:287 未知版本拒绝且 3 行数据仍在）；cargo test -p syncbond-server 11 通过，workspace clippy -D warnings 绿）。
- [x] **DSR-13** 实现事务密文追加与持久 ACK（依赖 DSR-12；验收：同 ID 同信封返回原序号、异内容冲突；注入提交失败不产生成功 ACK 或可读脏状态，重启保留已确认记录）（证据：apps/syncbond-server/src/sqlite.rs append()=BEGIN IMMEDIATE 单事务（写锁前置，序号窗口不可被并发作废）：通道存在性先查→ChannelNotFound；同 ID 同 payload→原 seq+duplicate:true（幂等重试不烧号，后续新消息接 next）；同 ID 异 payload→整批回滚+IdempotencyConflict；循环中任一失败经 drop 自动 ROLLBACK，ACK 仅在 commit 成功后构造返回=无提交无 ACK；payload=serde_json 序列化 Envelope 原样存；空批=no-op 不查通道；head() 真实现供游标比对；tests 7（:391 连续序号、:415 重试取原序号不烧号、:446 异内容冲突无副作用、:466 注入批内冲突整批原子回滚无脏行、:492 未知通道拒写、:504 重启保留+重启后仍幂等、:538 空批）；cargo test -p syncbond-server 18 通过，workspace clippy -D warnings 绿）。
- [ ] **DSR-14** 实现按条数和字节限制的分页读取（依赖 DSR-13；验收：游标仅推进到实际交付末项，空页不跳游标，单条超限/无效游标显式报错，序号间隙不漏读，hasMore 正确）。
- [ ] **DSR-15** 实现管理凭证与通道创建（依赖 DSR-12；验收：无管理授权不能创建通道，不使用硬编码或开发默认密钥，凭证不出现在 URL/日志）。
- [ ] **DSR-16** 实现每设备/通道访问凭证签发与校验（依赖 DSR-15；验收：仅存凭证摘要，读写权限分别校验，跨通道、错误及缺失凭证拒绝）。
- [ ] **DSR-17** 实现服务访问凭证撤销（依赖 DSR-16；验收：重启后撤销仍有效，既有连接的后续访问也被拒绝，其他设备权限不受影响）。
- [ ] **DSR-18** 实现存储配额（依赖 DSR-13；验收：达到配置的通道/磁盘预算后明确拒绝追加，已存数据仍可读取，初版不自动裁剪历史）。

### D. P1 — 网络服务

- [ ] **DSR-19** 暴露控制、追加与分页 HTTP 接口（依赖 DSR-14、DSR-16；验收：真实 socket 请求覆盖成功、版本不匹配及稳定错误映射，健康/就绪端点反映服务状态）。
- [ ] **DSR-20** 实现短期配对房间（依赖 DSR-11、DSR-16；验收：至少 128 位随机房间能力值、最多两端、TTL 清理及加入限流；不接收或持久化短码）。
- [ ] **DSR-21** 实现 WebSocket 配对帧转发（依赖 DSR-20；验收：两端正确路由，第三端/跨房间拒绝，断开及过期通知双方，绑定浏览器 Origin 与代理信任策略）。
- [ ] **DSR-22** 实现 WebSocket 更新通知（依赖 DSR-13、DSR-16；验收：仅提交成功才通知有权设备，通知丢失不影响通过 pull 恢复，撤销凭证断开订阅）。
- [ ] **DSR-23** 实现网络资源上限与超时（依赖 DSR-19、DSR-21、DSR-22；验收：读取/组装前限制帧与请求体，有界队列、连接上限、速率限制、心跳/读写超时；慢端与巨帧得到有界失败）。
- [ ] **DSR-24** 实现服务优雅退出（依赖 DSR-13、DSR-19、DSR-22；验收：停止接入新请求，限定时间处理已接收提交，退出重启后所有已 ACK 密文可拉取）。

### E. P1 — Rust 客户端闭环

- [ ] **DSR-25** 提供非阻塞配对状态机驱动接口（无前置；验收：输入/输出协议帧可由外部事件循环驱动，复用现有 SPAKE2/签名逻辑，不复制密码协议；原 Transport 接口行为保持可测）。
- [ ] **DSR-26** 将短码策略接入配对编排（依赖 DSR-25；验收：真实配对入口执行单次使用、TTL、限次与格式归一；过期、消费过和锁定的码不能再次建立会话）。
- [ ] **DSR-27** 实现 `crates/syncbond-transport-ws` 配对适配（依赖 DSR-09、DSR-21、DSR-25、DSR-26；验收：注入已有设备身份，两个独立进程经房间完成配对，TLS 校验、取消及超时有效，同步核心通过有界桥接接入）。
- [ ] **DSR-28** 实现有界操作批次加密与解码（依赖 DSR-02、DSR-08、DSR-09；验收：只把加密信封交给 relay，单批符合网络限制，大日志拆批，不依赖完整 oplog 单帧发送）。
- [ ] **DSR-29** 实现持久 outbox 与 ACK 确认（依赖 DSR-13、DSR-19、DSR-28；验收：发送前可恢复，确认丢失重发不重复追加，服务器提交前不删除待发送数据）。
- [ ] **DSR-30** 实现接收状态与服务器游标原子提交（依赖 DSR-01、DSR-04、DSR-14、DSR-19、DSR-28；验收：操作、去重、HLC 与接收游标一致落盘，提交失败重启不跳过数据；服务器/来源/本地序号分离）。
- [ ] **DSR-31** 实现分页续传与断线重连驱动（依赖 DSR-22、DSR-29、DSR-30；验收：有界退避与取消，重连从已提交游标恢复，通知漏收时仍补齐，断线不丢未 ACK 数据）。
- [ ] **DSR-32** 接入成员撤销的新密钥安全分发（依赖 DSR-17、DSR-27、DSR-28；验收：经存活设备各自安全通道分发新钥，明确两设备配对加入已有组的授权流程，监听中继的被撤销端不能取得新钥；保持应用显式触发轮换）。
- [ ] **DSR-33** 提供 Rust 双进程示例（依赖 DSR-06、DSR-24、DSR-27、DSR-31；验收：从空目录启动服务器、两个独立客户端身份及存储，完成配对、离线写入与重启同步，脚本退出并报告失败）。

### F. P2 — 多语言接入（逐个验收）

- [ ] **DSR-34** 扩展 C ABI 外部帧配对接口（依赖 DSR-25、DSR-26；验收：已有身份可分别启动两端，定义帧驱动/取消/所有权与错误语义，纯 C 测试跑真实分离的两端）。
- [ ] **DSR-35** 扩展 C ABI 复制状态保存与恢复接口（依赖 DSR-30；验收：导出/导入完整已提交状态及游标，有版本与输入校验，恢复后不丢远端数据；标注快照含私密材料）。
- [ ] **DSR-36** 为绑定提供 C ABI 中继客户端驱动（依赖 DSR-31、DSR-34、DSR-35；验收：可配置 URL/凭证并启动、停止和查询进度，无需各绑定重写协议，线程/回调资源生命周期明确）。
- [ ] **DSR-37** 接入 Node 绑定网络同步（依赖 DSR-36；验收：两个 Node 进程经服务器同步并恢复，阻塞工作不占用 JS 主线程，错误正确映射）。
- [ ] **DSR-38** 接入 Python 绑定网络同步（依赖 DSR-36；验收：两个 Python 进程经服务器同步并恢复，网络等待释放 GIL，取消与资源关闭有效）。
- [ ] **DSR-39** 接入 Go 绑定网络同步（依赖 DSR-36；验收：两个 Go 进程经服务器同步并恢复，关闭无句柄泄漏，CGO_ENABLED=0 继续显式报不支持）。
- [ ] **DSR-40** 接入 Java 绑定网络同步（依赖 DSR-36；验收：两个 JVM 进程同步并恢复，JNI 生命周期及异常映射可验证）。
- [ ] **DSR-41** 接入 C# 绑定网络同步（依赖 DSR-36；验收：两个 .NET 进程同步并恢复，取消、Dispose 与托管/原生资源释放可验证）。
- [ ] **DSR-42** 接入 C++ 包装网络同步（依赖 DSR-36；验收：两个 C++ 进程同步并恢复，RAII 正确释放新资源，示例在现有告警门禁下编译）。
- [ ] **DSR-43** 暴露 WASM 单线程网络同步核心接口（依赖 DSR-25、DSR-26、DSR-28、DSR-30；验收：已有身份导入/导出、配对帧驱动、远端操作处理及完整状态恢复可在 wasm32 执行，无线程依赖）。
- [ ] **DSR-44** 接入浏览器 WebSocket 与 IndexedDB 驱动（依赖 DSR-31、DSR-43；验收：两个独立浏览器上下文配对同步并刷新恢复，持久化失败不推进游标，无 IndexedDB 时显式降级）。

### G. P1/P2 — 验收、部署与持续验证

- [ ] **DSR-45** 固化真实网络恢复验收套件（依赖 DSR-33；验收：覆盖双向离线修改、乱序/重复投递、两端/服务器重启、ACK 丢失、分页边界及提交故障，失败进程与端口可靠清理）。
- [ ] **DSR-46** 固化授权与撤销验收套件（依赖 DSR-32；验收：未授权、跨通道、撤销后既有连接拒绝；被撤销端监听分发流量仍无法解开后续数据）。
- [ ] **DSR-47** 固化服务器密文边界验收（依赖 DSR-32、DSR-33；验收：真实数据/轮换链路的数据库、日志与应用层流量不含已知明文载荷、短码和组密钥）。
- [ ] **DSR-48** 固化资源与关闭验收套件（依赖 DSR-18、DSR-23、DSR-24；验收：巨帧、慢客户端、队列饱和、配额耗尽及中途关闭行为有界且可重复验证）。
- [ ] **DSR-49** 提供服务器 Dockerfile（依赖 DSR-24；验收：构建独立服务镜像，非 root 运行，可配置数据卷和健康检查，不内置凭证）。
- [ ] **DSR-50** 提供 Compose 与配置示例（依赖 DSR-49；验收：从空目录一条命令启动并通过健康检查，数据卷跨容器重建保留，凭证由外部提供，明文监听仅限本地开发）。
- [ ] **DSR-51** 编写双语运行维护指南（依赖 DSR-45、DSR-46、DSR-47、DSR-48、DSR-50；验收：启动、TLS 代理、Origin/代理信任、凭证、配额、备份恢复和升级步骤可照做，源码文档与文档站同步，更新 README 状态）。
- [ ] **DSR-52** 将服务器网络验收接入 CI（依赖 DSR-45、DSR-46、DSR-47、DSR-48、DSR-50；验收：干净环境自动启动服务并运行套件，超时失败、保留脱敏日志、不依赖公网或已有数据库，不改变稳定版发布授权）。
- [ ] **DSR-53** 将各绑定真实网络验收接入 CI（依赖 DSR-37–DSR-42、DSR-44、DSR-52；验收：逐语言运行独立进程/上下文测试，各自报告结果，不以共用 conformance runner 代替真实网络 API 验收）。

## P3 — 发布（阻断项未清不动）

- [x] 最终品牌名——**已定**：沿用 syncbond 为正式名（2026-11-05 用户拍板，不再改名；改名工作线取消，无需执行；crates.io 六名截至检查时未占用（按先到先得分配，本检查不保证取得），README 中英「临时名」口径已改为正式名）
- [ ] npm 发布——BLOCKED：用户输入（维持不发布稳定包；`npm whoami` ENEEDAUTH，`@cuihairu` scope 待用户登录确认；发布令+版本号只能由用户给；复核 2026-11-04：`npm whoami` 仍 ENEEDAUTH，保留 BLOCKED；复核 2026-11-05：`npm whoami` 仍 ENEEDAUTH，保留 BLOCKED；复核 2026-11-06：`npm whoami` 仍 ENEEDAUTH，保留 BLOCKED；复核 2026-11-09：`npm whoami` 仍 ENEEDAUTH，保留 BLOCKED；复核 2026-11-10：`npm whoami` 仍 ENEEDAUTH，保留 BLOCKED）
- [x] 每日构建（nightly）——已完成（2026-11-14，任务书 ~/.hermes/cache/scratch/tasks/syncbond-nightly.md）：`.github/workflows/nightly.yml` 滚动 nightly（48h 无新 commit 即 skip 门禁；CI 同口径测试门禁：fmt+clippy+`cargo test` 全绿才出包；产物 = core musl 静态库 x86_64/aarch64（`syncbond-nightly-<target>.tar.gz`，含头文件+BUILD_INFO）、Python wheel（maturin，装包跑 pytest 面）、N-API prebuilt（napi build）、WASM 包（wasm-pack）；滚动 `nightly` prerelease + SHA256SUMS，照 meshlet 口径；README 双语夜间节）。**nightly ≠ npm 正式发布：npm 上架维持 BLOCKED（上一行），正式版本号发布仍只能由用户手动给出并触发**

## 待拍板项（用户决策）

1. npm 发布策略——已代决：维持不发布，待用户输入（2026-10-30）
2. 最终品牌名——已定：沿用 syncbond 为正式名（2026-11-05 用户拍板；2026-10-30 旧口径已更新）
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
- [x] 审核发现：`sync_over` 发送侧无帧大小守卫——`seal_and_send(encode(&oplog))` 将整段 oplog 打包为一帧，oplog 超过 `MAX_FRAME_BYTES`（16 MiB）时本端无检查即发出、对端 `recv_and_open` 必拒「frame too large」，功能级失败且错误信息误导（对端视角），无分块/发送侧上限检查；帧上限仅收侧守卫（证据：`seal_and_send` 组帧后加 `frame.len() > MAX_FRAME_BYTES` 即拒（发送侧本地报错，不再发给对端）；新增 `seal_and_send_rejects_oversized_payload_before_sending` 测试（无守卫时对端视角失败，有守卫后本地拒绝且小载荷仍可收发）；cargo test 82 全绿；commit 5d6399d）

## 漏洞扫描遗留（2026-11-03 全舰队扫描，源 scratch/vuln-scan-*.md）

- [x] VULN-SYNCB-001 [中危·RUSTSEC-2026-0387] crypto-bigint 0.5.5→0.7.6+【跨大版本需改代码】：由 elliptic-curve 0.13/p256 或 rsa 0.9 锁定；验收：cargo audit 该 ID 清零 + cargo test 绿（证据：Cargo.lock crypto-bigint 0.7.10；cargo audit exit 0/147 deps 无漏洞；cargo test --workspace 全绿）
- [x] VULN-SYNCB-002 [高危·GHSA-587h-7wmj-h5pm 路径穿越] vite 5.4.21→6.4.4【跨大版本（override 强制 5→6）·补跑任务】：pnpm-workspace.yaml 的 `vite@<6.4.4: 6.4.4` override 在扫描窗口被并发进程回退 3 次；本任务复核 override 已不在、lock 仍为 vite@5.4.21；验收：override 落盘 + pnpm audit --audit-level=high 中 vite 不再命中 + pnpm -r test 绿（9/9）（证据：pnpm-workspace.yaml override vite:6.4.4 落盘；pnpm-lock.yaml vite@6.4.4；pnpm audit --audit-level=high 高危清零；pnpm -r test 9/9 绿；docs:build 通过）

## 审核发现（2026-11-03 第五轮，diff 303a2623..HEAD 共 15 提交/9 文件）

覆盖范围：逐提交逐文件审毕（codes.rs、hlc.rs、pairing.rs、relay.rs、transport.rs、member_rotation_tests.rs、pairing_tests.rs、relay_persistence_tests.rs）；`cargo test -p syncbond-core --lib`（15 绿）及三集成测试二进制（member_rotation 12、pairing 13、relay_persistence 2）全绿。已记录于上文各轮的发现在此轮 diff 内未见复发（codes 阈值 248/is_accepting 归一、transport send/try_recv 中毒恢复、issue 饱和、relay 裸路径、并发同 id open、seal_and_send 发送侧守卫均已按证据闭合）。以下为本轮发现：

- [x] 审核发现：codes.rs 模块注释「≈ 30.7 bits of entropy (31^6)」数值错误——log2(31^6)=log2(887,503,681)=29.725，应为 ≈29.7 bits；与同文件「4.954 bits/字符 ×6 = 29.72」自相矛盾，PROTOCOL.md:21 亦为 29.4 口径（crates/syncbond-core/src/codes.rs:4）（证据：crates/syncbond-core/src/codes.rs:4 改为 ≈29.7 bits；cargo test -p syncbond-core 82 全绿）
- [x] 审核发现：提交 97ba6e2 将 codes.rs 注释「30 符号→31 符号」并修正阈值，但 docs/design/PROTOCOL.md:21/47/53 仍「30 unambiguous symbols / ≈29.4 bits / 30^6 = 729,000,000」——codes.rs:5 明确以该文档为 online-guessing 分析出处，文档与实现口径脱节；且 :47 所列字母串 `23456789…WXYZ` 实为 31 字符却称 30 符号，内部自相矛盾；修复未传播（docs/design/PROTOCOL.md:21、47、53）（证据：4 份 PROTOCOL.md 拷贝改为 31 symbols/≈29.7 bits/31^6=887,503,681；docs:build 通过；无残留 30 符号口径）
- [x] 审核发现：`rejection_threshold_is_multiple_of_alphabet` 测试硬编码 248，与 `generate_code` 的阈值 248 各自独立、无共享常量——若实现改回有偏值（如 240）该测试仍绿，未真正守卫阈值与模偏差；应提取共享常量或统计 `generate_code` 输出分布（crates/syncbond-core/src/codes.rs:63、179）（证据：提取 `REJECTION_THRESHOLD` 并由实现/测试共用；测试补断言最大 31 倍数；cargo test -p syncbond-core 82 全绿）
- [x] 审核发现：`issue()` 改 `saturating_add(1)` 只保单调不减、不保唯一——`receive` 吸收恶意/异常远端 `(pt≈now, ct=u64::MAX)` 后，同一 wall-ms 内连续两次 `issue()` 返回相同 `(pt, u64::MAX, id)` 戳，破坏 `HlcStamp`「totally ordered and unique」不变量（hlc.rs:14）；新测试仅 issue 一次未覆盖重复戳，注释「saturating keeps monotonic uniqueness」失实（crates/syncbond-core/src/hlc.rs:81-83、150）（证据：`advance()` 进位辅助改为 ct=MAX 时 pt+1/ct=0；receive/issue 三处统一；测试覆盖连续两次 issue 唯一且严格递增；cargo test -p syncbond-core 82 全绿）
- [x] 审核发现：relay.rs 裸相对路径修复用 `.filter(|p| !p.as_os_str().is_empty())` 整段跳过目录 fsync，而非把空父路径映射到 `.`（`File::open(".")` 在 Linux 可 sync）——裸路径（如 `"state.json"`）下 e11824f 引入的 rename 持久性保证静默失效，落盘耐久与否仅由路径形态决定，行为不对称（crates/syncbond-core/src/relay.rs:150-154）（证据：空父路径映射到 `.` 统一目录 fsync；durable_relay_accepts_bare_relative_path 通过；cargo test -p syncbond-core 82 全绿）
- [x] 审核发现：本轮将 `send`/`try_recv` 与 `recv` 统一为锁中毒恢复（`unwrap_or_else(|p| p.into_inner())`），但同文件 `close_pair` 仍 `inbox.lock().unwrap()`——持锁线程 panic 后 `close_pair` 仍永久 panic，中毒恢复惯例在类内未完全一致（crates/syncbond-core/src/transport.rs:79）（证据：close_pair 改用 `unwrap_or_else(into_inner)`；新增 close_pair_recovers_poisoned_lock 测试；cargo test -p syncbond-core 83 全绿）
- [x] 审核发现：`durable_relay_accepts_bare_relative_path` 用 `env::set_current_dir` 改动进程级 CWD——测试二进制各测试默认并行运行，CWD 为进程全局态；现仅因另一测试用绝对临时路径才未串扰，若任一并行测试用相对路径或本测试在 `set_current_dir(temp)` 后、`set_current_dir(cwd)` 恢复前中断（catch_unwind 外 panic），将污染同进程其他测试（crates/syncbond-core/tests/relay_persistence_tests.rs:66、74）（证据：CwdGuard RAII 恢复 CWD + CWD_LOCK 串行化；cargo test -p syncbond-core 83 全绿）

## 审核发现（2026-11-04 第六轮复核，diff 303a2623..HEAD 共 15 提交/9 文件）

覆盖范围：逐提交逐文件复核（codes.rs、hlc.rs、pairing.rs、relay.rs、transport.rs、member_rotation_tests.rs、pairing_tests.rs、relay_persistence_tests.rs）；`git diff --stat` 与第五轮一致（9 文件/+230/−13），HEAD 未再前移，本轮与第五轮同区间。已逐条对照当前代码复核第五轮 7 条发现：**全部仍然成立**（codes.rs:4「30.7 bits」数值错、PROTOCOL.md:21/47/53 仍「30 符号/29.4 bits/30^6=729,000,000」、codes.rs:176-181 rejection 测试硬编码 248 与实现无共享常量、hlc.rs:83 issue() 饱和后同 ms 重复戳、relay.rs:150-154 裸路径整段跳过 fsync、transport.rs:79 close_pair 仍 `lock().unwrap()`、relay_persistence_tests.rs:66/74 `set_current_dir` 改进程级 CWD）。以下为本轮新增发现（均低危，不影响第五轮结论）：

- [x] 审核发现：`seal_and_send` 先 `crypto::seal`（加密整段 plaintext）并 `serde_json::to_vec(&envelope)`（整体序列化/分配）之后才做 `frame.len() > MAX_FRAME_BYTES` 检查——发送侧守卫只挡「不发出」，不挡「不加密/不分配」；调用方传超大 plaintext 时先付出全部加密与内存（plaintext + 编码膨胀）才被拒，守卫时机偏晚；建议组帧前先对 `plaintext.len()`（或上界）预检（crates/syncbond-core/src/pairing.rs:78-96）（证据：加密前加 `plaintext.len() > MAX_FRAME_BYTES` 预检；测试改传 MAX_FRAME_BYTES+1 走预检；cargo test -p syncbond-core 83 全绿）
- [x] 审核发现：`generate_code` 采样路径无分布测试——现有覆盖只有 `rejection_threshold_is_multiple_of_alphabet` 的算术断言（`248 % 31 == 0`），从未调用 `generate_code` 验证 31 个符号均可达、输出等概率；实现若在循环/下标处引入新偏差（如错用 `% 30` 或改阈值）该测试仍绿；建议对 `generate_code` 输出做大样本频次统计断言（crates/syncbond-core/src/codes.rs:53-68、176-181）（证据：新增 generate_code_reaches_every_symbol_uniformly（31 符号可达、10% 容差等概率、码长校验）；cargo test -p syncbond-core 84 全绿）
- [x] 审核发现：HLC 进位函数 `advance` 在 `pt==u64::MAX && ct==u64::MAX` 时 `pt.saturating_add(1)` 停在 u64::MAX，返回 `(u64::MAX, 0)` 与前一戳 `(u64::MAX, u64::MAX)` 相等/回退，破坏注释宣称的「totally ordered and unique even under counter saturation」；`issue_after_saturated_receive_stays_unique` 仅测 `pt=10_000`，未覆盖 pt 饱和（crates/syncbond-core/src/hlc.rs:45）（证据：`advance` 在 pt==ct==u64::MAX 时原地饱和不再回退 ct；注释补绝对边界说明；新增 advance_saturates_at_absolute_max 与 advance_at_absolute_max_never_regresses（u64::MAX 全饱和 receive/issue 单调不回退）；cargo test -p syncbond-core 88 全绿）
- [x] 审核发现：`seal_and_send` 预检用 `plaintext.len() > MAX_PLAINTEXT_HINT_BYTES` 只拒「严格大于」16 MiB，注释却称 "at/above the cap" 会在加密/分配前拒绝——恰等于 16 MiB 的明文仍先付全部 seal+JSON 序列化（base64url 膨胀后约 21.8 MiB）才被组帧后检查拒，注释与代码边界不符；测试只传 `MAX_FRAME_BYTES+1`，未覆盖 `==16 MiB` 边界（crates/syncbond-core/src/pairing.rs:83）（证据：预检改 `>=`（拒 at/above cap），注释与代码边界一致；新增 seal_and_send_rejects_payload_at_cap_before_sealing（==16 MiB 走预检拒绝）；cargo test -p syncbond-core 88 全绿）
- [x] 审核发现：`seal_and_send` 组帧后精确检查 `frame.len() > MAX_FRAME_BYTES`（唯一能拦下「低于提示阈值但编码后超限」的约 12–16 MiB 载荷的分支）无任何测试触达——新增 `seal_and_send_rejects_oversized_payload_before_sending` 的明文为 `MAX_FRAME_BYTES+1`，走的是加密前预检分支，后检分支无回归防护（crates/syncbond-core/src/pairing.rs:101）（证据：新增 seal_and_send_postencode_rejects_payload_under_hint（13 MiB 低于提示阈值、base64url 膨胀后超限，走组帧后精确检查拒绝）；cargo test -p syncbond-core 88 全绿）
- [x] 审核发现：`seal_and_send` 预检阈值 `MAX_PLAINTEXT_HINT_BYTES` 仍等于 `MAX_FRAME_BYTES`（16 MiB），高于 base64url 膨胀（约 4/3）下必然超限的实际阈值（约 12 MiB）——12–16 MiB 明文仍先付全量 `crypto::seal` + `serde_json::to_vec`（加密与约 4/3 内存膨胀）后才被组帧后检查拒绝；本轮仅将预检从 `>` 改为 `>=`，未扩大预检覆盖，新增 `seal_and_send_postencode_rejects_payload_under_hint`（13 MiB）恰证该未优化路径仍被触达（crates/syncbond-core/src/pairing.rs:87）（证据：`MAX_PLAINTEXT_HINT_BYTES` 降至 12 MiB——高于本协议固定 id 长度下可装入 `MAX_FRAME_BYTES` 帧的最大明文 12,582,728 字节（~11.9998 MiB），故 ≥12 MiB 明文必在加密/分配前被预检拒；新增 seal_and_send_rejects_payload_at_new_hint_before_sealing（==12 MiB 走预检拒绝）并将 postencode 测试改传 12 MiB−1（低于提示、base64url 膨胀后超限，仍走组帧后精确检查拒绝）；cargo test --workspace 全绿）
- [x] 审核发现：新增的策略说明遗漏 `Replicator::delete` 在 OR-Set 和 PN-Counter 下会因空 payload 不是合法 JSON 而返回 `MergeError`，误导调用方以为只是不生成墓碑；英文及中文镜像均有同样问题（docs/design/merge.md:47）（证据：`delete` 的 `apply_local` 将空 payload 交策略 `merge` 解码，`OrSetStrategy::decode`/`PnCounterStrategy::decode` 对空字节做 `serde_json::from_slice` 返回 `MergeError`；`docs/design/merge.md:55`、`docs/zh/design/merge.md:48`、`docs-site/src/design/merge.md:55`、`docs-site/src/zh/design/merge.md:48` 补「调用失败且记录保持不变」说明；新增回归测试 `delete_under_orset_and_pncounter_returns_merge_error`（crates/syncbond-core/tests/replication_tests.rs:372）；cargo test --workspace 全绿）
- [x] 审核发现：新增中文墓碑回收说明声称每个已知副本的 witness 必须支配墓碑且无证据的副本阻塞回收，但实现只比较本地聚合向量中各节点最后戳与墓碑戳，未记录每个副本是否见过该墓碑，未出现的副本也不参与检查；站点中文镜像相同（docs/zh/design/merge.md:59）（证据：`vector_dominates` 只遍历聚合向量中已有的节点——从未听到的副本不在向量中，不阻塞收簇；`docs/design/merge.md:78`、`docs/zh/design/merge.md:61`、`docs-site/src/design/merge.md:78`、`docs-site/src/zh/design/merge.md:61` 改述为「支配检查只覆盖有证据的副本；缺席副本不阻塞，barrier 仍拒绝迟到重投」；新增回归测试 `gc_does_not_require_evidence_from_never_heard_replicas`（crates/syncbond-core/tests/tombstone_gc_tests.rs:179）；cargo test --workspace 全绿）

- [x] 审核发现：`gc_does_not_require_evidence_from_never_heard_replicas` 末段「The barrier rejects the pre-delete write when a late peer redelivers it」断言为空转——`created` 是 node-a 自身 op（op_id `node-a:1` 已在 `put`→`apply_local` 时写入 `seen_op_ids`），`apply_remote` 在 replication.rs:274 的 `seen_op_ids.contains` 去重分支即返回 `Ok(false)`，从未触达 replication.rs:283-291 的 barrier 合并；若 barrier 拒复活逻辑失效（如移除 287 行 `had_barrier && !op.deleted && outcome.record.deleted` 判定）该测试仍绿，注释所述「barrier 拒绝」与回归防护名不副实；真正触达 barrier 的是 `gc_compacts_the_oplog_and_survives_a_restart`（经 `from_state` 重建、`stale` 非本节点 op_id 不命中去重）（crates/syncbond-core/tests/tombstone_gc_tests.rs:197）（证据：该测试改用从未被 node-a 听到的 node-b 的删除前写入 `stale`（op_id `node-b:1` 不在 `seen_op_ids`），redeliver 真实走 `ingest`/barrier 合并路径（replication.rs:280-291），若移除 287 行判定则断言失败；cargo test --workspace 全绿）

- [x] 审核发现：文档「so a late replica cannot resurrect the delete」绝对保证过强——barrier 只拒绝**合并中输给墓碑**的写入（支配/删除前写入），从未听到副本的**并发**写入若 HLC 戳更高（仍在 max_skew 界内）会在 LwwHlc 并发合并中胜出（conflict.rs:180-184 primary=incoming），使 replication.rs:287 的 `had_barrier && !op.deleted && outcome.record.deleted` 为假，走 307-308 行移除 barrier 并复活该键；此行为与 GC 前一致（无正确性回归，因 LwwHlc 并发高戳本应胜出），但文档宣称的「迟到副本无法复活删除」在该边界不成立，新测试亦未覆盖；中英及站点镜像同述（docs/design/merge.md:82、docs/zh/design/merge.md:61、docs-site/src/design/merge.md:82、docs-site/src/zh/design/merge.md:61）（证据：四处文档改为精确表述——barrier 只拒绝合并中输给墓碑的删除前写入；从未听到副本的并发高戳写入仍按既有 LWW 规则胜出并可重建该键（`docs/design/merge.md:78-83`、`docs/zh/design/merge.md:61`、`docs-site/src/design/merge.md:78-83`、`docs-site/src/zh/design/merge.md:61`）；`gc_tombstones` doc 注释同步（`crates/syncbond-core/src/replication.rs:317-326`）；新增回归测试 `concurrent_higher_stamp_write_resurrects_a_collected_delete`（`crates/syncbond-core/tests/tombstone_gc_tests.rs:209`，1ms 时钟偏移界内、并发高戳胜出并移除 barrier）；cargo test --workspace 全绿）

- [x] 审核发现：本轮修正只对「支配段落」的绝对保证做了限定，但同节紧随其后的「A collected tombstone is not deleted」段落仍保留未限定的绝对保证——「a pre-delete write redelivered after GC is rejected by the barrier instead of resurrecting the delete」（docs/design/merge.md:90-92、docs-site/src/design/merge.md:90-92、docs/zh/design/merge.md:63、docs-site/src/zh/design/merge.md:63），与上一段新增的「并发高戳写入可复活该键」异常直接矛盾（从未听到副本的并发高戳写入正是「GC 后重投的删除前写入」的一种，两段在同一节内自相矛盾）；`gc_tombstones` Rust doc 注释（crates/syncbond-core/src/replication.rs:317-325）与首段均已加「合并中输给墓碑」限定，唯独该段漏改，属同一「绝对保证过强」问题的未竟修正。（证据：四份文档该段改为「barrier 只对合并中输给墓碑的删除前写入拒绝；从未听到副本的并发高戳写入仍按 LWW 胜出并可重建该键」，与上一段及 `gc_tombstones` doc 注释一致（docs/design/merge.md:87-95、docs-site/src/design/merge.md:87-95、docs/zh/design/merge.md:63、docs-site/src/zh/design/merge.md:63）；cargo test --workspace 全绿，含 tombstone_gc_tests 10 项）

- [x] 审核发现：`gc_does_not_require_evidence_from_never_heard_replicas` 注释称「node-b writes the key before the delete」但 node-b 在程序序上于 `a.delete` 之后才创建，且两副本互不知情，该写入实为**并发**而非因果上先于删除；其被拒仅因戳更低（node-b put 为 ct=0 的首 op，node-a delete 为 ct=1 的第二 op），走的是「并发低戳输给墓碑」分支而非「因果支配的删除前写入」分支——后者由 `stale_put_cannot_resurrect_a_collected_delete` 覆盖；注释易误导读者以为本测试覆盖强保证的因果先于情形（crates/syncbond-core/tests/tombstone_gc_tests.rs:188-192）。（证据：该注释改为明确「并发、非因果先于，因戳更低被拒；因果先于情形由 `stale_put_cannot_resurrect_a_collected_delete` 覆盖」（crates/syncbond-core/tests/tombstone_gc_tests.rs:188-193）；cargo test --workspace 全绿，含 tombstone_gc_tests 10 项）

- [x] 审核发现：注释称 `stale_put_cannot_resurrect_a_collected_delete` 覆盖因果先于删除的写入，但该写入在删除前已被 node-a 接收并记入 `seen_op_ids`，重投时直接被去重，未验证墓碑 barrier 对因果先于写入的合并拒绝（crates/syncbond-core/tests/tombstone_gc_tests.rs:191）。（证据：核实属实；测试改为 GC 后先验证原路径去重，再经 snapshot/from_state 重启重建清空 seen 集后重投同一因果先于写入，真实走 ingest/barrier 合并并被拒绝（`crates/syncbond-core/tests/tombstone_gc_tests.rs:99-129`）；临时移除 barrier 拒绝判定后该测试失败，还原后通过；cargo test --workspace 全绿，含 tombstone_gc_tests 10 项；commit e934bce。更正 2026-11-05：重启后重投真实触达 barrier 的路径在区间前已由 `gc_compacts_the_oplog_and_survives_a_restart` 覆盖（见下一条审核发现），原发现针对该测试自身「未触达 barrier」仍然成立（不能整体称误判）；准确处置口径为「该测试未覆盖此路径，但仓库已有另一测试覆盖，故新增测试段重复」，e934bce 新增段已按 f3adfcc9 前例撤除。变异验证已独立复现：临时禁用 replication.rs:287 判定 → gc_compacts FAILED，还原 → PASS（codex 复核意见已采纳））

## 审核发现（f3adfcc9..9e7dac8 只审不改）

- [x] 审核发现：e934bce 给 `stale_put_cannot_resurrect_a_collected_delete` 新增的重启重投段与既有 `gc_compacts_the_oplog_and_survives_a_restart` 近乎重复（同 fixture、同 snapshot/from_state→重投 `stale`→被拒 流程，唯一新增断言仅「被拒后 barrier 仍存在」，其余断言均为既有覆盖），且 9e7dac8 记录称该情形「未验证墓碑 barrier 对因果先于写入的合并拒绝」，与本文件区间之前已有记录「真正触达 barrier 的是 `gc_compacts_the_oplog_and_survives_a_restart`（经 `from_state` 重建、`stale` 非本节点 op_id 不命中去重）」相抵触——该路径在本区间之前已有回归防护，本轮实为重复补测而非补缺口，更贴切的修法是如 f3adfcc9 对姊妹测试那样仅改注释指向既有覆盖（crates/syncbond-core/tests/tombstone_gc_tests.rs:113-126 与 :136-147、todo.md:160、todo.md:152）。（证据：`git show f3adfcc9:crates/syncbond-core/tests/tombstone_gc_tests.rs` 显示 `gc_compacts_the_oplog_and_survives_a_restart` 在区间前已含 `assert!(!restored.apply_remote(&stale).unwrap())`，且 `stale`（node-b:1）不在 GC 压缩后 oplog（仅剩 node-a:2 墓碑）重建的 seen 集中、真实走 ingest/barrier 合并拒绝（replication.rs:280-291），临时移除 287 行判定该断言即失败；`git log f3adfcc9..9e7dac8` 仅 e934bce（只改测试文件）与 9e7dac8（只追加 todo.md）两笔，无源码改动故无安全面变化；cargo test --workspace 全绿，含 tombstone_gc_tests 10 项。已按审计建议实施：撤除 e934bce 新增的重复段，注释改为指向既有覆盖 `gc_compacts_the_oplog_and_survives_a_restart`（照 f3adfcc9 前例）；本机复验变异——临时禁用 replication.rs 的 `had_barrier && !op.deleted && outcome.record.deleted` 判定后 `gc_compacts_the_oplog_and_survives_a_restart` 即 FAILED、`stale_put_cannot_resurrect_a_collected_delete` 不受影响，还原后全绿；todo.md:160 已附更正；cargo clippy --workspace --all-targets -- -D warnings 干净；commit 85f8fc6。更正 2026-11-06：node-b:2（echo/hb）经 `apply_remote`→`ingest` 非 barrier 路径只写 `records` 不入 oplog（replication.rs:310-311），GC 后 oplog 仅剩 node-a:2 墓碑；原「仅剩 node-b:2、node-a:2 墓碑」表述不实，结论不受影响）
- [x] 审核发现：本轮新增「审核发现（f3adfcc9..9e7dac8 只审不改）」条目的证据称 GC 压缩后 oplog「仅剩 node-b:2、node-a:2 墓碑」，但 node-b:2（echo/hb）经 `apply_remote`→`ingest` 的非 barrier 路径只写 `records` 不入 oplog（replication.rs:310-311），node-a 的 oplog 在 GC 后仅剩 node-a:2 墓碑一项（`gc_collects_tombstones_after_the_threshold_when_every_replica_saw_the_delete` 断言 `oplog_entries_removed == 2` 亦佐证：若 node-b:1 在 oplog 则 k 相关应移除 3 项）——证据父述不实，应作「仅剩 node-a:2 墓碑」；结论（node-b:1 不在重建 seen 集、真实走 barrier 拒绝）不受影响（todo.md:164）。（验证：`ingest` 非 barrier 路径仅 `records.insert`（replication.rs:310-311）；`from_state` 仅从 `state.oplog` 重建 seen（replication.rs:494-496）；todo.md:164 已更正为「仅剩 node-a:2 墓碑」；cargo test -p syncbond-core --test tombstone_gc_tests 10/10 全绿；cargo test --workspace 全绿）
- [x] 审核发现：新增条目「验证」引证 `ingest` 非 barrier 路径为 replication.rs:303-311，但该范围含 303-306 的 barrier-墓碑分支（replication.rs:304 `self.oplog.push(op.clone())`），与同条「非 barrier 路径仅 `records.insert` 不入 oplog」矛盾；同条前文已正确引 310-311，两处引用不一致，应统一为 310-311（todo.md:165）。（验证：todo.md:165 现仅引 replication.rs:310-311（`ingest` 非 barrier 路径仅 `records.insert`），不复含 303-311——不一致已消除；修复经 commit 0ca6489；cargo test --workspace 全绿）
- [x] 审核发现：本轮范围（8e945848..HEAD）新增 todo.md:165 的「验证」节引 `ingest` 非 barrier 路径为 replication.rs:303-311，该区间含 303-308 的 barrier-墓碑分支（replication.rs:304 `self.oplog.push(op.clone())`），与主文所引 310-311（`records.insert`+`Ok(true)`，非 barrier 路径落点）不一致，应统一为 310-311；该问题与既有未提交条目 todo.md:166 所述一致，本轮复核确认属实，无新增问题（todo.md:165）。（验证：同 todo.md:166——todo.md:165 现仅引 replication.rs:310-311，不复含 303-311；修复经 commit 0ca6489；cargo test --workspace 全绿）
- [x] 审核发现：最终品牌名标记为已由用户拍板，但同一文件的待拍板项仍称待用户定名，导致决策状态相互矛盾（todo.md:38）。（验证：todo.md:44 待拍板项已改为「已定：沿用 syncbond 为正式名（2026-11-05 用户拍板）」，与 todo.md:38 一致；cargo test --workspace 全绿）
- [x] 审核发现：中英文 README 及待办将 crates.io 上未占用的六个包名称为已归属或预留给本项目，但名称按先到先得分配，空闲查询不能保证项目取得这些名称（README.md:8）。（验证：README.md:8 与 README.zh.md:8 已改为「截至检查时未占用；按先到先得分配，本检查不保证取得」，不再称归属/预留；cargo test --workspace 全绿）

## 审核发现（098d1ee..HEAD 只审不改）

- [x] 审核发现：本轮新增「审核发现」todo.md:169 自述修复「中英文 README 及待办」的 crates.io「归属/预留」表述并称「不再称归属/预留」，但同文件 todo.md:38 仍写「crates.io 六名空闲归属本项目已复核」（归属本项目），与本条验证表述及已修正的 README.md:8/README.zh.md:8 相矛盾——修复只覆盖两处 README，未覆盖其自述范围中的「待办」（todo.md:38、todo.md:169）。（验证：todo.md:38 已改为「六名截至检查时未占用（按先到先得分配，本检查不保证取得）」，与 README.md:8/README.zh.md:8 口径一致；cargo test --workspace 全绿）
- [x] 审核发现：本 diff 已将 todo.md:165「验证」节引证从 replication.rs:303-311 改为 310-311，正是未结条目 todo.md:166 与 todo.md:167 所建议的「应统一为 310-311」，但该两条仍为 `[ ]` 未勾销、亦未标注「已按建议实施」，读者无法得知其建议已被落实（todo.md:165、todo.md:166、todo.md:167）。（验证：todo.md:166 与 todo.md:167 已勾销并注明修复经 commit 0ca6489；cargo test --workspace 全绿）
- [x] 审核发现：README.zh.md:8 句末为「仍可用）.」，中文全角右括号「）」后接半角句点「.」，且全句句读未用全角句号，中英标点混排，未与英文版「remain available).」样式对齐（README.zh.md:8）。（验证：README.zh.md:8 句末已改为「仍可用）。」，全角句号，与英文版样式对齐；cargo test --workspace 全绿）
- [x] 审核发现：本轮 diff 未见问题（0ca64895131c41f2f84ac3effaf1aa05fa18e59c..HEAD）。（验证：git diff 0ca64895..HEAD --stat 复核改动面（README.zh.md、todo.md），逐行核对各改动点（README.zh.md:8 标点、todo.md:38 crates.io 口径、todo.md:165 引证、166/167 勾销）均属实无问题；当日 HEAD ecc6461e3f78b4c41e813ba5e23c65a89d35af31；cargo test --workspace 全绿）

## 覆盖率补测（2026-11-09，任务书 ~/.hermes/cache/scratch/tasks/syncbond.md）

- [x] 覆盖率补测完成：目标 ≥98%（codecov 口径）**已达成**。测量口径与 CI 相同——`cargo llvm-cov --workspace --all-targets --lcov`（cargo-llvm-cov 0.9.1）；含全部 crate（含 wasm 目标代码）时 4348/4513 = 96.34%，按 codecov.yml `ignore: crates/syncbond-wasm` 剔除后 **4348/4414 = 98.50%**。起点：82.91%（本批前基线）→ 91.82%（绑定壳层补测）→ 96.34% raw / 98.50%（codecov 口径）。（证据：/tmp/lcov3.info 逐行 DA 解析，见本节末「未覆盖清单」）
- [x] wasm 排除理由（如实记录）：crates/syncbond-wasm 全部 99 行均为 wasm-bindgen 胶水，只能在 wasm32 运行时的 JS 宿主内执行；宿主 llvm-cov 物理上无法对其插桩计数（本机为 linux-x86_64，测试跑在 native 目标上）。该代码的正确性由 bindings-ts CI job 中的 `wasm32-unknown-unknown` 构建与 TS 测试验证，属「宿主不可测、CI 有独立验证面」的例外，非未测缺口，故 codecov.yml 显式 ignore 并在此记录。（证据：lcov 中该目录 lines=99 hit=0；CI .github/workflows 中 bindings-ts job 含 wasm32 构建）
- [x] 本批覆盖的缺口（仅新增测试，未改任何生产代码行为）：pairing 协议帧健壮性（截断/错型/签名翻转/重放/非应用帧，含 SPAKE2 握手途中篡改的 TamperingTransport 模式）；HLC Debug 输出与 receive 的 local-ahead/wall-ahead 分支；replication 的 total_exchanged 统计、GC barrier 刷新、崩溃窗口重放、Record::new 字段映射；member_crypto 安全分支（错误协议版本、源密钥替换检测、被移除成员拒绝针对自己的合法签名轮换、pre-rotation 密钥不同导致 MAC 失败、畸形 MAC hex）；scenario 错误分支（未知 strategy、非数组 steps、GC dominance、密钥 epoch 校验默认值、put 失败回显）；napi/python 进程内 compute/sync 真实会话交换与模块注册面；以及 transport/relay/codes/discovery/crypto/identity/conflict/ffi-error/handles 的零散单分支。（证据：cargo test --workspace --all-targets 全绿；cargo fmt --all -- --check 干净；cargo clippy --workspace --all-targets -- -D warnings 干净）
- [x] 剩余 66 行未覆盖清单（均为不可达或胶水，如实记录，不做无意义凑数测试）：codes.rs:225,237（panic 路径格式化）；member_crypto.rs:279-280,288-291,307,451（with_epoch 内 device_id_from_public_key 派生校验使替换/垃圾密钥被前置拒绝，公开 API 无法触达）；pairing_spake2.rs:117（random_scalar 重试，概率天文小）、250-252,303,332-334（with_scalars/new_with_scalars 仅 RFC 9382 附录 B 一致性向量用）；relay.rs:127（`if let` 块闭合 `}` 行界伪影，其 map_err 闭包 126 行已被 parent-is-a-file 测试触达）；replication.rs:374,508（merge 前置不变量使分支不可达）；abi.rs:40-43,91,470,617,642,715（catch_unwind panic 回退与 OOM 不可达防御分支）；scenario.rs:279,283（防御分支）；napi lib.rs 21 行与 pairing.rs 6 行（#[napi] 属性展开胶水、AsyncTask Env 门槛路径——进程内测试直接调 compute()，属性包装层需 napi 运行时）；python lib.rs 7 行（#[pymethods] 展开胶水）。（证据：/tmp/lcov3.info 逐文件 missed 行清单）

- [x] 审核发现：本轮 diff 未见问题（c748ae0f..HEAD）。（验证：区间仅含 94d5b1a——todo.md:39 单行追加「复核 2026-11-09：`npm whoami` 仍 ENEEDAUTH，保留 BLOCKED」，与当日实测一致（`npm whoami` exit 1 ENEEDAUTH，日志 ~/.npm/_logs/2026-11-09T14_07_25_680Z-debug-0.log）；该 commit 仅改 todo.md 一行（1 insertion 1 deletion），信息英文简短无 AI 痕迹，作者 cuihairu <chuihairu@gmail.com>；复核 2026-11-10：`npm whoami` 仍 ENEEDAUTH，todo.md:39 已续记；cargo test --workspace 全绿）

## 覆盖率巡检（2026-11-11，任务书 ~/.hermes/cache/scratch/tasks/cov-syncbond.md）

- [x] 巡检结论：基线口径厘清 + 可达缺口补测 15 个行为测试（只加测试，未改任何生产行为）。2026-11-09 的 96.34% raw / 98.50%（codecov 口径）是当日快照；其后代码净增（审计修复、lan mDNS、key_epoch 场景等，CI 口径插桩行 4414→4725）使两口径回落。本轮起点（补测前实测）：`--all-features` 口径 line 92.01%（region 90.33% / function 84.73%，discovery.rs 43.07% 是最大缺口——lan 块 152 行全新未测）；CI 口径（`cargo llvm-cov --workspace --all-targets`）line 94.96%、剔除 wasm 后 97.07%。终点：`--all-features` line **95.24%**（region 93.27% / function 87.11%，discovery.rs 98.13%，152 行缺口收至 5）；CI 口径 line 95.19%、剔除 wasm 后 **97.27%**。（证据：cargo llvm-cov summary 前后对照，cargo-llvm-cov 0.9.1；全量 `cargo test --workspace --all-features` 207/0 绿；clippy --all-targets -D warnings 默认+全特性两口径 0 错；cargo fmt --check 干净）
- [x] 本批闭合的缺口（均为真实行为断言，非凑数）：lan mDNS provider 9 测试（构造/Default/Debug 渲染、非法记录在校验期拒绝且不建 daemon、无状态 unpublish/drop、register/unregister 往返、二次 publish 复用 daemon、publish 后 drop 注销+关停、无自有公告 browse 正常返回、自公告按实例名解析（2s×5 自适应重试：兄弟测试并行公告与调度争用会使固定 3s 窗口抖动，修正后连跑 11 次全绿含高负载并发档）（commit 3a26718）；member_crypto 伪签名轮换两测——签名合法但成员集非法在签名校验后、MAC 前以 InvalidMembership 拒绝（重含被移除设备 / 清空 removed id）（commit 7cd5f99）；pairing_spake2 两测——new_with_scalars 双角色完整握手、双侧不同口令 ConfirmationFailed（commit b3db5c1）；scenario key_epoch 缺 survivors/removed 列表输入错误两测（commit 6816be7）。行级闭合：discovery 152→5、member_crypto:307、pairing_spake2:250-252/303/332-334（255 行缺 11→4）、scenario:279/283。（证据：cargo llvm-cov report --show-missing-lines 前后清单）
- [x] 对 2026-11-09「剩余 66 行不可达清单」的三处更正：member_crypto.rs:307、pairing_spake2.rs:250-252/332-334/303、scenario.rs:279/283 当时段定为不可达/防御分支，实际可达（伪造重签轮换、公共确定性构造器、缺字段 fixture），本轮已闭合并补测试；其余条目复核属实（member_crypto 279-280/288-291/451——with_epoch 的 device_id_from_public_key 前置校验使公共 API 无法送入伪钥；spake2:117 概率重试；relay:127 裸路径行界伪影；replication:374/508 前置不变量；abi catch_unwind/OOM 防御；napi/python #[napi]/#[pymethods] 宏胶水与 AsyncTask Env 门槛——sync()/resolve 仅 Node 运行时可执行，进程内测试只能直调 compute()）。
- [x] 98% 目标评估：CI 口径剔除 wasm 后 97.27%，未达；剩余缺口全部为上述宏胶水/Env 门槛/防御分支/不可达幽灵行，在不改生产行为、不写凑数测试的前提下不可达，如实记录上限。每轮巡检后代码增长都会摊薄比率（11-09 快照 98.50% → 本轮起点 97.07% 即此效应），可持续做法是把「新增代码同批带测试」作为惯例而非事后补测冲比率。
- [x] 观察项（未动 CI，留待用户拍板）：ci.yml 的 test 与 coverage 两 job 均不带 `--all-features`，lan mDNS 代码与其 9 个测试从不进 CI（本轮全部本地验证）；若需 CI 兜底，可在 coverage job 加一步 `cargo test --workspace --all-features`。另：llvm-cov 下 wasm_node 测试依赖 wasm32 无插桩缓存——`cargo llvm-cov clean`（全清）后 wasm-pack 继承 `-C instrument-coverage` 环境重编 wasm32 必失败（E0463 profiler_builtins），须先无插桩 `wasm-pack build` 重建缓存、或用 `cargo llvm-cov clean --profraw-only`（本巡检采用后者，两口径复测 exit 0）。（证据：/tmp/cov_all.txt E0463 失败记录 → 重建缓存后通过）

## 文档站语言自动识别（2026-11-14，fleet-docs-audit-G2 待拍板）

- [ ] 文档站浏览器语言自动识别跳转（P2，等用户拍板范围）：站有 `locales` root=英文 / zh=中文 与 `langSwitcher`（`docs-site/src/.vitepress/config.mts:21-22`），但无 `navigator.language` 探测、无 `rootLocale` 重定向，访客只能手动切换。舰队再审计（fleet-docs-audit-G2）对 67 个公开仓跑 `scripts/fleet-url-contract.py` 契约探针：0 个仓检出任何自动识别机制，故自动跳转列为增强项待用户拍板哪些仓上；受规基线维持「手动切换 + 显式链接」
