[English](../deploy.md)

# 运行中继：运行维护指南

状态：**默认服务器已交付**（`apps/syncbond-server`，todo.md DSR-11 至 DSR-50）。本页是部署者照做的指南：启动它、前置 TLS、签发凭证、设定配额、备份、恢复、升级。它所服务的契约冻结于[中继协议（v1）](design/relay-protocol.md)规范；信任边界与职责记录于[默认服务器设计](design/default-server.md)。

这里每一步都是确定性的：每个命令都已由验收套件（`apps/syncbond-server/tests/`）对已交付镜像与二进制实测过。

## 1. 你在运行什么

一个单进程：存储**密文信封**并转发配对帧。它永不见明文操作、用过的配对短码、身份密钥或组密钥——那些都在设备侧。部署者持有一份 **admin 引导凭证**，创建频道，并为每设备每频道签发凭证。公网部署在反代处终结 TLS；中继本身在一个端口上跑明文 HTTP/1.1 + WebSocket。

状态是一个目录（`dataDir`）：SQLite 数据库（`relay.db` 及其 `-wal`/`-shm`）与 `admin-credential` 文件。其余都不持久化。

## 2. 快速开始（Compose）

在仓库根目录：

```sh
docker compose -f deploy/compose.yaml up -d
```

这构建镜像（`deploy/Dockerfile`）、以命名卷（`relay-data`）挂载 `/data` 启动容器，镜像自带的健康检查报告就绪。无需任何前置准备——容器使用镜像内置配置，服务器在首启时把 admin 凭证写入卷。

检查：

```sh
docker compose -f deploy/compose.yaml ps          # 预期：Up (healthy)
curl http://127.0.0.1:8080/v1/ready               # {"status":"ready"}
```

发布端口只绑 `127.0.0.1`——明文仅限本地开发。宿主机 8080 被占时换宿主端口，无需改文件：

```sh
SYNCBOND_HTTP_PORT=18080 docker compose -f deploy/compose.yaml up -d
```

停止（保留数据卷；`-v` 删除）：

```sh
docker compose -f deploy/compose.yaml down        # 加 -v 同时删数据
```

## 3. 直接运行二进制

```sh
cargo build --release --locked --package syncbond-server
./target/release/syncbond-server /path/to/config.json
```

唯一参数是配置文件路径；缺参会打印用法并以 2 退出。非法配置在创建任何东西之前非零退出——不可读或更新的数据库是硬停止，绝不擦除。`SIGINT`/`SIGTERM` 触发有界 drain；一切已确认的数据落盘后以 0 退出。

容器内同一二进制以非 root 用户（`syncbond`，UID 1000）运行，配置在 `/etc/syncbond/config.json`：

```sh
docker build -f deploy/Dockerfile -t syncbond-server .
docker run -d -p 127.0.0.1:8080:8080 -v syncbond-data:/data syncbond-server
```

宿主机绑定（而非命名卷）须对 UID 1000 可写：`chown 1000:1000 /host/data`。

## 4. 配置

一个 JSON 文件，封闭形状：未知字段令启动失败——拼写错误永不静默禁用某个设置。

| 键 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `listen` | 地址 | `127.0.0.1:8080` | 绑定地址。容器内配置用 `0.0.0.0:8080`——那是容器内面；公网边缘是 TLS 代理。 |
| `dataDir` | 路径 | `./data` | 数据库 + `admin-credential`。非空且不为 `/`。 |
| `channelQuotaBytes` | 字节 | 1073741824 | 每频道预算。`0` 禁用；否则至少 4 MiB（一个最大信封）。 |
| `diskQuotaBytes` | 字节 | 8589934592 | 全库预算，同样 `0`-或-≥4 MiB 规则。 |
| `allowedOrigins` | 列表 | `[]` | 允许打开 WebSocket 连接的浏览器 Origin。空=不允许任何浏览器 Origin；非浏览器客户端不受影响。 |
| `trustedProxies` | 列表 | `[]` | 其 `X-Forwarded-For` 可被采信的代理 IP/CIDR（见 §7）。 |
| `maxWsSessions` | 计数 | 64 | 同时准入的 WebSocket 会话（配对+events）。`0` 禁用限制。 |
| `maxConnections` | 计数 | 256 | 同时处理的 TCP 连接；超出即在 accept 处丢弃。`0` 禁用。 |
| `headerTimeoutSeconds` | 秒 | 30 | 客户端发完请求头的时限（慢速头/慢速攻击上界）。`0` 禁用。 |
| `shutdownTimeoutSeconds` | 秒 | 10 | 关停 drain 可时长。`0` 等待每个连接结束。 |

全键示例是 [`deploy/config.example.json`](https://github.com/cuihairu/syncbond/blob/main/deploy/config.example.json)；镜像内置的最小配置是 `deploy/config.json`。Compose 中覆盖配置：绑定一个文件盖住内置的：

```yaml
    volumes:
      - ./my-config.json:/etc/syncbond/config.json:ro
```

冻结契约值（房间 TTL、帧上限、速率限制、心跳）**不可配置**——见 §13 限额表。

## 5. 健康检查

监听端口上有两个免鉴权 GET 路由：

- `/v1/health`——存活：进程应答。不触碰存储。
- `/v1/ready`——就绪：仅在监听器起来**且**存储打开后翻转。

容器镜像的 `HEALTHCHECK` 每 30 s 探测 `/v1/ready`（5 s 超时、15 s 启动期、3 次重试），`docker ps` 因此报告真相。若在你的配置里绑了非默认端口，同步覆盖健康命令（`docker run --health-cmd ...`）。

## 6. TLS 反向代理

中继说明文；**公网部署必须在其前置 TLS 终结**（default-server.md §4）。代理与中继走 docker 网络或回环；客户端只见 `https://`/`wss://`。

nginx，为 `relay.example.com` 终结 TLS 并转发到容器发布的回环端口：

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;
    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;      # WebSocket 配对/events
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;                     # > 90 s 空闲超时
    }
}
```

Caddy 一行搞定 TLS、WebSocket 升级与头：

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

两种情况都保持 compose 端口映射回环（`127.0.0.1:8080:8080`），使明文面仅同宿主代理可达，并把代理地址列入 `trustedProxies`（§7），让配对房速率限制以真实客户端 IP 为键。

## 7. 浏览器 Origin 与代理信任

**Origin。** 浏览器 WebSocket 连接按 `allowedOrigins` 校验——列出你的 Web 应用实际所在的精确 Origin（`https://app.example.com`）。非浏览器客户端（Rust/TS/Python 绑定、curl）不受 Origin 校验。空（默认）不允许任何浏览器 Origin。

**代理信任。** 配对房创建速率限制以客户端 IP 为键。直连时该键即对端 socket 地址。在推荐的代理后每个对端*都是*代理，故把代理地址（IP 或 CIDR）列入 `trustedProxies`；对该列表内的对端，客户端地址取自 `X-Forwarded-For`，从右向左扫描、恰好越过受信代理一跳。更左的字段由客户端自己写入，永不采信——这正是不受信对端的头被完全忽略的原因：回环调用者不能靠发 `X-Forwarded-For` 铸造新的速率限额预算。

```json
{
  "listen": "0.0.0.0:8080",
  "dataDir": "/data",
  "allowedOrigins": ["https://app.example.com"],
  "trustedProxies": ["172.16.0.0/12", "127.0.0.1"]
}
```

`172.16.0.0/12` 覆盖默认 docker 桥接网段；若知道 compose 网络子网可再收紧。不是 IP/CIDR 的名字令启动失败，而非速率限制时失败。

## 8. 凭证

**Admin 引导凭证。** 首启（新库）时服务器生成 64 位十六进制 token，以属主私有权限写入 `dataDir/admin-credential`，此后以常数时间校验 admin 请求。它是部署者必须保管的唯一秘密——与数据库一起备份（§10）。库存在但文件缺失时，服务器**拒绝启动且不触碰数据**（重新生成等于把新钥匙交给删文件者）：从你的备份恢复它。

```sh
# Compose 部署中：
docker compose -f deploy/compose.yaml exec relay cat /data/admin-credential
```

**频道与每设备凭证。** 所有 admin 调用以该 token 作为 Bearer 凭证；relay-client crate（每个绑定都包它）封装了这些调用：

```rust
use syncbond_relay_client::{RelayClient, TlsPolicy};
use syncbond_relay_protocol::dto::CredentialScope;

let client = RelayClient::new("https://relay.example.com", TlsPolicy::Validate, timeout)?;
// 每个复制组一个频道：
let channel = client.create_channel(admin_token, "req-1").await?;   // -> channel_id
// 每设备每频道一份凭证——token 只显示一次：
let issued = client.issue_credential(
    admin_token, &channel.channel_id,
    &[CredentialScope::Append, CredentialScope::Pull],
    Some("phone"), "req-2").await?;                                  // -> token
// 设备一丢失立即吊销（独立于组密钥轮换）：
client.revoke_credential(admin_token, &channel.channel_id, &credential_id).await?;
```

经受保护的侧信道把凭证交给需要它的设备——绝不进 URL 或日志。吊销是每次授权重读的持久化标志，被吊销的 token 立即被拒；吊销已吊销的凭证仍为 200。未知或已吊销 token 是 401；缺作用域或频道不符的合法 token 是 403。组 id 与设备 id 都不是凭证——丢一份凭证只影响一台设备对一个频道的访问，仅此而已。

## 9. 配额

两个预算都来自配置：每频道 `channelQuotaBytes`、全库 `diskQuotaBytes`。两者都接受 `0`（禁用）或至少 4 MiB——一个最大信封——因为更小的非零预算永远无法准入一次写入。

批次越额时 append 被拒 **HTTP 507 `quota_exceeded`** 且**整批回滚**——部分批次永不成立，重试总是安全。读与 admin 调用永不被配额阻塞：满频道仍可 pull、仍可管理。配额按存储字节计；信封内的加密是客户端的事，中继只按它存储的计费。

## 10. 备份与恢复

全部状态即数据目录：`relay.db`、`relay.db-wal`、`relay.db-shm`、`admin-credential`。停机时备份（服务器关停时自己就做这事——退出前折叠 WAL，因此干净停止是自然的备份点）：

```sh
docker compose -f deploy/compose.yaml stop relay
docker run --rm -v syncbond_relay-data:/data -v "$PWD":/backup alpine \
    tar czf /backup/syncbond-data-$(date +%F).tar.gz -C /data .
docker compose -f deploy/compose.yaml start relay
```

（纯二进制：`systemctl stop syncbond-server && tar czf backup.tgz -C /var/lib/syncbond .`。）

恢复是逆过程：停止、用备份替换目录内容、启动、确认 `{"status":"ready"}`。旧服务器确认过的一切都能再 pull 到——验收套件正好钉住这一点（`resource_shutdown_suite.rs`：三条已确认 append 跨停止存活，重启同一 `dataDir` 后 `pull` 回它们，seq 1..3）。

复制**运行中**的库不在此承诺内：`-wal` 可能持有已确认未折叠的数据。若无法停机，用 SQLite 在线备份（`sqlite3 relay.db ".backup '/backup/relay.db'"`）而非文件拷贝，并仍单独备份 `admin-credential`。

## 11. 升级

数据库迁移经 SQLite 的 `PRAGMA user_version` **严格向上**。对部署者的推论：

- **升级**服务器（更新的二进制/镜像 + 更旧库）在启动时向前迁移。
- **降级**（更旧二进制 + 更新库）拒绝启动——`database schema version N is newer than this server supports (M); refusing to start without touching data`。数据绝不擦除；换回旧二进制或恢复升级前的备份。

步骤：

```sh
# 1. 备份（§10）——每次升级前的不流泪原则。
# 2. 替换镜像/二进制：
docker compose -f deploy/compose.yaml build
# 3. 重建并核验：
docker compose -f deploy/compose.yaml up -d
curl http://127.0.0.1:8080/v1/ready
```

数据卷跨容器重建保留（命名卷不被 `down` 无 `-v` 删除），频道、凭证、信封原样跨越升级。

## 12. 关停行为

`SIGTERM`（`docker stop` 与一切服务管理器所发）触发以 `shutdownTimeoutSeconds` 为界的 drain：已接受请求完成，每个 WebSocket 在冲掉已排队内容后以声明式 code（`1001`）关闭，然后折叠 WAL、以 0 退出。信号前确认过的一切在重启后可 pull 到——干净停止服务器的数据目录拷贝即有效备份（§10）。

## 13. 冻结限额（参考）

不可配置；服务器可低于这些上限配置，绝不高于（relay-protocol.md §9）：

| 限额 | 值 |
|---|---|
| 单个信封（序列化后） | 4 MiB |
| 每次 append 批次信封数 | 16 |
| 批次总字节 | 8 MiB |
| 整个请求体 | 16 MiB（传输层以上 413） |
| 单个配对帧 | 16 MiB |
| 每 socket 出站队列 | 17 MiB（排不动的对端被 1013 关闭） |
| pull 页 | 64 条 / 16 MiB（默认 16 / 4 MiB） |
| 配对房 | 2 参与者、120 s TTL、128 位能力 |
| 建房速率 | 每客户端 IP 每分钟 16 次 |
| WebSocket 心跳 / 空闲关闭 | 30 s / 90 s |

超限或畸形输入以声明式关闭码结束连接（`1008` 协议违例、`1013` 出站预算耗尽、`1001` 对端离开/关停、`4401` 凭证被吊销、`4410` 房间过期）——绝不挂起，也绝不把契约承诺的 code 换成 reset。资源与关闭验收套件（`apps/syncbond-server/tests/resource_shutdown_suite.rs`）对已交付二进制逐一钉住这些行为；密文边界套件钉住没有任何秘密骑在服务器文件、日志或流量里。
