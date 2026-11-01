---
layout: home

hero:
  name: "SyncBond"
  text: "无账号、端到端加密的设备同步"
  tagline: "可嵌入的设备配对与数据同步 SDK：载荷不透明、合并策略可插拔、Rust 内核 + TypeScript 绑定。内核永远不理解你的业务数据。"
  actions:
    - theme: brand
      text: 需求基线
      link: /zh/requirements
    - theme: alt
      text: 协议规范（v1）
      link: /design/PROTOCOL
    - theme: alt
      text: GitHub
      link: https://github.com/cuihairu/syncbond

features:
  - title: 无账号配对
    details: 两台设备各显示一段短码，即通过 SPAKE2（RFC 9382）导出共享密钥，带双向密钥确认与转录绑定的身份交换——全部四组 RFC 官方测试向量通过。
  - title: 端到端加密信封
    details: XChaCha20-Poly1305 信封中除密文外全部字段均为 AEAD 关联数据；重放、跨组、错纪元与篡改一律拒绝。
  - title: 可推理的收敛性
    details: 基于 游标 + 去重 的 oplog 复制——乱序与重复投递收敛到同一状态。合并策略可插拔：HLC-LWW（含因果墓碑）、OR-Set、PN-Counter。
  - title: 以契约为本的可嵌入性
    details: 内核不含任何应用概念——载荷即不透明字节，合并行为即可插拔策略。密码学全部由经审计的 RustCrypto 组件组装，本仓不实现任何密码学原语。
---
