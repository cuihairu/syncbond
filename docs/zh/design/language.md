[English](../../design/language.md)

# 语言决策：Rust 内核 + TypeScript 绑定 对比 纯 TypeScript

状态：**v1 已采纳的决策——Rust 内核（`crates/syncbond-core`）+ TypeScript 绑定骨架（`packages/ts-bindings`）**。记录以供评审；下文的对比是依据。

## 驱动选择的需求

- 运行在输入法 / 桌面应用内（Windows、macOS、Linux、移动端），外加一个同步 relay 服务。
- 处理机密材料（会话密钥、身份密钥、PAKE 标量）——内存卫生很重要。
- 必须至少能从 TypeScript（UI 层）嵌入，最终还能从其他平台语言嵌入。
- CRDT（无冲突复制数据类型）/复制逻辑的正确性是发布阻断项；测试套件就是产品本身。

## 对比

| 维度 | Rust 内核 + TS 绑定（napi-rs / wasm-bindgen） | 纯 TypeScript |
|---|---|---|
| 跨平台覆盖 | 一个内核，Node/Electron（napi-rs）、浏览器（wasm-bindgen）绑定，之后经 FFI 支持 Swift/Kotlin | 到处都是同一个运行时，但每个宿主都要内嵌 JS 引擎 |
| 机密处理 | 密钥位于原生内存；可以做 `zeroize` 式擦除；不存在密钥材料的 GC 副本 | 密钥字节位于 JS 堆；GC 复制与 inspector 访问扩大暴露面 |
| 性能 | 曲线运算（P-256 PAKE）、scrypt 与二进制复制循环都是原生执行；scrypt 尤其受益 | JS 里的 scrypt/PAKE 可用，但在低端设备上慢 10–50 倍 |
| 安全/审计 | RustCrypto + dalek + noble 等价 crate，类型级所有权；`unsafe` 仅限绑定胶水层 | noble-js 技术栈经过审计，但整个运行时与应用代码共享 |
| 维护 | 两种语言；绑定层必须跟随内核 API | 单一语言，工具链最小 |
| 迭代速度 | 协议实验较慢（编译、codegen） | 实验最快 |
| IME/桌面集成 | 原生模块加载是输入法周边组件的标准做法 | 把 JS 运行时嵌进输入法进程很别扭 |
| Relay/服务端 | 同一 crate 服务端复用 | 需要单独的服务端代码库，或到处用 Node |
| 团队经验 | 已有 Rust 实践（meshlet、sandtable） | 到处都是既有 TS 实践 |

## 决策

Rust 内核 + TypeScript 绑定，因为起决定作用的行是机密处理、原生 IME 嵌入以及内核在 relay 中的复用——正是纯 TS 最弱的几行。接受的代价：一个绑定层与更慢的迭代。TS 绑定从镜像 Rust API 的类型化骨架（`packages/ts-bindings/src/index.ts`）起步；napi-rs 实现是 P2 的第一项工作。

## 反悔说明

如果绑定层最终成为维护负担（在 todo.md 中跟踪），回退方案是纯 TS 加经过审计的 noble-js 技术栈——协议文档在设计上与运行时无关，无论哪种方式信封 schema 都是稳定契约。
