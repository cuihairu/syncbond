# 2026-10-30 批量决策分析（syncbond）

> 状态:已代决(2026-10-14 用户授权「按推荐拍,后续可推翻」);需要密钥/账号/用户私有数据的事项标「需用户输入,暂缓」,不硬做

本文件分析 `todo.md` 全部 BLOCKED/待决策/缺用户输入条目。扫描结论：P3 发布区块 2 条（品牌名、npm 发布）为「BLOCKED：用户输入」；「待拍板项（用户决策）」5 条中 #1/#2 与上述同源（需用户输入），#3 跨版本协商、#4 墓碑降级 GC 已于 2026-10-28 巡检授权代决（todo.md:31,34，维持，不重复拍板），**#5 自动轮换触发为本批唯一可代决取舍项**。

---

## 条目 1：最终品牌名（todo.md:38 P3 区块，待拍板#2 同源）

**事实**：`todo.md:38`——BLOCKED：用户输入。`README.md:11`「syncbond is a temporary development name; the final brand is to be decided」。2026-10-30 修正复核：沿用 `syncbond` 时需覆盖 workspace 实际包名 `syncbond-core`/`syncbond-ffi`/`syncbond-napi`/`syncbond-python`/`syncbond-wasm`（`Cargo.toml:3-9`；`crates/syncbond-python/Cargo.toml:2,10`）；crates.io 占用状态已实测确认：API 可达（对照 `serde`=200、`index.crates.io`=200），五个 workspace 包名均 404「does not exist」= 确认为未占用。

### 推荐决策

**暂缓，需用户输入。** 用户核验候选并定名后 → 开启改名工作线；定名前不勾除本条、不启动改名。

### 理由（成本/收益/风险）

1. **收益**：品牌名是产品公开身份，也是所有包名/scope/文档标题的根；定名后才能一次性改到位，避免二次改名。
2. **成本**：仓库侧零剩余工程——改名工作线（crate/package/scope 更名 + README banner + CI 矩阵同步）已定义，只待定名即可执行。
3. **风险（不做）**：维持临时开发名，产品以开发名对外，属低风险（当前 pre-1.0 无发布存量）。
4. **风险（硬做/代决）**：候选核验权为用户保留（`todo.md:38`），仓库内无候选清单；我代决定名=越权替用户做公开身份决策。crates.io 占用已实测确认候选名未占用（残余风险排除），但代决定名本身仍属越权。
5. **教学性**：为什么品牌名不能「随便取」？因为它会**刻进发布物的名字**——crate 名、npm scope、包 ID、CI 矩阵，一旦发布改名的兼容成本极高（旧名永久占用、下游依赖断裂）。所以「定名」要用户拍板，且要事先核实候选名在 crates.io/npm 未被占用；本次已实测 crates.io API 可达、五个 workspace 包名均 404 未占用，占用状态确认为「无障碍」而非「未确认」。

### 立即执行动作

无（改名需先定名）。

**待用户**：核验候选并定名（若沿用 `syncbond`，按五个 workspace 包名覆盖执行改名工作线；crates.io 占用已实测确认未占用）。

### 明确不做/延后

- 不代用户定名、不启动改名工作线（等用户给候选）。
- 不把 crates.io 占用状态写成未确认（已实测确认未占用）。
- 不 bump version、不打 tag、不建 Release、不跑发版 workflow。

---

## 条目 2：npm 发布（todo.md:39 P3 区块，待拍板#1 同源）

**事实**：`todo.md:39`——BLOCKED：用户输入。用户已令「不发布任何 npm 稳定包」；`npm whoami` → ENEEDAUTH（未登录），scope `@cuihairu/syncbond` 归属无从确认；`npm view syncbond`/`@cuihairu/syncbond` 均 404（未占用，但仅本地视图）；`packages/ts-bindings/package.json` 包名为 `@syncbond/bindings-ts`（workspace 私有名，非发布目标）。

### 推荐决策

**暂缓，需用户输入。** 维持「不发布任何 npm 稳定包」；待用户 `npm adduser` 登录并确认 `@cuihairu` scope 归属后，按全局红线由用户给出版本号+发布令方可发布。

### 理由（成本/收益/风险）

1. **收益**：遵守用户明令（不发布 npm 稳定包）与全局发布红线（版本号只能由用户手动给）。
2. **成本**：零——不发布即无发布成本；workspace 私有名 `@syncbond/bindings-ts` 不受影响（非发布目标）。
3. **风险（不做）**：暂无 npm 发布需求，维持现状无风险敞口。
4. **风险（硬做）**：未登录状态下无法确认 scope 归属，若强行发布到错误 scope/未授权 scope，会污染公共命名空间或发布失败；且品牌改名（条目 1）可能先于发布改变最终包名，现在发布=把临时名固化。
5. **教学性**：为什么发布前要先 `npm adduser`？npm 的 `@scope/pkg` 是**账号所有**的命名空间，发布前必须证明你对 `@cuihairu` 有权限（登录即验证身份+scope 归属），否则 npm 拒绝；这正是「未登录（ENEEDAUTH）→ 无法确认归属」的原因。发布是**对外不可逆**动作，故必须用户登录+给出版本号+发布令三重门控。

### 立即执行动作

无。

**待用户**：`npm adduser` 登录并确认 `@cuihairu` scope 归属；并按全局红线给出版本号 + 发布令（禁止我自判断）。

### 明确不做/延后

- 不发布任何 npm 稳定包、不代用户确认 scope、不代用户给版本号。
- 不 bump version、不打 tag、不建 Release、不跑发版 workflow。

---

## 条目 3：自动轮换触发（todo.md:47 待拍板#5）

**事实**：`todo.md:47`——成员移除是否由核心自动 rotate（当前 rotate 是应用手动调用）。代码事实：`crates/syncbond-core/src/crypto.rs:160-162` 明文「`rotate()` mints the next epoch key. **Distribution of the new key is the application's job** through the surviving members' channels — a revoked device that only holds epoch N keys cannot read epoch N+1 envelopes」；`crypto.rs:198-204` 的 `rotate()` 只 mint 并返回新键，**不自动分发**；`member_crypto.rs:184-207` 的 `rotate_for_removal()` 已把「移除成员 + 轮换 + 为每个幸存成员生成一条认证分发消息」打包为原子 API，返回 `RotationResult` 交由调用方（应用）投递。

### 推荐决策

**代决拍板：维持现状——rotate 保持应用显式调用（推荐 `rotate_for_removal`），不把 rotate 改为核心自动。** 已按 2026-10-14 授权口径代决，可后续推翻。

### 理由（成本/收益/风险）

1. **架构事实（核心无对端信道）**：核心是纯加密库（`KeyRing`），没有「怎么联系到每个幸存设备」的传输通道——`crypto.rs:160-162` 明文把分发列为应用职责。核心若「自动 rotate」却无法自动分发，新键只存在于发起设备本地。
2. **风险（若改自动，核心无法自证分发成功）**：自动 rotate 而无可靠分发 → 幸存成员仍持旧 epoch 键 → 组内新信封打不开（epoch 严格递增、旧键解不了新 epoch，`crypto.rs:160-162`「cannot read epoch N+1」）→ **组收敛静默破坏**。syncbond 第一优先级即「协议安全与收敛正确性」（todo 已述），此路径直接违背。
3. **收益（维持现状已够）**：`rotate_for_removal`（`member_crypto.rs:186`）已是原子组合——一次调用得「移除+轮换+每个幸存成员的分发消息」，**消除了「忘了轮换」的常见缺陷诱因**；剩余唯一风险（分发网络失败）本就属应用信道，核心无法代劳，自动改不了。
4. **成本**：维持现状零改动、零回归；改自动需引入「核心→对端传输」抽象，破坏核心「纯加密/无 IO」边界，且需跨语言（C/C++/C#/Go/Java/Python/napi/WASM）同步改契约，成本高、风险大。
5. **教学性**：轮换不是「换把锁」——新键必须**可靠送达每个仍在组的设备**，否则还在组里的设备拿着旧钥匙开不了新锁。所以轮换的本质是「原子地移除+换钥+广播」三步，核心做了前两步并打包好广播内容（`RotationResult`），最后一步「广播送达」只能是应用的信道，因为只有应用知道怎么联系到每个设备。把广播塞进核心=核心必须假装它联系得上设备，这是它做不到的。

### 立即执行动作

无（纯决策维持，不改代码、不涉版本）。

### 明确不做/延后

- 不把 rotate 改为核心自动、不引入核心→对端传输抽象、不新增跨语言契约改动。
- 不改 `KeyRing::rotate`/`rotate_for_removal` 现有语义。
- 不 bump version、不打 tag、不建 Release、不跑发版 workflow。

---

## 小结

| 条目 | 推荐决策 | 立即动作 | 状态 |
|---|---|---|---|
| 最终品牌名（todo.md:38） | 暂缓，待用户定名 | 无 | 需用户输入，暂缓 |
| npm 发布（todo.md:39） | 暂缓，维持不发布 | 无 | 需用户输入，暂缓 |
| 自动轮换触发（todo.md:47） | 维持应用显式 rotate_for_removal，不自动 | 无 | 已代决拍板 |
| 跨版本协商（todo.md:31,45） | 既有已代决：不支持/不开放（2026-10-28） | 无 | 已代决，维持 |
| 墓碑降级 GC（todo.md:34,46） | 既有已代决：不支持/不开放（2026-10-28） | 无 | 已代决，维持 |
