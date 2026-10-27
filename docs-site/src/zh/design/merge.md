[English](../../design/merge.md)

# 合并设计：可插拔策略（v1）

状态：已在 `crates/syncbond-core/src/conflict.rs` 与 `src/replication.rs` 中实现。

## 原则

SDK 不知道数据是什么含义。合并行为是应用在一个 trait 背后做出的选择：

```rust
pub trait MergeStrategy: Send + Sync {
    fn merge(
        &self,
        local: Option<&Record>,
        incoming: &Record,
        ctx: &MergeContext,
    ) -> Result<MergeOutcome, MergeError>;
}
```

一个 `Record` 携带：不透明的 `payload`、`deleted` 标志、`stamp`（HLC 戳）、`witness`（节点 → 写入时最后见到的完整 HLC 戳），以及保留的 `conflicts`。下文的内置策略只是便利设施，从不是强加的语义。

`merge` 是可失败的：解释自身载荷的策略（OR-Set、PN-Counter）遇到畸形文档时
返回 `MergeError` 而不是 panic，因此每个语言绑定都上报相同的显式错误。

## 因果性：完整戳 witness

一次写入的 `witness` 按节点记录完整的最后所见 `HlcStamp`（pt、ct、id）——而不只是计数器。当 HLC 物理分量前进时计数器会归零，因此只含计数器的 witness 会跨越时钟秒边界静默丢失"已见过"的事实。使用完整戳后：

- `A` 因果后于 `B` 当且仅当 `A.witness[B.stamp.id] >= B.stamp`（戳排序）；
- 互不后于 → 并发。

有因果序的合并是无歧义且单调的；只有并发写入才会进入策略层裁决。

## 内置策略

| 策略 | 语义 | 为何作为默认 |
|---|---|---|
| `LwwHlc` | 按 HLC 排序的 last-writer-wins（最后写入者胜），因果墓碑（tombstone），并发版本保留 | 对普通属性而言最廉价且正确的默认 |
| `OrSetStrategy` | 基于规范化 JSON 文档的 OR-Set（观察移除集合）（添加 = 元素 → 标签，移除 = 退役标签） | 收藏/标签：未观察到的移除之上并发添加获胜 |
| `PnCounterStrategy` | 两个 G-Counter（inc/dec），按节点取最大值合并 | 离线时不能丢失增量的计数器 |

### LwwHlc 规则（默认策略）

1. 有因果序：后代获胜。携带过期编辑重连的旧设备无法复活已删除的记录——墓碑的 witness 占优（测试：`old_device_reconnect_cannot_resurrect_a_delete`）。
2. 并发写入：两者都保留。戳较高的成为主版本；落败者追加到 `conflicts`（按戳去重），交由应用裁决（测试：`example_2_note_documents_with_offline_conflict`）。
3. 时钟超前（run-ahead）：若传入戳声称的墙钟时间比本地超前超过 `max_skew_ms`（默认 5 分钟），则无论因果性如何都按并发处理——损坏的设备时钟不能静默覆盖本地状态；超前的写入被保留并标记（测试：`large_clock_skew_does_not_silently_overwrite`）。本地 HLC 还会拒绝采纳超前的远端戳（`HybridClock::receive`）。

## 墓碑垃圾回收（设计，尚未实现）

只有当**两个**条件同时满足时，才允许丢弃墓碑：

1. **时间**：`now - tombstone.stamp.pt > retention`（默认提案：30 天），且
2. **因果支配**：每个已知副本对该键的 witness 都支配墓碑的戳——即不存在仍能投递"本应由墓碑杀死的写入"的存活对端。操作上这需要副本向量心跳，它将随 relay（P2）一起到来；在此之前 GC 仅以 `snapshot` 压实加基于时间的剪除形式暴露，完整的基于支配的 GC 是待决决策（todo.md）。

在不满足条件 2 的情况下丢弃墓碑，正是本模型要防止的复活 bug。

## 收敛性论证

- LWW 合并在记录上可交换且幂等（同戳短路、conflicts 去重）。
- OR-Set 的添加/移除并集是半格（semilattice）；观察移除对未观察到的标签给出添加获胜。
- PN-Counter 的按节点最大值是半格。
- 上述策略下，操作投递是幂等的（op-id 去重）且与顺序无关，因此乱序 + 重复投递收敛（测试：`out_of_order_and_duplicate_delivery_converge`、`example_3_arbitrary_binary_records`）。
