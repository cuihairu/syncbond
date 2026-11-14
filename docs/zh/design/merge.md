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

### 各策略下的 `deleted` 标志语义

`Record.deleted` 标志只有 `LwwHlc` 采纳——它把删除变成因果墓碑（`Replicator::delete` 写入 `deleted: true`）。在 `OrSetStrategy` 与 `PnCounterStrategy` 下 `deleted` 标志被**忽略**：合并结果恒为 `deleted: false`，对这些策略调用 `Replicator::delete` 不产生墓碑。需要在 OR-Set 下表达移除的应用须经 payload 表达（退役元素的标签）；PN-Counter 根本没有删除——移除以递减建模（或把该键切换为 `LwwHlc` 墓碑）。不要依赖 `deleted: true` 在非 `LwwHlc` 策略下移除值。

注意：在 `OrSetStrategy` 或 `PnCounterStrategy` 下调用 `Replicator::delete` **不会**作为空操作成功——删除操作携带空 payload，这两个策略的 `merge` 会将其当作 JSON 解码，因此以 `MergeError` 拒绝（空文档不是合法的 OR-Set / PN-Counter JSON）。调用失败且记录保持不变——应用必须改经 payload 表达移除（退役 OR-Set 元素的标签，或递减 PN-Counter）。

### LwwHlc 规则（默认策略）

合并是对双方所知全部版本的集合运算——本地主版本连同其保留的 `conflicts`，加上传入写入连同它携带的 conflicts——按戳去重：

1. **被支配的版本被淘汰。** 只要该池中*任意*版本的 witness 都能证明它观察过某个版本的戳，该版本即被支配。要看整个池，而不只是交换的两端：被保留的 conflict 携带其作者的 witness，因此被 `B` 支配的 `A` 在 `C` 成为主版本之后仍然被支配。携带过期编辑重连的旧设备因此无法复活已删除的记录——墓碑的 witness 占优（测试：`old_device_reconnect_cannot_resurrect_a_delete`）。
2. **并发的幸存者全部保留。** 戳最高的幸存者成为主版本，其余保留在 `conflicts` 中交由应用裁决。冲突集合是规范化过的：按戳去重并排序，因此双向合并产生同一集合（测试：`example_2_note_documents_with_offline_conflict`）。
3. **时钟超前（run-ahead）。** 若传入戳声称的墙钟时间比本地超前超过 `max_skew_ms`（默认 5 分钟），则无论因果性如何都按并发处理——损坏的设备时钟不能静默覆盖本地状态；超前的写入被保留并标记。只要有正常的幸存者存在，超前戳就不会赢得主版本，因此失控的时钟不压制任何值。空记录路径执行同一策略（`MergeOutcome.skew_detected` 同样被置位），异常的首次写入被标记而非静默接受。本地 HLC 还会拒绝采纳超前的远端戳（`HybridClock::receive`）。测试：`large_clock_skew_does_not_silently_overwrite`、`empty_record_path_flags_a_future_write`、`future_write_outcome_is_order_independent_and_trackable`。
4. **支配知识不会丢弃。** 被支配版本的 witness 会被并入合并结果的 witness。否则一个已被支配的版本重投时可能作为幽灵冲突存活下来（测试：`independent_writes_converge_under_every_delivery_order`）。

## 墓碑垃圾回收（已实现）

`Replicator::gc_tombstones(now_ms, older_than_ms)` 只有当**两个**条件同时满足时才收墓碑：

1. **时间**：`now_ms - tombstone.stamp.pt >= older_than_ms`，且
2. **因果支配**：每个已知副本对该键的 witness 都支配墓碑的戳。副本器从 op witness 累积的 witness 表**就是**副本向量——不需要单独的心跳协议，它随 relay 同步一起走。支配检查只覆盖我们有证据的副本：从未听到过的副本只是不在向量中，并不阻塞收簇。收簇安全不依赖该缺席——压实后的 barrier 会拒绝合并中输给墓碑的稍后重投删除前写入；从未听到副本的并发高戳写入仍按既有 LWW 规则胜出并可重建该键，与 GC 前行为一致（`concurrent_higher_stamp_write_resurrects_a_collected_delete`）。

被收簇的墓碑**并没有被删除**。它被压实成一条 barrier 条目（`gc_barriers`，剥掉 payload 与保留冲突，保留戳与 witness），该键的 oplog 历史塌缩为唯一的墓碑 op。barrier 正是保证所在：GC 后重投、在合并中输给墓碑的删除前写入会被 barrier 拒绝而不是复活该删除（`stale_put_cannot_resurrect_a_collected_delete`）；从未听到删除的副本的并发高戳写入仍按既有 LWW 规则胜出并可重建该键，与 GC 前行为一致（`concurrent_higher_stamp_write_resurrects_a_collected_delete`）。保留的墓碑 op 让新副本仍能得知删除，因此压实形态对每个被删键只花 O(1)，且从不降级任何对端的视图。

两个值得注意的推论：

- 被垃圾回收后的状态可安全重启：barrier 属于 `SyncState`（`#[serde(default)]`，GC 之前的快照原样加载），重放复现压实形态（`gc_compacts_the_oplog_and_survives_a_restart`）。
- 压实过的对端与未压实的对端收敛；墓碑在走，payload 不走（`compacted_peer_converges_with_an_uncompacted_peer`）。

只看时间阈值的降级模式**刻意不是**稳定的应用选项：它豁免证据要求，可能从仍携带删除前历史的对端重新物化已收簇的键。Rust 方法标了 `#[doc(hidden)]`，只能经 conformance fixture runner 的 `gc` 步骤（`mode: "time_only"`）或显式选择加入的 Rust 下游触达；C ABI 与稳定语言绑定只暴露支配检查模式。默认关闭，也不作为应用选项写档。

## 收敛性论证

- LWW 合并是投递版本集合的规范函数，与合并顺序无关：支配与排序只读戳与 witness，冲突集合经规范化（按戳去重并排序），超集支配知识留在合并记录的 witness 里。同一组写入的任意投递排列产生同一主版本与同一规范化冲突集合（测试：`independent_writes_converge_under_every_delivery_order`——A=1000 / B=900 已观察 A / C=950 矩阵覆盖全部六种投递顺序——以及 `multi_node_permutation_convergence_property`，在确定性 witness DAG 上穷举 `n!` 种投递排列）。
- OR-Set 的添加/移除并集是半格（semilattice）；观察移除对未观察到的标签给出添加获胜。
- PN-Counter 的按节点最大值是半格。
- 上述策略下，操作投递是幂等的（op-id 去重）且与顺序无关，因此乱序 + 重复投递收敛（测试：`out_of_order_and_duplicate_delivery_converge`、`example_3_arbitrary_binary_records`）。
