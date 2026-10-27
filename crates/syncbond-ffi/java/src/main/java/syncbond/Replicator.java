package syncbond;

/** One synchronizing device. */
public final class Replicator implements AutoCloseable {
    private final NativeHandle nativeHandle;

    /** Creates a replicator on the wall clock; strategy is a {@code STRATEGY_*} value. */
    public Replicator(String nodeId, int strategy) {
        this.nativeHandle = new NativeHandle(
                Native.replicatorNew(nodeId, strategy), Native::replicatorFree);
    }

    /** Creates a replicator on a frozen clock, which makes runs reproducible. */
    public Replicator(String nodeId, int strategy, long nowMs) {
        this.nativeHandle = new NativeHandle(
                Native.replicatorNewFixed(nodeId, strategy, nowMs), Native::replicatorFree);
    }

    public String nodeId() {
        return Native.replicatorNodeId(nativeHandle.get());
    }

    public int recordCount() {
        return Native.replicatorRecordCount(nativeHandle.get());
    }

    public int oplogLen() {
        return Native.replicatorOplogLen(nativeHandle.get());
    }

    public void put(String key, byte[] payload) {
        Native.replicatorPut(nativeHandle.get(), key, payload);
    }

    public void delete(String key) {
        Native.replicatorDelete(nativeHandle.get(), key);
    }

    /** The live payload under a key, or null when absent or tombstoned. */
    public byte[] get(String key) {
        return Native.replicatorGet(nativeHandle.get(), key);
    }

    public String liveKeysJson() {
        return Native.replicatorLiveKeysJson(nativeHandle.get());
    }

    public String opJson(int index) {
        return Native.replicatorOpJson(nativeHandle.get(), index);
    }

    /** Applies one wire op; false when it was a duplicate or rejected. */
    public boolean applyRemoteJson(String opJson) {
        return Native.replicatorApplyRemoteJson(nativeHandle.get(), opJson);
    }

    /** One blocking direction of the oplog exchange; returns ops sent. */
    public int sync(Session session, boolean sendFirst) {
        return Native.replicatorSync(nativeHandle.get(), session.rawHandle(), sendFirst);
    }

    public String recordsJson() {
        return Native.replicatorRecordsJson(nativeHandle.get());
    }

    public String gcBarriersJson() {
        return Native.replicatorGcBarriersJson(nativeHandle.get());
    }

    /** Collects causally dominated tombstones older than {@code olderThanMs}. */
    public int gcTombstones(long nowMs, long olderThanMs) {
        return Native.replicatorGcTombstones(nativeHandle.get(), nowMs, olderThanMs);
    }

    /**
     * Runs both directions of one oplog exchange. The responder half blocks in
     * its direction, so it runs on a worker thread; the two halves use
     * distinct handles, matching the ABI's single-thread-per-handle rule.
     * Returns {@code {initiator ops, responder ops}}.
     */
    public static int[] syncPair(Replicator left, Replicator right,
                                 Session initiator, Session responder) {
        int[] rightOps = new int[1];
        RuntimeException[] failure = new RuntimeException[1];
        Thread worker = new Thread(() -> {
            try {
                rightOps[0] = right.sync(responder, false);
            } catch (RuntimeException error) {
                failure[0] = error;
            }
        });
        worker.start();
        int leftOps;
        try {
            leftOps = left.sync(initiator, true);
        } finally {
            try {
                worker.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SyncbondException(Native.ERR_INTERNAL, "interrupted joining sync thread");
            }
        }
        if (failure[0] != null) {
            throw failure[0];
        }
        return new int[] {leftOps, rightOps[0]};
    }

    @Override
    public void close() {
        nativeHandle.close();
    }
}
