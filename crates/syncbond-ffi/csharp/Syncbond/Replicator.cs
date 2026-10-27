namespace Syncbond;

/// <summary>One synchronizing device.</summary>
public sealed class Replicator : IDisposable
{
    private readonly ReplicatorHandle handle;

    /// <summary>Creates a replicator on the wall clock; strategy is a STRATEGY_* value.</summary>
    public Replicator(string nodeId, uint strategy)
    {
        IntPtr native = Native.ReplicatorNew(nodeId, strategy);
        if (native == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        handle = new ReplicatorHandle(native);
    }

    /// <summary>Creates a replicator on a frozen clock, which makes runs reproducible.</summary>
    public Replicator(string nodeId, uint strategy, ulong nowMs)
    {
        IntPtr native = Native.ReplicatorNewFixedClock(nodeId, strategy, nowMs);
        if (native == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        handle = new ReplicatorHandle(native);
    }

    private IntPtr RawHandle => handle.GetHandle();

    public string NodeId => Native.TakeReplicatorNodeId(RawHandle);

    public uint RecordCount => Native.ReplicatorRecordCount(RawHandle);

    public uint OplogLen => Native.ReplicatorOplogLen(RawHandle);

    public void Put(string key, byte[] payload) =>
        Native.Check(Native.ReplicatorPut(RawHandle, key, payload, (nuint)payload.Length));

    public void Delete(string key) => Native.Check(Native.ReplicatorDelete(RawHandle, key));

    /// <summary>The live payload under a key, or null when absent or tombstoned.</summary>
    public byte[]? Get(string key)
    {
        int code = Native.ReplicatorGet(RawHandle, key, out Native.SbBuffer buffer);
        if (code == Native.ResultAbsent)
        {
            return null;
        }
        Native.Check(code);
        return Native.TakeBuffer(ref buffer);
    }

    public string LiveKeysJson => Native.TakeReplicatorLiveKeysJson(RawHandle);

    public string OpJson(uint index) => Native.TakeReplicatorOpJson(RawHandle, index);

    /// <summary>Applies one wire op; true when it was applied.</summary>
    public bool ApplyRemoteJson(string opJson) =>
        Native.ReplicatorApplyRemoteJson(RawHandle, opJson) != 0;

    /// <summary>One blocking direction of the oplog exchange; returns ops sent.</summary>
    public uint Sync(Session session, bool sendFirst)
    {
        Native.Check(Native.ReplicatorSync(RawHandle, session.RawHandle, sendFirst ? 1 : 0, out uint sent));
        return sent;
    }

    public string RecordsJson => Native.TakeReplicatorRecordsJson(RawHandle);

    public string GcBarriersJson => Native.TakeReplicatorGcBarriersJson(RawHandle);

    /// <summary>Collects causally dominated tombstones older than <paramref name="olderThanMs"/>.</summary>
    public int GcTombstones(ulong nowMs, ulong olderThanMs) =>
        Native.ReplicatorGcTombstones(RawHandle, nowMs, olderThanMs);

    /// <summary>
    /// Runs both directions of one oplog exchange. The responder half blocks
    /// in its direction, so it runs on a worker thread; the two halves use
    /// distinct handles, matching the ABI's single-thread-per-handle rule.
    /// Returns (initiator ops, responder ops).
    /// </summary>
    public static (uint InitiatorOps, uint ResponderOps) SyncPair(
        Replicator left, Replicator right, Session initiator, Session responder)
    {
        uint responderOps = 0;
        Exception? failure = null;
        Thread worker = new(() =>
        {
            try
            {
                responderOps = right.Sync(responder, sendFirst: false);
            }
            catch (Exception error)
            {
                failure = error;
            }
        });
        worker.Start();
        uint initiatorOps;
        try
        {
            initiatorOps = left.Sync(initiator, sendFirst: true);
        }
        finally
        {
            worker.Join();
        }
        if (failure != null)
        {
            throw failure;
        }
        return (initiatorOps, responderOps);
    }

    public void Dispose() => handle.Dispose();
}
