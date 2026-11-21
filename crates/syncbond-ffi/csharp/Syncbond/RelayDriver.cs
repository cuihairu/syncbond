namespace Syncbond;

/// <summary>
/// One relay channel driver over the C ABI. The native driver owns the whole
/// network session — the relay client, the runtime and one worker thread that
/// runs the core loop — plus the device state. The host only configures,
/// starts, stops and interleaves writes; the relay protocol never has to be
/// rewritten in C#.
///
/// The four native handles the driver needs (identity, keyring, replicator,
/// receive state) are built in <see cref="Open(Config)"/> and their ownership
/// transfers to the driver on success AND on failure, matching the ABI
/// contract, so none of them is a separate <see cref="SbHandle"/> of its own
/// (a double free).
/// </summary>
public sealed class RelayDriver : IDisposable
{
    /// <summary>TLS certificate checking strictness, mirroring SB_TLS_*.</summary>
    public const int TlsValidate = Native.TlsValidate;
    public const int TlsValidateCa = Native.TlsValidateCa;
    public const int TlsAcceptInvalid = Native.TlsAcceptInvalid;

    /// <summary>Why the loop ended, mirroring SB_DRIVER_STOP_*.</summary>
    public const int DriverStopNone = Native.DriverStopNone;
    public const int DriverStopCancelled = Native.DriverStopCancelled;
    public const int DriverStopExhausted = Native.DriverStopExhausted;
    public const int DriverStopFatal = Native.DriverStopFatal;

    /// <summary>Everything <see cref="Open(Config)"/> needs; the fields mirror the C ABI call.</summary>
    public sealed class Config
    {
        public string RelayUrl = "";
        public string ChannelId = "";
        public string ChannelToken = "";
        public string ServerId = "";
        public string CursorChannel = "";
        public string GroupId = "";
        public ulong KeyEpoch = 1;
        /// <summary>Shared 32-byte group key material; two devices in one group import the same bytes.</summary>
        public byte[] GroupKey = Array.Empty<byte>();
        /// <summary>Names a fresh replicator; ignored when <see cref="State"/> restores one.</summary>
        public string NodeId = "";
        public ulong TimeoutMs = 5000;
        public int TlsMode = TlsValidate;
        /// <summary>Pins a CA (DER) when <see cref="TlsMode"/> is <see cref="TlsValidateCa"/>.</summary>
        public byte[]? CaDer;
        /// <summary>An exported snapshot to resume from; null or empty starts fresh.</summary>
        public byte[]? State;
    }

    private readonly RelayDriverHandle handle;

    private RelayDriver(IntPtr native) => handle = new RelayDriverHandle(native);

    /// <summary>Builds a driver over one live relay channel.</summary>
    public static RelayDriver Open(Config config)
    {
        if (config.GroupKey is not { Length: 32 })
        {
            throw new SyncbondException(Native.ErrInput, "group key must be exactly 32 bytes");
        }
        // Fresh handles per attempt; if any of them fails, free the ones
        // already created before returning. Once sb_relay_driver_new is called
        // it owns all four on success AND on failure, so neither path frees
        // them here.
        IntPtr identity = Native.IdentityGenerate();
        if (identity == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        IntPtr keyring = IntPtr.Zero;
        IntPtr replicator = IntPtr.Zero;
        IntPtr receive = IntPtr.Zero;
        try
        {
            keyring = Native.KeyringImport(config.GroupId, config.KeyEpoch, config.GroupKey);
            if (keyring == IntPtr.Zero)
            {
                throw Native.Error(Native.ErrInput);
            }
            if (config.State is { Length: > 0 } blob)
            {
                Native.Check(Native.StateImport(
                    blob, (nuint)blob.Length, Syncbond.StrategyLwwHlc,
                    out replicator, out receive));
            }
            else
            {
                replicator = Native.ReplicatorNew(config.NodeId, Syncbond.StrategyLwwHlc);
                if (replicator == IntPtr.Zero)
                {
                    throw Native.Error(Native.ErrInput);
                }
                receive = Native.ReceiveStateNew();
                if (receive == IntPtr.Zero)
                {
                    throw Native.Error(Native.ErrInput);
                }
            }
        }
        catch
        {
            Native.IdentityFree(identity);
            if (keyring != IntPtr.Zero)
            {
                Native.KeyringFree(keyring);
            }
            if (replicator != IntPtr.Zero)
            {
                Native.ReplicatorFree(replicator);
            }
            if (receive != IntPtr.Zero)
            {
                Native.ReceiveStateFree(receive);
            }
            throw;
        }
        IntPtr driver = Native.RelayDriverNew(
            config.RelayUrl, config.ChannelId, config.ChannelToken, config.ServerId,
            config.CursorChannel, config.GroupId, config.KeyEpoch, identity, keyring,
            replicator, receive, config.TimeoutMs, (uint)config.TlsMode,
            config.CaDer, config.CaDer is { Length: > 0 } ca ? (nuint)ca.Length : 0u);
        if (driver == IntPtr.Zero)
        {
            // The library freed identity, keyring, replicator and receive
            // already; nothing to release on this side.
            throw Native.Error(Native.ErrInput);
        }
        return new RelayDriver(driver);
    }

    private IntPtr RawHandle => handle.GetHandle();

    /// <summary>Replaces the loop's pacing knobs; only effective before <see cref="Start"/>.</summary>
    public void Configure(int pageLimit, long maxPagesPerCycle, long initialBackoffMs,
                          long maxBackoffMs, int maxAttempts, long idleIntervalMs) =>
        Native.Check(Native.RelayDriverConfig(
            RawHandle, (ushort)pageLimit, (nuint)maxPagesPerCycle, (ulong)initialBackoffMs,
            (ulong)maxBackoffMs, (uint)maxAttempts, (ulong)idleIntervalMs));

    /// <summary>Spawns the worker thread; a second start while running is an input error.</summary>
    public void Start() => Native.Check(Native.RelayDriverStart(RawHandle));

    /// <summary>Cancels the loop and joins the worker; idempotent.</summary>
    public void Stop() => Native.Check(Native.RelayDriverStop(RawHandle));

    /// <summary>Stages a local write; the worker sends it on its next cycle.</summary>
    public void Write(string key, byte[] payload) =>
        Native.Check(Native.RelayDriverWrite(RawHandle, key, payload, (nuint)payload.Length));

    /// <summary>Stages a local delete (a causal tombstone), like <see cref="Write"/>.</summary>
    public void Delete(string key) => Native.Check(Native.RelayDriverDelete(RawHandle, key));

    /// <summary>The live payload, or null when the key is absent or tombstoned.</summary>
    public byte[]? Get(string key)
    {
        int code = Native.RelayDriverGet(RawHandle, key, out Native.SbBuffer buffer);
        if (code == Native.ResultAbsent)
        {
            return null;
        }
        Native.Check(code);
        return Native.TakeBuffer(ref buffer);
    }

    /// <summary>Whether the worker thread is up.</summary>
    public bool Running => Native.RelayDriverRunning(RawHandle) != 0;

    /// <summary>The monotonic counters (and the running flag).</summary>
    public RelayProgress Progress
    {
        get
        {
            Native.Check(Native.RelayDriverProgress(RawHandle, out Native.SbRelayProgress progress));
            return new RelayProgress(
                progress.Running != 0, progress.Cycles, progress.SentBatches,
                progress.SentEnvelopes, progress.PagesPulled, progress.Applied);
        }
    }

    /// <summary>One of the DriverStop* values; None while running or never started.</summary>
    public int StopReason => Native.RelayDriverStopReason(RawHandle);

    /// <summary>The text of the error that ended the loop, or null when it ended cleanly.</summary>
    public string? Error => Native.TakeRelayDriverError(RawHandle);

    /// <summary>
    /// The device state plus the receive cursors as one versioned snapshot, the
    /// blob a later <see cref="Config.State"/> restores from. The blob is
    /// private (it embeds the device identity); guard it accordingly.
    /// </summary>
    public byte[] ExportState()
    {
        Native.Check(Native.RelayDriverExportState(RawHandle, out Native.SbBuffer snapshot));
        return Native.TakeBuffer(ref snapshot);
    }

    /// <summary>Stops the worker (joining it) and releases the driver; idempotent.</summary>
    public void Dispose() => handle.Dispose();
}

/// <summary>The monotonic counters a running relay driver has accumulated.</summary>
public sealed record RelayProgress(
    bool Running, ulong Cycles, ulong SentBatches, ulong SentEnvelopes,
    ulong PagesPulled, ulong Applied);
