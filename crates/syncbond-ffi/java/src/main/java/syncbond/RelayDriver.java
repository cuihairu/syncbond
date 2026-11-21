package syncbond;

/**
 * One relay channel driver over the C ABI. The native driver owns the whole
 * network session — the relay client, the runtime and one worker thread that
 * runs the core loop — plus the device state. The host only configures,
 * starts, stops and interleaves writes; the relay protocol never has to be
 * rewritten in Java.
 *
 * <p>The four native handles the driver needs (identity, keyring, replicator,
 * receive state) are built here and their ownership transfers to the driver on
 * success AND on failure, matching the ABI contract, so none of them is ever
 * wrapped in a {@link NativeHandle} of its own (a double free).
 */
public final class RelayDriver implements AutoCloseable {
    /** TLS certificate checking strictness, mirroring SB_TLS_*. */
    public static final int TLS_VALIDATE = Native.TLS_VALIDATE;
    public static final int TLS_VALIDATE_CA = Native.TLS_VALIDATE_CA;
    public static final int TLS_ACCEPT_INVALID = Native.TLS_ACCEPT_INVALID;

    /** Why the loop ended, mirroring SB_DRIVER_STOP_*. */
    public static final int DRIVER_STOP_NONE = Native.DRIVER_STOP_NONE;
    public static final int DRIVER_STOP_CANCELLED = Native.DRIVER_STOP_CANCELLED;
    public static final int DRIVER_STOP_EXHAUSTED = Native.DRIVER_STOP_EXHAUSTED;
    public static final int DRIVER_STOP_FATAL = Native.DRIVER_STOP_FATAL;

    /** The monotonic counters a running driver has accumulated. */
    public static final class Progress {
        public final boolean running;
        public final long cycles;
        public final long sentBatches;
        public final long sentEnvelopes;
        public final long pagesPulled;
        public final long applied;

        Progress(boolean running, long cycles, long sentBatches, long sentEnvelopes,
                 long pagesPulled, long applied) {
            this.running = running;
            this.cycles = cycles;
            this.sentBatches = sentBatches;
            this.sentEnvelopes = sentEnvelopes;
            this.pagesPulled = pagesPulled;
            this.applied = applied;
        }
    }

    /** Everything {@link #open} needs; the fields mirror the C ABI call. */
    public static final class Config {
        public String relayUrl;
        public String channelId;
        public String channelToken;
        public String serverId;
        public String cursorChannel;
        public String groupId;
        public long keyEpoch = 1;
        /** Shared 32-byte group key material; two devices in one group import the same bytes. */
        public byte[] groupKey;
        /** Names a fresh replicator; ignored when {@code state} restores one. */
        public String nodeId;
        public long timeoutMs = 5000;
        public int tlsMode = Native.TLS_VALIDATE;
        /** Pins a CA (DER) when {@code tlsMode} is {@link #TLS_VALIDATE_CA}. */
        public byte[] caDer;
        /** An exported snapshot to resume from; null or empty starts fresh. */
        public byte[] state;
    }

    private final NativeHandle nativeHandle;

    private RelayDriver(long handle) {
        this.nativeHandle = new NativeHandle(handle, Native::relayDriverFree);
    }

    /** Builds a driver over one live relay channel. */
    public static RelayDriver open(Config config) {
        if (config.groupKey == null || config.groupKey.length != 32) {
            throw new SyncbondException(
                    Native.ERR_INPUT, "group key must be exactly 32 bytes");
        }
        // Fresh handles per attempt; if any of them fails, free the ones
        // already created before returning. Once sb_relay_driver_new is
        // called it owns all four on success AND on failure, so neither
        // path frees them here.
        long identity = Native.identityGenerate();
        long keyring = 0;
        long replicator = 0;
        long receive = 0;
        try {
            keyring = Native.keyringImport(config.groupId, config.keyEpoch, config.groupKey);
            if (config.state != null && config.state.length > 0) {
                long[] restored = Native.stateImport(config.state, Native.STRATEGY_LWW_HLC);
                replicator = restored[0];
                receive = restored[1];
            } else {
                replicator = Native.replicatorNew(config.nodeId, Native.STRATEGY_LWW_HLC);
                receive = Native.receiveStateNew();
            }
        } catch (RuntimeException error) {
            Native.identityFree(identity);
            if (keyring != 0) {
                Native.keyringFree(keyring);
            }
            if (replicator != 0) {
                Native.replicatorFree(replicator);
            }
            if (receive != 0) {
                Native.receiveStateFree(receive);
            }
            throw error;
        }
        long driver = Native.relayDriverNew(
                config.relayUrl, config.channelId, config.channelToken,
                config.serverId, config.cursorChannel, config.groupId, config.keyEpoch,
                identity, keyring, replicator, receive, config.timeoutMs,
                config.tlsMode, config.caDer);
        return new RelayDriver(driver); // 0 already threw from the native side
    }

    /** Replaces the loop's pacing knobs; only effective before {@link #start}. */
    public void config(int pageLimit, long maxPagesPerCycle, long initialBackoffMs,
                       long maxBackoffMs, long maxAttempts, long idleIntervalMs) {
        Native.relayDriverConfig(nativeHandle.get(), pageLimit, maxPagesPerCycle,
                initialBackoffMs, maxBackoffMs, maxAttempts, idleIntervalMs);
    }

    /** Spawns the worker thread; a second start while running is an input error. */
    public void start() {
        Native.relayDriverStart(nativeHandle.get());
    }

    /** Cancels the loop and joins the worker; idempotent. */
    public void stop() {
        Native.relayDriverStop(nativeHandle.get());
    }

    /** Stages a local write; the worker sends it on its next cycle. */
    public void write(String key, byte[] payload) {
        Native.relayDriverWrite(nativeHandle.get(), key, payload);
    }

    /** Stages a local delete (a causal tombstone), like {@link #write}. */
    public void delete(String key) {
        Native.relayDriverDelete(nativeHandle.get(), key);
    }

    /** The live payload, or null when the key is absent or tombstoned. */
    public byte[] get(String key) {
        return Native.relayDriverGet(nativeHandle.get(), key);
    }

    /** Whether the worker thread is up. */
    public boolean running() {
        return Native.relayDriverRunning(nativeHandle.get()) != 0;
    }

    /** The monotonic counters (and the running flag). */
    public Progress progress() {
        long[] p = Native.relayDriverProgress(nativeHandle.get());
        return new Progress(p[0] != 0, p[1], p[2], p[3], p[4], p[5]);
    }

    /** One of the {@code DRIVER_STOP_*} values; {@code NONE} while running. */
    public int stopReason() {
        return Native.relayDriverStopReason(nativeHandle.get());
    }

    /** The text of the error that ended the loop, or null when it ended cleanly. */
    public String error() {
        return Native.relayDriverError(nativeHandle.get());
    }

    /**
     * The device state plus the receive cursors as one versioned snapshot, the
     * blob a later {@link Config#state} restores from. The blob is private (it
     * embeds the device identity); guard it accordingly.
     */
    public byte[] exportState() {
        return Native.relayDriverExportState(nativeHandle.get());
    }

    @Override
    public void close() {
        nativeHandle.close();
    }
}
