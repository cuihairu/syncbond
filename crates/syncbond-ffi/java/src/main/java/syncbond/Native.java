package syncbond;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * The JNI surface over the syncbond C ABI. This is the only class that calls
 * into native code; the public wrappers delegate here. The methods mirror
 * syncbond.h one for one and add nothing but JNI type conversion.
 *
 * <p>The native library is resolved at class-load time: first from the
 * {@code syncbond.lib} system property or the {@code SYNCBOND_LIB}
 * environment variable (an absolute path), then from
 * {@code java.library.path} (as {@code syncbond_java}), then from a
 * build-relative location under the repository. Either explicit location
 * should name the JNI shim; the shim carries a runtime dependency on the C
 * ABI shared library next to it.
 */
final class Native {
    private Native() {}

    static final int ERR_NONE = 0;
    static final int ERR_PROTOCOL = -1;
    static final int ERR_INPUT = -2;
    static final int ERR_VERSION_MISMATCH = -3;
    static final int ERR_CROSS_GROUP = -4;
    static final int ERR_KEY_EPOCH_MISMATCH = -5;
    static final int ERR_REPLAY = -6;
    static final int ERR_AUTH_FAILED = -7;
    static final int ERR_INTERNAL = -8;
    static final int RESULT_ABSENT = 1;

    static final int STRATEGY_LWW_HLC = 0;
    static final int STRATEGY_OR_SET = 1;
    static final int STRATEGY_PN_COUNTER = 2;

    static final int TLS_VALIDATE = 0;
    static final int TLS_VALIDATE_CA = 1;
    static final int TLS_ACCEPT_INVALID = 2;

    static final int DRIVER_STOP_NONE = 0;
    static final int DRIVER_STOP_CANCELLED = 1;
    static final int DRIVER_STOP_EXHAUSTED = 2;
    static final int DRIVER_STOP_FATAL = 3;

    static {
        load();
    }

    private static void load() {
        // Prefer an explicit path; it makes the test and example hermetic.
        // The system property is set by the Gradle test task; the environment
        // variable is for ad-hoc runs. Either names the JNI shim.
        String explicit = System.getProperty("syncbond.lib");
        if (explicit == null || explicit.isEmpty()) {
            explicit = System.getenv("SYNCBOND_LIB");
        }
        if (explicit != null && !explicit.isEmpty()) {
            System.load(Paths.get(explicit).toAbsolutePath().toString());
            return;
        }
        // Allow java.library.path (System.loadLibrary).
        try {
            System.loadLibrary("syncbond_java");
            return;
        } catch (UnsatisfiedLinkError ignored) {
            // Fall through to the repository-relative location.
        }
        // Development fallback: the Gradle build drops the shim here.
        String[] candidates = {
            "crates/syncbond-ffi/java/build/libs/libsyncbond_java.so",
            "../../target/ffi-java/libsyncbond_java.so",
        };
        for (String candidate : candidates) {
            Path path = Paths.get(candidate);
            if (Files.exists(path)) {
                System.load(path.toAbsolutePath().toString());
                return;
            }
        }
        throw new UnsatisfiedLinkError(
                "syncbond native library not found; set SYNCBOND_LIB to the "
                        + "libsyncbond_java.so path or add its directory to java.library.path");
    }

    // ------------------------------------------------------------- version
    static native int abiVersion();
    static native int protocolVersion();
    static native int lastErrorCode();
    static native String lastError();

    // ------------------------------------------------------------ identity
    static native long identityGenerate();
    static native long identityImport(byte[] secretKey);
    static native void identityFree(long handle);
    static native String identityDeviceId(long handle);
    static native byte[] identityPublicKey(long handle);
    static native byte[] identitySecretKey(long handle);

    // ------------------------------------------------------------ pairing
    static native long pairMemory(String code);
    static native void pairFree(long handle);
    static native String pairCode(long handle);
    static native long pairInitiator(long handle);
    static native long pairResponder(long handle);

    // ------------------------------------------------------------- session
    static native void sessionFree(long handle);
    static native String sessionGroupId(long handle);
    static native String sessionPeerDeviceId(long handle);
    static native boolean sessionInvalidated(long handle);
    static native void sessionSend(long handle, byte[] payload);
    static native byte[] sessionRecv(long handle);
    static native void sessionInvalidate(long handle);

    // --------------------------------------------------------- replicator
    static native long replicatorNew(String nodeId, int strategy);
    static native long replicatorNewFixed(String nodeId, int strategy, long nowMs);
    static native void replicatorFree(long handle);
    static native String replicatorNodeId(long handle);
    static native int replicatorRecordCount(long handle);
    static native int replicatorOplogLen(long handle);
    static native void replicatorPut(long handle, String key, byte[] payload);
    static native void replicatorDelete(long handle, String key);
    /** Returns null when the key is absent or tombstoned. */
    static native byte[] replicatorGet(long handle, String key);
    static native String replicatorLiveKeysJson(long handle);
    static native String replicatorOpJson(long handle, int index);
    static native boolean replicatorApplyRemoteJson(long handle, String opJson);
    static native int replicatorSync(long handle, long sessionHandle, boolean sendFirst);
    static native String replicatorRecordsJson(long handle);
    static native String replicatorGcBarriersJson(long handle);
    static native int replicatorGcTombstones(long handle, long nowMs, long olderThanMs);

    // --------------------------------------------------------- key material
    static native long keyringNew(String groupId);
    static native long keyringImport(String groupId, long epoch, byte[] key);
    static native void keyringFree(long handle);
    static native long keyringEpoch(long handle);
    /** Fills {@code outKey} (32 bytes) and returns the new epoch. */
    static native long keyringRotate(long handle, byte[] outKey);
    static native String keyringSealJson(long handle, String senderDeviceId, byte[] plaintext);
    static native byte[] keyringOpenJson(long handle, String envelopeJson);

    // ---------------------------------------------------------- conformance
    static native String conformanceRun(String fixtureJson);

    // ------------------------------------------------------- receive state
    static native long receiveStateNew();
    static native void receiveStateFree(long handle);

    // --------------------------------------------------------- state import
    /** Restores {replicator, receive}; throws on a version mismatch. */
    static native long[] stateImport(byte[] blob, int strategy);

    // ------------------------------------------------------- relay driver
    static native long relayDriverNew(String relayUrl, String channelId,
                                      String channelToken, String serverId, String cursorChannel,
                                      String groupId, long keyEpoch, long identity, long keyring,
                                      long replicator, long receive, long timeoutMs, int tlsMode,
                                      byte[] caDer);
    static native void relayDriverFree(long handle);
    static native int relayDriverConfig(long handle, int pageLimit, long maxPagesPerCycle,
                                        long initialBackoffMs, long maxBackoffMs, long maxAttempts,
                                        long idleIntervalMs);
    static native int relayDriverStart(long handle);
    static native int relayDriverStop(long handle);
    static native int relayDriverWrite(long handle, String key, byte[] payload);
    static native int relayDriverDelete(long handle, String key);
    /** null when the key has no live value; throws on other failures. */
    static native byte[] relayDriverGet(long handle, String key);
    static native int relayDriverRunning(long handle);
    /** {running, cycles, sentBatches, sentEnvelopes, pagesPulled, applied}. */
    static native long[] relayDriverProgress(long handle);
    static native int relayDriverStopReason(long handle);
    static native String relayDriverError(long handle);
    static native byte[] relayDriverExportState(long handle);
}
