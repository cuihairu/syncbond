package syncbond;

/** Static entry points and the constants mirroring syncbond.h. */
public final class Syncbond {
    private Syncbond() {}

    public static final int ERR_NONE = Native.ERR_NONE;
    public static final int ERR_PROTOCOL = Native.ERR_PROTOCOL;
    public static final int ERR_INPUT = Native.ERR_INPUT;
    public static final int ERR_VERSION_MISMATCH = Native.ERR_VERSION_MISMATCH;
    public static final int ERR_CROSS_GROUP = Native.ERR_CROSS_GROUP;
    public static final int ERR_KEY_EPOCH_MISMATCH = Native.ERR_KEY_EPOCH_MISMATCH;
    public static final int ERR_REPLAY = Native.ERR_REPLAY;
    public static final int ERR_AUTH_FAILED = Native.ERR_AUTH_FAILED;
    public static final int ERR_INTERNAL = Native.ERR_INTERNAL;
    public static final int RESULT_ABSENT = Native.RESULT_ABSENT;

    public static final int STRATEGY_LWW_HLC = Native.STRATEGY_LWW_HLC;
    public static final int STRATEGY_OR_SET = Native.STRATEGY_OR_SET;
    public static final int STRATEGY_PN_COUNTER = Native.STRATEGY_PN_COUNTER;

    public static int abiVersion() {
        return Native.abiVersion();
    }

    public static int protocolVersion() {
        return Native.protocolVersion();
    }

    /** Last SB_ERR_* code of the calling thread, mirroring the C ABI. */
    public static int lastErrorCode() {
        return Native.lastErrorCode();
    }

    /** Last error text of the calling thread, mirroring the C ABI. */
    public static String lastError() {
        return Native.lastError();
    }

    /**
     * Pairs two freshly generated devices over an in-memory loopback; an empty
     * or null code lets the library generate one. Both sides of the handshake
     * run inside the call.
     */
    public static PairResult pairMemory(String code) {
        String effective = code == null || code.isEmpty() ? null : code;
        return new PairResult(Native.pairMemory(effective));
    }

    /** Runs a cross-language conformance fixture, returning canonical JSON. */
    public static String conformanceRun(String fixtureJson) {
        return Native.conformanceRun(fixtureJson);
    }
}
