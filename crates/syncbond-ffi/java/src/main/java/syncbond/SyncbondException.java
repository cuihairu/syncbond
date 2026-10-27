package syncbond;

/** One syncbond failure carrying the stable SB_ERR_* code. */
public class SyncbondException extends RuntimeException {
    private final int code;

    public SyncbondException(int code, String message) {
        super(message == null || message.isEmpty()
                ? "syncbond: error " + code
                : "syncbond: " + message + " (code " + code + ")");
        this.code = code;
    }

    /** The SB_ERR_* code from syncbond.h. */
    public int getCode() {
        return code;
    }
}
