package syncbond;

/** Both sessions produced by one pairing handshake. */
public final class PairResult implements AutoCloseable {
    private final Session initiator;
    private final Session responder;
    private final String code;

    /** Extracts the two session handles and releases the transient result handle. */
    PairResult(long resultHandle) {
        this.initiator = new Session(Native.pairInitiator(resultHandle));
        this.responder = new Session(Native.pairResponder(resultHandle));
        this.code = Native.pairCode(resultHandle);
        Native.pairFree(resultHandle);
    }

    public String code() {
        return code;
    }

    public Session initiator() {
        return initiator;
    }

    public Session responder() {
        return responder;
    }

    @Override
    public void close() {
        initiator.close();
        responder.close();
    }
}
