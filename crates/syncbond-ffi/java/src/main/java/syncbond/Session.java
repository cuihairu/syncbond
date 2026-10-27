package syncbond;

/** One authenticated, encrypted end of a pairing. */
public final class Session implements AutoCloseable {
    private final NativeHandle nativeHandle;

    Session(long handle) {
        this.nativeHandle = new NativeHandle(handle, Native::sessionFree);
    }

    public String groupId() {
        return Native.sessionGroupId(nativeHandle.get());
    }

    public String peerDeviceId() {
        return Native.sessionPeerDeviceId(nativeHandle.get());
    }

    public boolean invalidated() {
        return Native.sessionInvalidated(nativeHandle.get());
    }

    /** Encrypt and enqueue one application payload. */
    public void send(byte[] payload) {
        Native.sessionSend(nativeHandle.get(), payload);
    }

    /** Blocking: decrypt and return the next application payload. */
    public byte[] recv() {
        return Native.sessionRecv(nativeHandle.get());
    }

    /** Mark the session dead (removed device). */
    public void invalidate() {
        Native.sessionInvalidate(nativeHandle.get());
    }

    /** The raw handle, for sibling wrappers. */
    long rawHandle() {
        return nativeHandle.get();
    }

    @Override
    public void close() {
        nativeHandle.close();
    }
}
