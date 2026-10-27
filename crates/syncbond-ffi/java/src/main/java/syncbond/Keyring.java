package syncbond;

/** Group key material with replay tracking for one device. */
public final class Keyring implements AutoCloseable {
    /** A rotated epoch together with the new 32-byte key for distribution. */
    public record Rotation(long epoch, byte[] key) {}

    private final NativeHandle nativeHandle;

    /** Starts a group at epoch 1. */
    public Keyring(String groupId) {
        this.nativeHandle = new NativeHandle(Native.keyringNew(groupId), Native::keyringFree);
    }

    /** Rebuilds key material handed to this device by rotation. */
    public Keyring(String groupId, long epoch, byte[] key) {
        this.nativeHandle =
                new NativeHandle(Native.keyringImport(groupId, epoch, key), Native::keyringFree);
    }

    public long epoch() {
        return Native.keyringEpoch(nativeHandle.get());
    }

    /** Mints the next epoch and returns it with the new key. */
    public Rotation rotate() {
        byte[] key = new byte[32];
        long epoch = Native.keyringRotate(nativeHandle.get(), key);
        return new Rotation(epoch, key);
    }

    public String sealJson(String senderDeviceId, byte[] plaintext) {
        return Native.keyringSealJson(nativeHandle.get(), senderDeviceId, plaintext);
    }

    public byte[] openJson(String envelopeJson) {
        return Native.keyringOpenJson(nativeHandle.get(), envelopeJson);
    }

    @Override
    public void close() {
        nativeHandle.close();
    }
}
