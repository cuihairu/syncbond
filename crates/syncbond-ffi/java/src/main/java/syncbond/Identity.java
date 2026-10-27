package syncbond;

/** One device's Ed25519 key material. */
public final class Identity implements AutoCloseable {
    private final NativeHandle nativeHandle;

    private Identity(long handle) {
        this.nativeHandle = new NativeHandle(handle, Native::identityFree);
    }

    /** Generate a fresh identity. */
    public static Identity generate() {
        return new Identity(Native.identityGenerate());
    }

    /** Rebuild an identity from a persisted 64-byte keypair. */
    public static Identity importSecret(byte[] secretKey) {
        return new Identity(Native.identityImport(secretKey));
    }

    public String deviceId() {
        return Native.identityDeviceId(nativeHandle.get());
    }

    public byte[] publicKey() {
        return Native.identityPublicKey(nativeHandle.get());
    }

    public byte[] secretKey() {
        return Native.identitySecretKey(nativeHandle.get());
    }

    @Override
    public void close() {
        nativeHandle.close();
    }
}
