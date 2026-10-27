namespace Syncbond;

/// <summary>One device's Ed25519 key material.</summary>
public sealed class Identity : IDisposable
{
    private readonly IdentityHandle handle;

    private Identity(IntPtr nativeHandle)
    {
        if (nativeHandle == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        handle = new IdentityHandle(nativeHandle);
    }

    /// <summary>Generate a fresh identity.</summary>
    public static Identity Generate() => new(Native.IdentityGenerate());

    /// <summary>Rebuild an identity from a persisted 64-byte keypair.</summary>
    public static Identity ImportSecret(byte[] secretKey) =>
        new(Native.IdentityImport(secretKey, (nuint)secretKey.Length));

    public string DeviceId => Native.TakeIdentityDeviceId(handle.GetHandle());

    public byte[] PublicKey
    {
        get
        {
            byte[] key = new byte[32];
            Native.Check(Native.IdentityPublicKey(handle.GetHandle(), key));
            return key;
        }
    }

    public byte[] SecretKey
    {
        get
        {
            byte[] key = new byte[64];
            Native.Check(Native.IdentitySecretKey(handle.GetHandle(), key));
            return key;
        }
    }

    public void Dispose() => handle.Dispose();
}
