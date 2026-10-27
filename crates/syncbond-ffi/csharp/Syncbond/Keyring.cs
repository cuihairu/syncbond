namespace Syncbond;

/// <summary>Group key material with replay tracking for one device.</summary>
public sealed class Keyring : IDisposable
{
    /// <summary>A rotated epoch together with the new 32-byte key for distribution.</summary>
    public sealed record Rotation(ulong Epoch, byte[] Key);

    private readonly KeyringHandle handle;

    /// <summary>Starts a group at epoch 1.</summary>
    public Keyring(string groupId)
    {
        IntPtr native = Native.KeyringNew(groupId);
        if (native == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        handle = new KeyringHandle(native);
    }

    /// <summary>Rebuilds key material handed to this device by rotation.</summary>
    public Keyring(string groupId, ulong epoch, byte[] key)
    {
        IntPtr native = Native.KeyringImport(groupId, epoch, key);
        if (native == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        handle = new KeyringHandle(native);
    }

    private IntPtr RawHandle => handle.GetHandle();

    public ulong Epoch => Native.KeyringEpoch(RawHandle);

    /// <summary>Mints the next epoch and returns it with the new key.</summary>
    public Rotation Rotate()
    {
        byte[] key = new byte[32];
        Native.Check(Native.KeyringRotate(RawHandle, out ulong epoch, key));
        return new Rotation(epoch, key);
    }

    public string SealJson(string senderDeviceId, byte[] plaintext) =>
        Native.TakeKeyringSealJson(RawHandle, senderDeviceId, plaintext);

    public byte[] OpenJson(string envelopeJson)
    {
        Native.Check(Native.KeyringOpenJson(RawHandle, envelopeJson, out Native.SbBuffer buffer));
        return Native.TakeBuffer(ref buffer);
    }

    public void Dispose() => handle.Dispose();
}
