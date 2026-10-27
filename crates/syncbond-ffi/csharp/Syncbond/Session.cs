namespace Syncbond;

/// <summary>One authenticated, encrypted end of a pairing.</summary>
public sealed class Session : IDisposable
{
    private readonly SessionHandle handle;

    internal Session(IntPtr nativeHandle)
    {
        if (nativeHandle == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        handle = new SessionHandle(nativeHandle);
    }

    internal IntPtr RawHandle => handle.GetHandle();

    public string GroupId => Native.TakeSessionGroupId(RawHandle);

    public string PeerDeviceId => Native.TakeSessionPeerDeviceId(RawHandle);

    public bool Invalidated => Native.SessionInvalidated(RawHandle) != 0;

    /// <summary>Encrypt and enqueue one application payload.</summary>
    public void Send(byte[] payload) =>
        Native.Check(Native.SessionSend(RawHandle, payload, (nuint)payload.Length));

    /// <summary>Blocking: decrypt and return the next application payload.</summary>
    public byte[] Recv()
    {
        Native.Check(Native.SessionRecv(RawHandle, out Native.SbBuffer buffer));
        return Native.TakeBuffer(ref buffer);
    }

    /// <summary>Mark the session dead (removed device).</summary>
    public void Invalidate() => Native.Check(Native.SessionInvalidate(RawHandle));

    public void Dispose() => handle.Dispose();
}
