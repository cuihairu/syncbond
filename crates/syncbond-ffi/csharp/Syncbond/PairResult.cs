namespace Syncbond;

/// <summary>Both sessions produced by one pairing handshake.</summary>
public sealed class PairResult : IDisposable
{
    private readonly Session initiator;
    private readonly Session responder;

    internal PairResult(IntPtr resultHandle)
    {
        if (resultHandle == IntPtr.Zero)
        {
            throw Native.Error(Native.ErrInput);
        }
        // Each call returns a fresh handle; the caller frees both.
        initiator = new Session(Native.PairResultInitiator(resultHandle));
        responder = new Session(Native.PairResultResponder(resultHandle));
        Code = Native.TakePairResultCode(resultHandle);
        Native.PairResultFree(resultHandle);
    }

    public string Code { get; }

    public Session Initiator => initiator;

    public Session Responder => responder;

    public void Dispose()
    {
        initiator.Dispose();
        responder.Dispose();
    }
}
