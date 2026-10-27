using Microsoft.Win32.SafeHandles;

namespace Syncbond;

/// <summary>
/// One native handle released by an <c>sb_*_free</c> function. Deriving from
/// <see cref="SafeHandle"/> gives every wrapper <see cref="IDisposable"/>
/// plus a finalizer backstop, so a handle is released exactly once whether it
/// is disposed explicitly or the wrapper becomes unreachable.
/// </summary>
internal abstract class SbHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    protected SbHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    /// <summary>The raw handle, or throw when this handle was released.</summary>
    internal IntPtr GetHandle()
    {
        if (IsClosed || IsInvalid)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
        return DangerousGetHandle();
    }
}

internal sealed class IdentityHandle : SbHandle
{
    internal IdentityHandle(IntPtr handle) : base(handle) { }

    protected override bool ReleaseHandle()
    {
        Native.IdentityFree(handle);
        return true;
    }
}

internal sealed class SessionHandle : SbHandle
{
    internal SessionHandle(IntPtr handle) : base(handle) { }

    protected override bool ReleaseHandle()
    {
        Native.SessionFree(handle);
        return true;
    }
}

internal sealed class ReplicatorHandle : SbHandle
{
    internal ReplicatorHandle(IntPtr handle) : base(handle) { }

    protected override bool ReleaseHandle()
    {
        Native.ReplicatorFree(handle);
        return true;
    }
}

internal sealed class KeyringHandle : SbHandle
{
    internal KeyringHandle(IntPtr handle) : base(handle) { }

    protected override bool ReleaseHandle()
    {
        Native.KeyringFree(handle);
        return true;
    }
}
