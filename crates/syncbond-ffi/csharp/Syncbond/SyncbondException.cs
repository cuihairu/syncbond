namespace Syncbond;

/// <summary>One syncbond failure carrying the stable SB_ERR_* code.</summary>
public sealed class SyncbondException : Exception
{
    /// <summary>The SB_ERR_* code from syncbond.h.</summary>
    public int Code { get; }

    public SyncbondException(int code, string message)
        : base(string.IsNullOrEmpty(message) ? $"syncbond: error {code}" : $"syncbond: {message} (code {code})")
    {
        Code = code;
    }
}
