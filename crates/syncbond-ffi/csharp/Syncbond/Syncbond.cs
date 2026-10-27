namespace Syncbond;

/// <summary>Static entry points and the constants mirroring syncbond.h.</summary>
public static class Syncbond
{
    public const int ErrNone = Native.ErrNone;
    public const int ErrProtocol = Native.ErrProtocol;
    public const int ErrInput = Native.ErrInput;
    public const int ErrVersionMismatch = Native.ErrVersionMismatch;
    public const int ErrCrossGroup = Native.ErrCrossGroup;
    public const int ErrKeyEpochMismatch = Native.ErrKeyEpochMismatch;
    public const int ErrReplay = Native.ErrReplay;
    public const int ErrAuthFailed = Native.ErrAuthFailed;
    public const int ErrInternal = Native.ErrInternal;
    public const int ResultAbsent = Native.ResultAbsent;

    public const uint StrategyLwwHlc = Native.StrategyLwwHlc;
    public const uint StrategyOrSet = Native.StrategyOrSet;
    public const uint StrategyPnCounter = Native.StrategyPnCounter;

    public static uint AbiVersion() => Native.AbiVersion();

    public static uint ProtocolVersion() => Native.ProtocolVersion();

    /// <summary>Last SB_ERR_* code of the calling thread, mirroring the C ABI.</summary>
    public static int LastErrorCode() => Native.LastErrorCode();

    /// <summary>Last error text of the calling thread, mirroring the C ABI.</summary>
    public static string LastError() => Native.LastError();

    /// <summary>
    /// Pairs two freshly generated devices over an in-memory loopback; an
    /// empty or null code lets the library generate one. Both sides of the
    /// handshake run inside the call.
    /// </summary>
    public static PairResult PairMemory(string? code)
    {
        string? effective = string.IsNullOrEmpty(code) ? null : code;
        return new PairResult(Native.PairMemory(effective));
    }

    /// <summary>Runs a cross-language conformance fixture, returning canonical JSON.</summary>
    public static string ConformanceRun(string fixtureJson) => Native.TakeConformanceRun(fixtureJson);
}
