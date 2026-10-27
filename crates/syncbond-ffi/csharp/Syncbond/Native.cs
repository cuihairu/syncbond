using System.Reflection;
using System.Runtime.InteropServices;

namespace Syncbond;

/// <summary>
/// The P/Invoke surface over the syncbond C ABI. This is the only class that
/// calls into native code; the public wrappers delegate here. The methods
/// mirror syncbond.h one for one and add nothing but marshalling. The native
/// library is resolved through <see cref="SYNCBOND_NATIVE"/> (an absolute
/// path to libsyncbond_ffi.so) or by the default loader.
/// </summary>
internal static class Native
{
    private const string Lib = "syncbond_ffi";

    internal const int ErrNone = 0;
    internal const int ErrProtocol = -1;
    internal const int ErrInput = -2;
    internal const int ErrVersionMismatch = -3;
    internal const int ErrCrossGroup = -4;
    internal const int ErrKeyEpochMismatch = -5;
    internal const int ErrReplay = -6;
    internal const int ErrAuthFailed = -7;
    internal const int ErrInternal = -8;
    internal const int ResultAbsent = 1;

    internal const uint StrategyLwwHlc = 0;
    internal const uint StrategyOrSet = 1;
    internal const uint StrategyPnCounter = 2;

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);
    }

    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (name != Lib)
        {
            return IntPtr.Zero;
        }
        string? explicitPath = Environment.GetEnvironmentVariable("SYNCBOND_NATIVE");
        if (!string.IsNullOrEmpty(explicitPath) && File.Exists(explicitPath))
        {
            return NativeLibrary.Load(explicitPath);
        }
        if (NativeLibrary.TryLoad(Lib, out IntPtr handle))
        {
            return handle;
        }
        return IntPtr.Zero;
    }

    /// <summary>Throw a <see cref="SyncbondException"/> for a negative result.</summary>
    internal static void Check(int code)
    {
        if (code < 0)
        {
            throw Error(code);
        }
    }

    /// <summary>The precise thread-local code, falling back to the in-band code.</summary>
    internal static SyncbondException Error(int inBand)
    {
        int precise = LastErrorCode();
        if (precise == ErrNone)
        {
            precise = inBand;
        }
        string message = LastError();
        return new SyncbondException(precise, message);
    }

    // ------------------------------------------------------------- version
    [DllImport(Lib, EntryPoint = "sb_abi_version", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint AbiVersion();

    [DllImport(Lib, EntryPoint = "sb_protocol_version", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint ProtocolVersion();

    [DllImport(Lib, EntryPoint = "sb_last_error_code", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int LastErrorCode();

    [DllImport(Lib, EntryPoint = "sb_last_error", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr LastErrorNative();

    [DllImport(Lib, EntryPoint = "sb_free_string", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void FreeString(IntPtr text);

    [DllImport(Lib, EntryPoint = "sb_free_buffer", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void FreeBuffer(ref SbBuffer buffer);

    [StructLayout(LayoutKind.Sequential)]
    internal struct SbBuffer
    {
        internal IntPtr Data;
        internal nuint Len;
        internal nuint Cap;
    }

    /// <summary>Copy an owned C string into a managed string, then free it.</summary>
    internal static string TakeString(IntPtr owned)
    {
        if (owned == IntPtr.Zero)
        {
            throw Error(ErrInput);
        }
        string text = Marshal.PtrToStringUTF8(owned) ?? "";
        FreeString(owned);
        return text;
    }

    /// <summary>Copy an owned C buffer into a managed byte array, then free it.</summary>
    internal static byte[] TakeBuffer(ref SbBuffer buffer)
    {
        if (buffer.Data == IntPtr.Zero)
        {
            FreeBuffer(ref buffer);
            throw Error(ErrInput);
        }
        byte[] bytes = new byte[(int)buffer.Len];
        if (buffer.Len > 0)
        {
            Marshal.Copy(buffer.Data, bytes, 0, (int)buffer.Len);
        }
        FreeBuffer(ref buffer);
        return bytes;
    }

    internal static string LastError()
    {
        IntPtr text = LastErrorNative();
        return text == IntPtr.Zero ? "" : Marshal.PtrToStringUTF8(text) ?? "";
    }

    // ------------------------------------------------------------- identity
    [DllImport(Lib, EntryPoint = "sb_identity_generate", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr IdentityGenerate();

    [DllImport(Lib, EntryPoint = "sb_identity_import", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr IdentityImport(byte[] secretKey, nuint len);

    [DllImport(Lib, EntryPoint = "sb_identity_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void IdentityFree(IntPtr identity);

    [DllImport(Lib, EntryPoint = "sb_identity_device_id", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr IdentityDeviceId(IntPtr identity);

    [DllImport(Lib, EntryPoint = "sb_identity_public_key", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int IdentityPublicKey(IntPtr identity, byte[] outPublicKey);

    [DllImport(Lib, EntryPoint = "sb_identity_secret_key", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int IdentitySecretKey(IntPtr identity, byte[] outSecretKey);

    internal static string TakeIdentityDeviceId(IntPtr identity) =>
        TakeString(IdentityDeviceId(identity));

    // -------------------------------------------------------------- pairing
    [DllImport(Lib, EntryPoint = "sb_pair_memory", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr PairMemory([MarshalAs(UnmanagedType.LPUTF8Str)] string? code);

    [DllImport(Lib, EntryPoint = "sb_pair_result_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void PairResultFree(IntPtr result);

    [DllImport(Lib, EntryPoint = "sb_pair_result_code", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr PairResultCode(IntPtr result);

    [DllImport(Lib, EntryPoint = "sb_pair_result_initiator", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr PairResultInitiator(IntPtr result);

    [DllImport(Lib, EntryPoint = "sb_pair_result_responder", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr PairResultResponder(IntPtr result);

    internal static string TakePairResultCode(IntPtr result) =>
        TakeString(PairResultCode(result));

    // -------------------------------------------------------------- session
    [DllImport(Lib, EntryPoint = "sb_session_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void SessionFree(IntPtr session);

    [DllImport(Lib, EntryPoint = "sb_session_group_id", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr SessionGroupId(IntPtr session);

    [DllImport(Lib, EntryPoint = "sb_session_peer_device_id", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr SessionPeerDeviceId(IntPtr session);

    [DllImport(Lib, EntryPoint = "sb_session_invalidated", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int SessionInvalidated(IntPtr session);

    [DllImport(Lib, EntryPoint = "sb_session_send", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int SessionSend(IntPtr session, byte[] payload, nuint len);

    [DllImport(Lib, EntryPoint = "sb_session_recv", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int SessionRecv(IntPtr session, out SbBuffer outPayload);

    [DllImport(Lib, EntryPoint = "sb_session_invalidate", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int SessionInvalidate(IntPtr session);

    internal static string TakeSessionGroupId(IntPtr session) =>
        TakeString(SessionGroupId(session));

    internal static string TakeSessionPeerDeviceId(IntPtr session) =>
        TakeString(SessionPeerDeviceId(session));

    // ---------------------------------------------------------- replicator
    [DllImport(Lib, EntryPoint = "sb_replicator_new", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr ReplicatorNew(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string nodeId, uint strategy);

    [DllImport(Lib, EntryPoint = "sb_replicator_new_fixed_clock", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr ReplicatorNewFixedClock(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string nodeId, uint strategy, ulong nowMs);

    [DllImport(Lib, EntryPoint = "sb_replicator_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ReplicatorFree(IntPtr replicator);

    [DllImport(Lib, EntryPoint = "sb_replicator_node_id", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ReplicatorNodeId(IntPtr replicator);

    [DllImport(Lib, EntryPoint = "sb_replicator_record_count", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint ReplicatorRecordCount(IntPtr replicator);

    [DllImport(Lib, EntryPoint = "sb_replicator_oplog_len", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint ReplicatorOplogLen(IntPtr replicator);

    [DllImport(Lib, EntryPoint = "sb_replicator_put", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ReplicatorPut(
        IntPtr replicator, [MarshalAs(UnmanagedType.LPUTF8Str)] string key, byte[] payload, nuint len);

    [DllImport(Lib, EntryPoint = "sb_replicator_delete", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ReplicatorDelete(
        IntPtr replicator, [MarshalAs(UnmanagedType.LPUTF8Str)] string key);

    [DllImport(Lib, EntryPoint = "sb_replicator_get", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ReplicatorGet(
        IntPtr replicator, [MarshalAs(UnmanagedType.LPUTF8Str)] string key, out SbBuffer outPayload);

    [DllImport(Lib, EntryPoint = "sb_replicator_live_keys_json", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ReplicatorLiveKeysJson(IntPtr replicator);

    [DllImport(Lib, EntryPoint = "sb_replicator_op_json", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ReplicatorOpJson(IntPtr replicator, uint index);

    [DllImport(Lib, EntryPoint = "sb_replicator_apply_remote_json", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ReplicatorApplyRemoteJson(
        IntPtr replicator, [MarshalAs(UnmanagedType.LPUTF8Str)] string opJson);

    [DllImport(Lib, EntryPoint = "sb_replicator_sync", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ReplicatorSync(
        IntPtr replicator, IntPtr session, int sendFirst, out uint outSentOps);

    [DllImport(Lib, EntryPoint = "sb_replicator_records_json", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ReplicatorRecordsJson(IntPtr replicator);

    [DllImport(Lib, EntryPoint = "sb_replicator_gc_barriers_json", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ReplicatorGcBarriersJson(IntPtr replicator);

    [DllImport(Lib, EntryPoint = "sb_replicator_gc_tombstones", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int ReplicatorGcTombstones(
        IntPtr replicator, ulong nowMs, ulong olderThanMs);

    internal static string TakeReplicatorNodeId(IntPtr r) => TakeString(ReplicatorNodeId(r));
    internal static string TakeReplicatorLiveKeysJson(IntPtr r) => TakeString(ReplicatorLiveKeysJson(r));
    internal static string TakeReplicatorOpJson(IntPtr r, uint index) => TakeString(ReplicatorOpJson(r, index));
    internal static string TakeReplicatorRecordsJson(IntPtr r) => TakeString(ReplicatorRecordsJson(r));
    internal static string TakeReplicatorGcBarriersJson(IntPtr r) =>
        TakeString(ReplicatorGcBarriersJson(r));

    // -------------------------------------------------------------- keyring
    [DllImport(Lib, EntryPoint = "sb_keyring_new", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr KeyringNew([MarshalAs(UnmanagedType.LPUTF8Str)] string groupId);

    [DllImport(Lib, EntryPoint = "sb_keyring_import", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr KeyringImport(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string groupId, ulong epoch, byte[] key);

    [DllImport(Lib, EntryPoint = "sb_keyring_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void KeyringFree(IntPtr keyring);

    [DllImport(Lib, EntryPoint = "sb_keyring_epoch", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ulong KeyringEpoch(IntPtr keyring);

    [DllImport(Lib, EntryPoint = "sb_keyring_rotate", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int KeyringRotate(IntPtr keyring, out ulong outEpoch, byte[] outKey);

    [DllImport(Lib, EntryPoint = "sb_keyring_seal_json", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr KeyringSealJson(
        IntPtr keyring, [MarshalAs(UnmanagedType.LPUTF8Str)] string senderDeviceId,
        byte[] plaintext, nuint len);

    [DllImport(Lib, EntryPoint = "sb_keyring_open_json", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int KeyringOpenJson(
        IntPtr keyring, [MarshalAs(UnmanagedType.LPUTF8Str)] string envelopeJson,
        out SbBuffer outPayload);

    internal static string TakeKeyringSealJson(IntPtr keyring, string senderDeviceId, byte[] plaintext) =>
        TakeString(KeyringSealJson(keyring, senderDeviceId, plaintext, (nuint)plaintext.Length));

    // --------------------------------------------------------- conformance
    [DllImport(Lib, EntryPoint = "sb_conformance_run", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ConformanceRun([MarshalAs(UnmanagedType.LPUTF8Str)] string fixtureJson);

    internal static string TakeConformanceRun(string fixtureJson) => TakeString(ConformanceRun(fixtureJson));
}
