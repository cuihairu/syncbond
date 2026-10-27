using System.Text;
using Syncbond;
using Xunit;

namespace Syncbond.Tests;

/// <summary>Mirrors the Java / Go / Python suites over the same C ABI.</summary>
public sealed class SyncbondTests
{
    private static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);

    private static string Text(byte[] data) => Encoding.UTF8.GetString(data);

    private const string Fixture = """
        {
          "version": 1,
          "scenarios": [
            {
              "type": "replication",
              "name": "lww",
              "strategy": "lww",
              "nodes": {"left": 1000, "right": 2000},
              "steps": [
                {"put": {"node": "left", "key": "k", "payload": "bGVmdA"}},
                {"put": {"node": "right", "key": "k", "payload": "cmlnaHQ"}},
                {"sync": ["left", "right"]},
                {"check": {"node": "left", "key": "k", "state": "live", "payload": "cmlnaHQ", "name": "left_sees_newer_write"}},
                {"check": {"node": "right", "key": "k", "state": "live", "payload": "cmlnaHQ", "name": "right_keeps_newer_write"}}
              ]
            },
            {
              "type": "key_epoch",
              "name": "rotation",
              "group": "g",
              "epoch": 1,
              "next_epoch": 2,
              "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              "next_key": "__________________________________________8",
              "survivors": ["s1"],
              "removed": ["gone"],
              "plaintext": "cGF5bG9hZA"
            }
          ]
        }
        """;

    [Fact]
    public void AbiAndProtocolVersions()
    {
        Assert.Equal(1u, Syncbond.AbiVersion());
        Assert.Equal(1u, Syncbond.ProtocolVersion());
    }

    [Fact]
    public void IdentityRoundTrip()
    {
        using Identity generated = Identity.Generate();
        byte[] secret = generated.SecretKey;
        Assert.Equal(64, secret.Length);
        string deviceId = generated.DeviceId;
        byte[] publicKey = generated.PublicKey;
        Assert.Equal(32, publicKey.Length);

        using Identity rebuilt = Identity.ImportSecret(secret);
        Assert.Equal(deviceId, rebuilt.DeviceId);
        Assert.Equal(publicKey, rebuilt.PublicKey);
        Assert.Equal(secret, rebuilt.SecretKey);
    }

    [Fact]
    public void PairProducesMatchingGroupIds()
    {
        using PairResult pair = Syncbond.PairMemory(null);
        Assert.Equal(6, pair.Code.Length);
        Assert.Equal(pair.Initiator.GroupId, pair.Responder.GroupId);
        Assert.False(string.IsNullOrEmpty(pair.Initiator.PeerDeviceId));
        Assert.False(pair.Initiator.Invalidated);
        Assert.False(pair.Responder.Invalidated);
    }

    [Fact]
    public void ReplicatedPutConverges()
    {
        using PairResult pair = Syncbond.PairMemory(null);
        using Replicator left = new("left", Syncbond.StrategyLwwHlc, 1000);
        using Replicator right = new("right", Syncbond.StrategyLwwHlc, 2000);
        left.Put("k", Utf8("hello"));
        (uint initiatorOps, _) =
            Replicator.SyncPair(left, right, pair.Initiator, pair.Responder);
        Assert.True(initiatorOps >= 1, "initiator should send the op");
        Assert.Equal(Utf8("hello"), right.Get("k"));
        Assert.Equal(left.RecordsJson, right.RecordsJson);
    }

    [Fact]
    public void DeleteReplicates()
    {
        using PairResult pair = Syncbond.PairMemory(null);
        using Replicator left = new("left", Syncbond.StrategyLwwHlc, 1000);
        using Replicator right = new("right", Syncbond.StrategyLwwHlc, 2000);
        left.Put("old", Utf8("v"));
        left.Delete("old");
        Replicator.SyncPair(left, right, pair.Initiator, pair.Responder);
        Assert.Null(right.Get("old"));
        Assert.Null(left.Get("old"));
        Assert.Equal(0, right.GcTombstones(3000, 5000));
    }

    [Fact]
    public void LaterWriteWins()
    {
        using PairResult pair = Syncbond.PairMemory(null);
        using Replicator left = new("left", Syncbond.StrategyLwwHlc, 1000);
        using Replicator right = new("right", Syncbond.StrategyLwwHlc, 2000);
        left.Put("k", Utf8("first"));
        right.Put("k", Utf8("second"));
        Replicator.SyncPair(left, right, pair.Initiator, pair.Responder);
        Assert.Equal(Utf8("second"), left.Get("k"));
        Assert.Equal(Utf8("second"), right.Get("k"));
    }

    [Fact]
    public void InvalidatedSessionRejectsSend()
    {
        using PairResult pair = Syncbond.PairMemory(null);
        pair.Initiator.Invalidate();
        Assert.True(pair.Initiator.Invalidated);
        Assert.Throws<SyncbondException>(() => pair.Initiator.Send(Utf8("late")));
        Assert.NotEqual(Syncbond.ErrNone, Syncbond.LastErrorCode());
    }

    [Fact]
    public void SessionSendRecv()
    {
        using PairResult pair = Syncbond.PairMemory(null);
        pair.Initiator.Send(Utf8("ping"));
        pair.Responder.Send(Utf8("pong"));
        Assert.Equal("pong", Text(pair.Initiator.Recv()));
        Assert.Equal("ping", Text(pair.Responder.Recv()));
    }

    [Fact]
    public void KeyEpochRotationBlocksRemovedDevice()
    {
        byte[] preKey = new byte[32];
        Array.Fill(preKey, (byte)1);
        byte[] nextKey = new byte[32];
        Array.Fill(nextKey, (byte)2);

        using Keyring survivor = new("g", 2, nextKey);
        using Keyring removed = new("g", 1, preKey);
        Assert.Equal(2ul, survivor.Epoch);
        Assert.Equal(1ul, removed.Epoch);

        string envelope = survivor.SealJson("s1", Utf8("payload after rotation"));
        Assert.Equal(Utf8("payload after rotation"), survivor.OpenJson(envelope));

        SyncbondException error =
            Assert.Throws<SyncbondException>(() => removed.OpenJson(envelope));
        Assert.Equal(Syncbond.ErrKeyEpochMismatch, error.Code);
    }

    [Fact]
    public void EnvelopeReplayRejected()
    {
        byte[] key = new byte[32];
        Array.Fill(key, (byte)3);
        using Keyring ring = new("g", 1, key);
        string envelope = ring.SealJson("s1", Utf8("once"));
        Assert.Equal(Utf8("once"), ring.OpenJson(envelope));
        SyncbondException error = Assert.Throws<SyncbondException>(() => ring.OpenJson(envelope));
        Assert.Equal(Syncbond.ErrReplay, error.Code);
    }

    [Fact]
    public void DisposeIsIdempotent()
    {
        Identity identity = Identity.Generate();
        identity.Dispose();
        identity.Dispose(); // must not double-free or throw
        Assert.Throws<ObjectDisposedException>(() => _ = identity.DeviceId);
    }

    [Fact]
    public void ConformanceReportOk()
    {
        string report = Syncbond.ConformanceRun(Fixture);
        Assert.Contains("\"ok\":true", report);
        Assert.Contains("\"type\":\"replication\"", report);
        Assert.Contains("\"type\":\"key_epoch\"", report);
    }

    [Fact]
    public void ConformanceRotationCheckRejectedDevice()
    {
        string report = Syncbond.ConformanceRun(Fixture);
        Assert.Contains("\"name\":\"removed_device_cannot_open_envelope_sealed_after_rotation\"", report);
        Assert.Contains("\"rotated_error\":-5", report);
    }
}
