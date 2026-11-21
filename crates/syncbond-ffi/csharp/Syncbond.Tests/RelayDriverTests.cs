using System.Text;
using Syncbond;
using Xunit;

namespace Syncbond.Tests;

/// <summary>The P/Invoke lifecycle over a dead endpoint, mirroring the Go / Java suites.</summary>
public sealed class RelayDriverTests
{
    private static byte[] GroupKey()
    {
        byte[] key = new byte[32];
        Array.Fill(key, (byte)7);
        return key;
    }

    private static RelayDriver FreshDriver(string url, string channel, string token, string node)
    {
        return RelayDriver.Open(new RelayDriver.Config
        {
            RelayUrl = url,
            ChannelId = channel,
            ChannelToken = token,
            ServerId = "relay-1",
            CursorChannel = "ch",
            GroupId = "group-1",
            KeyEpoch = 1,
            GroupKey = GroupKey(),
            NodeId = node,
            TimeoutMs = 5000,
            TlsMode = RelayDriver.TlsValidate,
        });
    }

    private static void FastConfig(RelayDriver driver) =>
        driver.Configure(2, 8, 1, 2, 1000, 1);

    [Fact]
    public void BadArguments()
    {
        // A short group key is refused before any native call.
        SyncbondException shortKeyError = Assert.Throws<SyncbondException>(
            () => RelayDriver.Open(new RelayDriver.Config
            {
                RelayUrl = "http://127.0.0.1:1",
                ChannelId = "ch",
                ChannelToken = "tok",
                ServerId = "s",
                CursorChannel = "c",
                GroupId = "g",
                GroupKey = new byte[] { 1, 2, 3 },
                NodeId = "n",
            }));
        Assert.Equal(Syncbond.ErrInput, shortKeyError.Code);

        // An unknown tls mode is refused by the handle layer.
        Assert.Throws<SyncbondException>(
            () => RelayDriver.Open(new RelayDriver.Config
            {
                RelayUrl = "http://127.0.0.1:1",
                ChannelId = "ch",
                ChannelToken = "tok",
                ServerId = "s",
                CursorChannel = "c",
                GroupId = "g",
                GroupKey = GroupKey(),
                NodeId = "n",
                TlsMode = 7,
            }));

        // A zero timeout is refused too.
        Assert.Throws<SyncbondException>(
            () => RelayDriver.Open(new RelayDriver.Config
            {
                RelayUrl = "http://127.0.0.1:1",
                ChannelId = "ch",
                ChannelToken = "tok",
                ServerId = "s",
                CursorChannel = "c",
                GroupId = "g",
                GroupKey = GroupKey(),
                NodeId = "n",
                TimeoutMs = 0,
            }));
    }

    [Fact]
    public void DeadEndpointLifecycleAndState()
    {
        using RelayDriver driver = FreshDriver("http://127.0.0.1:1", "ch", "tok", "cs-dead");
        FastConfig(driver);

        Assert.False(driver.Running, "not running yet");
        Assert.Equal(RelayDriver.DriverStopNone, driver.StopReason);
        Assert.Null(driver.Error);
        Assert.False(driver.Progress.Running, "progress reports running before start");

        // Start spawns the worker, which retries the dead endpoint in a loop.
        driver.Start();
        Assert.True(driver.Running, "the worker is up");
        Assert.True(driver.Progress.Running, "progress reports running");

        // The host writes and reads through the marshalling layer.
        driver.Write("k", Encoding.UTF8.GetBytes("v"));
        Assert.Equal(Encoding.UTF8.GetBytes("v"), driver.Get("k"));
        Assert.Null(driver.Get("absent"));

        // The committed state exports with the write intact.
        byte[] blob = driver.ExportState();
        Assert.NotEmpty(blob);

        // A delete stages a tombstone.
        driver.Delete("k");
        Assert.Null(driver.Get("k"));

        // Stop cancels and joins; the reason is cancellation, not an error.
        driver.Stop();
        Assert.False(driver.Running, "the worker joined");
        Assert.Equal(RelayDriver.DriverStopCancelled, driver.StopReason);
        Assert.Null(driver.Error);
    }

    [Fact]
    public void RestoreFromState()
    {
        byte[] blob;
        using (RelayDriver driver = FreshDriver("http://127.0.0.1:1", "ch", "tok", "cs-first"))
        {
            FastConfig(driver);
            driver.Write("persist", Encoding.UTF8.GetBytes("p"));
            blob = driver.ExportState();
        }

        // A second driver rebuilt from the snapshot alone (a fresh node id,
        // which the state overrides) sees the committed write.
        using RelayDriver restored = RelayDriver.Open(new RelayDriver.Config
        {
            RelayUrl = "http://127.0.0.1:1",
            ChannelId = "ch",
            ChannelToken = "tok",
            ServerId = "relay-1",
            CursorChannel = "ch",
            GroupId = "group-1",
            KeyEpoch = 1,
            GroupKey = GroupKey(),
            NodeId = "different-node",
            TimeoutMs = 5000,
            TlsMode = RelayDriver.TlsValidate,
            State = blob,
        });
        Assert.Equal("p", Encoding.UTF8.GetString(restored.Get("persist")!));
    }

    [Fact]
    public void DisposeIsIdempotentAndStopsWorker()
    {
        // Double dispose is safe and a driver disposed while running joins its
        // worker instead of leaking the thread.
        RelayDriver driver = FreshDriver("http://127.0.0.1:1", "ch", "tok", "cs-idle");
        FastConfig(driver);
        driver.Start();
        driver.Dispose();
        driver.Dispose(); // idempotent
        Assert.Throws<ObjectDisposedException>(() => _ = driver.Running);

        // A started driver stopped once may start again after the stop.
        using RelayDriver restarted = FreshDriver("http://127.0.0.1:1", "ch", "tok", "cs-restart");
        FastConfig(restarted);
        restarted.Start();
        restarted.Stop();
        restarted.Start();
        restarted.Stop();
    }
}
