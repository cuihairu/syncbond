using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Syncbond;

namespace Syncbond.RelayChild;

/// <summary>
/// Relay driver child process (todo.md DSR-41): one .NET process runs one
/// device against a relay channel and reports how the run went. The parent
/// test spawns two of these (the "two .NET processes" of the acceptance) and
/// a second pair after a restart, so recovery from exported state is
/// exercised through real child processes, not one process juggling two
/// devices.
///
/// Usage: Syncbond.RelayChild &lt;phase&gt; &lt;config.json&gt; &lt;out.json&gt;
///
/// The child asserts its own invariants and exits non-zero on failure; the
/// parent checks the exit code and the reported output. A 1ms ticker thread
/// runs for the whole sync wait: the native driver does its blocking work on
/// its own worker thread, so the process must keep scheduling a concurrent
/// thread the whole time (the acceptance "blocking work does not occupy the
/// process").
/// </summary>
internal static class Program
{
    private sealed class RelayChildConfig
    {
        public string RelayUrl { get; set; } = "";
        public string ChannelId { get; set; } = "";
        public string Token { get; set; } = "";
        public string GroupKeyB64 { get; set; } = "";
        public string NodeId { get; set; } = "";
        public string? StateB64 { get; set; }
        public string[][] Writes { get; set; } = Array.Empty<string[]>();
        public string[][] Expect { get; set; } = Array.Empty<string[]>();
        public string[][] ExpectBeforeStart { get; set; } = Array.Empty<string[]>();
        public int WaitMs { get; set; } = 15000;
    }

    private sealed class RelayChildOutput
    {
        public string Phase { get; set; } = "";
        public string Node { get; set; } = "";
        public long MaxStallMs { get; set; }
        public long ReferenceGapMs { get; set; }
        public bool Converged { get; set; }
        public RelayProgressOut Progress { get; set; } = new();
        public int StopReason { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, string?> Got { get; set; } = new();
        public string StateB64 { get; set; } = "";
    }

    private sealed class RelayProgressOut
    {
        public bool Running { get; set; }
        public ulong Cycles { get; set; }
        public ulong SentBatches { get; set; }
        public ulong SentEnvelopes { get; set; }
        public ulong PagesPulled { get; set; }
        public ulong Applied { get; set; }
    }

    public static int Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine("usage: Syncbond.RelayChild <phase> <config.json> <out.json>");
            return 2;
        }
        string phase = args[0];
        try
        {
            // The parent writes camelCase keys; System.Text.Json is
            // case-sensitive by default, so match them case-insensitively.
            RelayChildConfig config = JsonSerializer.Deserialize<RelayChildConfig>(
                File.ReadAllText(args[1]),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            byte[] groupKey = Convert.FromBase64String(config.GroupKeyB64);
            byte[]? state = string.IsNullOrEmpty(config.StateB64)
                ? null
                : Convert.FromBase64String(config.StateB64);

            using RelayDriver driver = OpenDriver(phase, config, groupKey, state);

            // A restored device must already hold what it committed before the
            // restart.
            foreach (string[] pair in config.ExpectBeforeStart)
            {
                string? have = Value(driver, pair[0]);
                if (have != pair[1])
                {
                    Fail(phase, $"restored state lost {pair[0]}: got {have}, want {pair[1]}");
                }
            }

            driver.Configure(2, 8, 1, 2, 1000, 1);

            // The responsiveness probe: if the native driver's blocking calls
            // stopped the process, this ticker would stall while they run. The
            // reference thread separates OS-level CPU starvation (both stall
            // together, a pass) from a process genuinely blocked in a native
            // call (the reference keeps ticking, a fail).
            Probes probes = new();
            probes.Start();

            driver.Start();
            foreach (string[] pair in config.Writes)
            {
                driver.Write(pair[0], Encoding.UTF8.GetBytes(pair[1]));
            }

            long deadline = NowMs() + config.WaitMs;
            bool converged = false;
            while (NowMs() < deadline)
            {
                bool all = true;
                foreach (string[] pair in config.Expect)
                {
                    if (driver.Get(pair[0]) == null)
                    {
                        all = false;
                        break;
                    }
                }
                if (all)
                {
                    converged = true;
                    break;
                }
                Thread.Sleep(5);
            }
            (long tickerGapMs, long referenceGapMs) = probes.Stop();
            long stallMs = Math.Max(0, tickerGapMs - referenceGapMs);

            // Every write must reach the relay before this device may report
            // success, or a peer can wait forever: a device converges on its
            // own staged write (it is visible locally) before the worker
            // ships it, so `SentBatches > 0` alone would let b/1 look
            // delivered while it sits unsent in the outbox. Each write seals
            // exactly one envelope, so the relay must ack one per write. The
            // C++ child guards the same way (relay_child.cpp).
            ulong expected = (ulong)config.Writes.Length;
            long pushDeadline = NowMs() + 5000;
            while (driver.Progress.SentEnvelopes < expected && NowMs() < pushDeadline)
            {
                Thread.Sleep(2);
            }
            if (driver.Progress.SentEnvelopes < expected)
            {
                Fail(phase, $"only {driver.Progress.SentEnvelopes} of {expected} write envelopes reached the relay");
            }

            Dictionary<string, string?> got = new();
            foreach (string[] pair in config.Expect)
            {
                string? value = Value(driver, pair[0]);
                got[pair[0]] = value;
                if (value != pair[1])
                {
                    Fail(phase, $"expected {pair[0]}={pair[1]}, got {value}");
                }
            }
            if (!converged)
            {
                Fail(phase, "did not converge on the expected keys");
            }
            if (stallMs >= 250)
            {
                Fail(phase, $"the process stalled {stallMs}ms during the sync (reference {referenceGapMs}ms)");
            }

            // Cancel the loop and join the worker before reading the outcome,
            // so the stop reason is the deterministic "cancelled" (1) a clean
            // host stop yields.
            driver.Stop();
            if (driver.Running)
            {
                Fail(phase, "driver still running after a clean stop");
            }
            if (driver.StopReason != RelayDriver.DriverStopCancelled)
            {
                Fail(phase, $"stop reason is {driver.StopReason}, want 1 (cancelled)");
            }
            if (driver.Error != null)
            {
                Fail(phase, $"clean stop must have no error, got {driver.Error}");
            }
            RelayProgress progress = driver.Progress;
            string stateB64 = Convert.ToBase64String(driver.ExportState());

            RelayChildOutput output = new()
            {
                Phase = phase,
                Node = config.NodeId,
                MaxStallMs = stallMs,
                ReferenceGapMs = referenceGapMs,
                Converged = converged,
                Progress = new RelayProgressOut
                {
                    Running = progress.Running,
                    Cycles = progress.Cycles,
                    SentBatches = progress.SentBatches,
                    SentEnvelopes = progress.SentEnvelopes,
                    PagesPulled = progress.PagesPulled,
                    Applied = progress.Applied,
                },
                StopReason = driver.StopReason,
                Error = driver.Error,
                Got = got,
                StateB64 = stateB64,
            };
            File.WriteAllText(args[2], JsonSerializer.Serialize(
                output, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                }));
            return 0;
        }
        catch (Exception error)
        {
            Fail(phase, error.ToString());
            return 1;
        }
    }

    private static RelayDriver OpenDriver(
        string phase, RelayChildConfig config, byte[] groupKey, byte[]? state)
    {
        try
        {
            return RelayDriver.Open(new RelayDriver.Config
            {
                RelayUrl = config.RelayUrl,
                ChannelId = config.ChannelId,
                ChannelToken = config.Token,
                ServerId = "relay-1",
                CursorChannel = "ch",
                GroupId = "group-1",
                KeyEpoch = 1,
                GroupKey = groupKey,
                NodeId = config.NodeId,
                TimeoutMs = 5000,
                TlsMode = RelayDriver.TlsValidate,
                State = state,
            });
        }
        catch (Exception error)
        {
            Fail(phase, $"open driver: {error.Message}");
            throw;
        }
    }

    private static string? Value(RelayDriver driver, string key)
    {
        byte[]? data = driver.Get(key);
        return data == null ? null : Encoding.UTF8.GetString(data);
    }

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    private static void Fail(string phase, string message)
    {
        Console.Error.WriteLine($"relay-child {phase}: {message}");
        Environment.Exit(1);
    }

    /// <summary>
    /// Two 1ms-loop threads on their own OS threads: one watches the process,
    /// the other is the reference clock (see the probe comment above). Each
    /// loop thread is the only writer of its own gap; the reader joins the
    /// thread first, so the max is read only after the writer stopped.
    /// </summary>
    private sealed class Probes
    {
        private sealed class GapTracker
        {
            internal long Max;
        }

        private readonly GapTracker ticker = new();
        private readonly GapTracker reference = new();
        private volatile bool running;
        private Thread? tickerThread;
        private Thread? referenceThread;

        public void Start()
        {
            running = true;
            tickerThread = Loop("ticker", ticker);
            referenceThread = Loop("reference", reference);
        }

        private Thread Loop(string name, GapTracker tracker)
        {
            Thread thread = new(() =>
            {
                long last = NowMs();
                while (running)
                {
                    Thread.Sleep(1);
                    long now = NowMs();
                    long gap = now - last;
                    if (gap > tracker.Max)
                    {
                        tracker.Max = gap;
                    }
                    last = now;
                }
            })
            {
                Name = name,
                IsBackground = true,
            };
            thread.Start();
            return thread;
        }

        public (long TickerGapMs, long ReferenceGapMs) Stop()
        {
            running = false;
            tickerThread!.Join();
            referenceThread!.Join();
            return (ticker.Max, reference.Max);
        }
    }
}
