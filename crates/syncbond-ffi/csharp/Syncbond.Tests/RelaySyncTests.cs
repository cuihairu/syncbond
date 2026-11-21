using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace Syncbond.Tests;

/// <summary>
/// Relay driver e2e (todo.md DSR-41): two .NET processes sync through a real
/// relay channel and recover after a restart. The Rust harness boots the relay
/// in-process and exports <c>SYNCBOND_TEST_RELAY</c> (http URL) and
/// <c>SYNCBOND_TEST_ADMIN</c> (bearer token); without those the test skips so a
/// plain <c>dotnet test</c> stays green. Each device runs in its own child
/// process (the acceptance's "two .NET processes") and asserts process
/// responsiveness and a clean stop itself.
/// </summary>
public sealed class RelaySyncTests
{
    private static readonly byte[] GroupKey = GroupKeyBytes();
    private static readonly string GroupKeyB64 = Convert.ToBase64String(GroupKey);

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static byte[] GroupKeyBytes()
    {
        byte[] key = new byte[32];
        Array.Fill(key, (byte)7);
        return key;
    }

    /// <summary>One report the child wrote for the parent to assert on.</summary>
    private sealed class ChildOutput
    {
        public string Phase { get; set; } = "";
        public string Node { get; set; } = "";
        public long MaxStallMs { get; set; }
        public long ReferenceGapMs { get; set; }
        public bool Converged { get; set; }
        public ChildProgress Progress { get; set; } = new();
        public int StopReason { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, string?> Got { get; set; } = new();
        public string StateB64 { get; set; } = "";
    }

    private sealed class ChildProgress
    {
        public bool Running { get; set; }
        public ulong Cycles { get; set; }
        public ulong SentBatches { get; set; }
        public ulong SentEnvelopes { get; set; }
        public ulong PagesPulled { get; set; }
        public ulong Applied { get; set; }
    }

    private static string CsharpDir() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

    private static string ChildDll() => Path.Combine(
        CsharpDir(), "Syncbond.RelayChild", "bin", "Release", "net10.0", "Syncbond.RelayChild.dll");

    private static string PostAdmin(HttpClient client, string url, string token, string path,
                                    object body)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, url + path)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("authorization", "Bearer " + token);
        using HttpResponseMessage response = client.Send(request);
        string text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Assert.True(
            response.StatusCode == HttpStatusCode.Created,
            $"POST {path}: status {(int)response.StatusCode}: {text}");
        return text;
    }

    private static string Field(string json, string name)
    {
        JsonNode root = JsonNode.Parse(json) ?? throw new Exception("empty admin response");
        return root[name]?.GetValue<string>() ?? "";
    }

    /// <summary>
    /// One <c>Syncbond.RelayChild</c> process; returns its report.
    /// </summary>
    private static ChildOutput RunChild(string phase, string node,
                                       Dictionary<string, object> config, string tmpDir)
    {
        string basename = $"{phase}-{node}";
        string configPath = Path.Combine(tmpDir, basename + "-config.json");
        string outPath = Path.Combine(tmpDir, basename + "-out.json");
        File.WriteAllText(configPath, JsonSerializer.Serialize(config));

        string dll = ChildDll();
        if (!File.Exists(dll))
        {
            throw new Exception(
                $"the relay child is not built: {dll} (the harness builds it with " +
                "'dotnet build Syncbond.RelayChild -c Release')");
        }
        ProcessStartInfo info = new()
        {
            FileName = "dotnet",
            RedirectStandardError = true,
        };
        info.ArgumentList.Add("exec");
        info.ArgumentList.Add(dll);
        info.ArgumentList.Add(phase);
        info.ArgumentList.Add(configPath);
        info.ArgumentList.Add(outPath);
        using Process process = Process.Start(info)
            ?? throw new Exception("failed to start the relay child");
        // Read stderr on its own task so a full buffer cannot deadlock the
        // wait; stdout stays inherited so diagnostics show in the run log.
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        string error = stderr.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
        {
            throw new Exception($"child {phase} {node} exited {process.ExitCode}: {error}");
        }
        return JsonSerializer.Deserialize<ChildOutput>(File.ReadAllText(outPath), Json)
            ?? throw new Exception($"child {phase} {node} produced no output");
    }

    private static Dictionary<string, object> BaseConfig(string relayUrl, string channelId,
                                                        string token, string node)
    {
        return new Dictionary<string, object>
        {
            ["relayUrl"] = relayUrl,
            ["channelId"] = channelId,
            ["token"] = token,
            ["groupKeyB64"] = GroupKeyB64,
            ["nodeId"] = node,
            ["waitMs"] = 15000,
        };
    }

    private static void AssertChildOK(string phase, ChildOutput run, bool pulled)
    {
        Assert.True(
            run.StopReason == RelayDriver.DriverStopCancelled,
            phase + " stop reason is " + run.StopReason);
        Assert.True(
            string.IsNullOrEmpty(run.Error),
            phase + " must stop with no error, got " + run.Error);
        Assert.True(run.MaxStallMs < 250,
            $"{phase} stalled {run.MaxStallMs}ms (>= 250ms) during the sync");
        Assert.True(run.Converged, phase + " reported convergence");
        if (pulled)
        {
            Assert.True(run.Progress.Applied > 0,
                $"{phase} must have applied ops pulled from the relay");
        }
    }

    [SkippableFact]
    public async Task TwoDotNetProcessesSyncAndRecover()
    {
        string? relayUrl = Environment.GetEnvironmentVariable("SYNCBOND_TEST_RELAY");
        string? admin = Environment.GetEnvironmentVariable("SYNCBOND_TEST_ADMIN");
        Skip.If(string.IsNullOrEmpty(relayUrl) || string.IsNullOrEmpty(admin),
            "SYNCBOND_TEST_RELAY / SYNCBOND_TEST_ADMIN not set; skipping relay e2e");

        string tmpDir = Path.Combine(Path.GetTempPath(), "syncbond-csharp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpDir);
        try
        {
            using HttpClient client = new();
            string channelId = Field(
                PostAdmin(client, relayUrl, admin, "/v1/channels",
                    new { protocolVersion = 1, requestId = "csharp-channel-1" }),
                "channelId");
            Assert.False(string.IsNullOrEmpty(channelId), "channel: no channelId");
            string credentialPath = "/v1/channels/" + channelId + "/credentials";
            string tokenA = Field(PostAdmin(client, relayUrl, admin, credentialPath, new
            {
                protocolVersion = 1,
                requestId = "csharp-cred-a",
                scopes = new[] { "append", "pull" },
                label = "csharp-a",
            }), "token");
            string tokenB = Field(PostAdmin(client, relayUrl, admin, credentialPath, new
            {
                protocolVersion = 1,
                requestId = "csharp-cred-b",
                scopes = new[] { "append", "pull" },
                label = "csharp-b",
            }), "token");
            Assert.False(string.IsNullOrEmpty(tokenA), "credential a: no token");
            Assert.False(string.IsNullOrEmpty(tokenB), "credential b: no token");

            // Phase 1: two fresh devices write concurrently and converge both
            // ways. They must run at the same time: each waits on a key only
            // the other writes, so running them sequentially would deadlock.
            var configA = BaseConfig(relayUrl, channelId, tokenA, "csharp-a");
            configA["writes"] = new[] { new[] { "a/0", "a0" } };
            configA["expect"] = new[]
            {
                new[] { "a/0", "a0" },
                new[] { "b/1", "b1" },
            };
            var configB = BaseConfig(relayUrl, channelId, tokenB, "csharp-b");
            configB["writes"] = new[]
            {
                new[] { "b/0", "b0" },
                new[] { "b/1", "b1" },
            };
            configB["expect"] = configA["expect"];

            Task<ChildOutput> taskA = Task.Run(
                () => RunChild("live", "csharp-a", configA, tmpDir));
            Task<ChildOutput> taskB = Task.Run(
                () => RunChild("live", "csharp-b", configB, tmpDir));
            Task<ChildOutput[]> both = Task.WhenAll(taskA, taskB);
            Task timeout = Task.Delay(TimeSpan.FromSeconds(120));
            Assert.True(await Task.WhenAny(both, timeout) == both,
                "phase 1 children did not finish within 120s");
            ChildOutput[] phase1 = await both; // rethrows any child failure
            ChildOutput liveA = phase1[0];
            ChildOutput liveB = phase1[1];

            // Phase 2, sequential restarts: B resumes from its snapshot and
            // writes b/2 while A is already down (A's phase-1 child exited),
            // then A resumes and must pull what it missed while down. The
            // restored state of each device is verified by the child before it
            // starts the worker.
            var restartB = BaseConfig(relayUrl, channelId, tokenB, "csharp-b");
            restartB["stateB64"] = liveB.StateB64;
            restartB["expectBeforeStart"] = new[]
            {
                new[] { "b/0", "b0" },
                new[] { "b/1", "b1" },
            };
            restartB["writes"] = new[] { new[] { "b/2", "b2" } };
            restartB["expect"] = new[]
            {
                new[] { "b/0", "b0" },
                new[] { "b/1", "b1" },
                new[] { "b/2", "b2" },
            };
            ChildOutput restartedB = RunChild("restart", "csharp-b", restartB, tmpDir);

            var restartA = BaseConfig(relayUrl, channelId, tokenA, "csharp-a");
            restartA["stateB64"] = liveA.StateB64;
            restartA["expectBeforeStart"] = new[] { new[] { "a/0", "a0" } };
            restartA["writes"] = new[] { new[] { "a/1", "a1" } };
            restartA["expect"] = new[]
            {
                new[] { "a/0", "a0" },
                new[] { "a/1", "a1" },
                new[] { "b/1", "b1" },
                new[] { "b/2", "b2" },
            };
            ChildOutput restartedA = RunChild("restart", "csharp-a", restartA, tmpDir);

            // `pulled` marks the devices that must have applied an op pulled
            // from the relay: a restarted device that only writes its own key
            // has nothing to pull and legitimately reports zero.
            AssertChildOK("live-a", liveA, pulled: true);
            AssertChildOK("live-b", liveB, pulled: true);
            AssertChildOK("restart-b", restartedB, pulled: false);
            AssertChildOK("restart-a", restartedA, pulled: true);
            Assert.True(restartedA.Got["b/2"] == "b2",
                "A must catch what B wrote while A was down, got " + restartedA.Got["b/2"]);
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }
}
