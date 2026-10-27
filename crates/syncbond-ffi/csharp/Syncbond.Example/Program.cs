using System.Text;
using Syncbond;
using static Syncbond.Syncbond;

// Pairs two replicators over an in-memory loopback and converges one op.
byte[] payload = Encoding.UTF8.GetBytes("hello from csharp");
using PairResult pair = PairMemory(null);
Console.WriteLine($"pairing code: {pair.Code}");
using Replicator left = new("left", StrategyLwwHlc, 1000);
using Replicator right = new("right", StrategyLwwHlc, 2000);
left.Put("greeting", payload);
(uint sent, _) = Replicator.SyncPair(left, right, pair.Initiator, pair.Responder);
byte[]? got = right.Get("greeting");
bool ok = sent >= 1 && got is not null && got.SequenceEqual(payload);
Console.WriteLine($"right sees: {Encoding.UTF8.GetString(got!)}");
Console.WriteLine(ok ? "pair_sync: all checks passed" : "pair_sync: FAILED");
return ok ? 0 : 1;
