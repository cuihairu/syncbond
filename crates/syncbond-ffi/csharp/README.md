# syncbond C# SDK (P/Invoke)

A .NET binding over the syncbond C ABI (`libsyncbond_ffi`). The binding only
marshals types and forwards to the C ABI; no protocol logic lives in it.
Failures surface as `Syncbond.SyncbondException` carrying the stable
`SB_ERR_*` code from the thread-local error slot.

## Requirements

- .NET SDK 10+ (`dotnet`), and the syncbond C ABI shared library built at
  `target/release/libsyncbond_ffi.so` (`cargo build --release -p
  syncbond-ffi`).

## Build, pack and test

```sh
cargo build --release -p syncbond-ffi
dotnet pack Syncbond -c Release -o artifacts
SYNCBOND_NATIVE=$PWD/../../target/release/libsyncbond_ffi.so \
  dotnet test Syncbond.Tests -c Release
```

`dotnet pack` builds the library and emits `artifacts/syncbond.0.1.0.nupkg`.
The test project restores that package from the local `artifacts` feed (see
`NuGet.config`) and runs the xUnit suite (18 tests: versions, identity
round-trip, pairing, convergence, delete, LWW, session send/recv and
invalidation, key-epoch rotation, replay rejection, dispose idempotence,
conformance report, the four relay-driver lifecycle tests, and the two-process
relay e2e). The suite mirrors the Java, Go and Python suites so the same
behaviors are verified in every language.

`SYNCBOND_NATIVE` names the absolute path to `libsyncbond_ffi.so`; the
binding resolves the native library from it (or falls back to the default
loader).

## Example

```sh
SYNCBOND_NATIVE=$PWD/../../target/release/libsyncbond_ffi.so \
  dotnet run --project Syncbond.Example
```

Prints `pair_sync: all checks passed`.

## Handle lifecycle

Every native handle is owned by a `SafeHandle` subclass that releases it
through the matching `sb_*_free`. That gives every wrapper `IDisposable`
plus a finalizer backstop, so a handle is released exactly once whether it
is disposed explicitly or the wrapper becomes unreachable. Using a released
handle throws `ObjectDisposedException`. All public wrappers implement
`IDisposable` and should be used in `using` statements.

## Relay sync

`Syncbond.RelayDriver` drives one device through a real relay channel: a
worker thread runs the core loop, and the host configures, starts, stops and
interleaves `Write`/`Delete`/`Get` calls (the acceptance's "blocking work does
not occupy the process"). It is the C# analogue of the Go, Node, Python and
Java relay drivers over the same `sb_relay_driver_*` C ABI, so the whole relay
protocol stays native and is never rewritten in C#.

```csharp
using Syncbond;

using RelayDriver driver = RelayDriver.Open(new RelayDriver.Config
{
    RelayUrl = "http://127.0.0.1:9000",
    ChannelId = channelId,
    ChannelToken = token,
    ServerId = "relay-1",
    CursorChannel = "ch",
    GroupId = "group-1",
    KeyEpoch = 1,
    GroupKey = groupKey,          // shared 32-byte material
    NodeId = "device-1",
    TimeoutMs = 5000,
    TlsMode = RelayDriver.TlsValidate,
    State = null,                 // or a prior ExportState() blob to resume
});
driver.Configure(2, 8, 1, 2, 1000, 1);
driver.Start();
driver.Write("k", Encoding.UTF8.GetBytes("v"));
// ... wait for a peer ...
driver.Stop();
Console.WriteLine(driver.StopReason);   // 1 == cancelled on a clean stop
byte[] snapshot = driver.ExportState(); // resume a later driver from this
```

`Open(Config)` builds the identity, keyring, replicator and receive state
handles it needs; on success AND on failure their ownership transfers to the
native driver (per the ABI contract), so none of them is a separate
`IDisposable` (a double free). `Dispose` stops and joins the worker and
releases the driver, and is idempotent.

The relay e2e (`RelaySyncTests`) is gated on `SYNCBOND_TEST_RELAY` /
`SYNCBOND_TEST_ADMIN` (booted by the Rust harness `ffi_csharp`); without them
the e2e skips, so it never gates the suite on a live relay (the rest of the
suite still needs `SYNCBOND_NATIVE` as above). When enabled it provisions a
channel plus two credentials, runs two `Syncbond.RelayChild` processes
concurrently (each waiting on a key only the other writes), then restarts each
device from its exported state so the recovery path is exercised through real
child processes.

## Local publication

`dotnet pack` emits a `.nupkg` into `artifacts/` that downstream projects
restore from the local feed. This is a local build artifact; no remote
feed, repository or version tag is involved.
