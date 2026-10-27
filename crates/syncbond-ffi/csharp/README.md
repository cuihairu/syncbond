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
`NuGet.config`) and runs the xUnit suite (13 tests: versions, identity
round-trip, pairing, convergence, delete, LWW, session send/recv and
invalidation, key-epoch rotation, replay rejection, dispose idempotence,
conformance report). The suite mirrors the Java, Go and Python suites so the
same behaviors are verified in every language.

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

## Local publication

`dotnet pack` emits a `.nupkg` into `artifacts/` that downstream projects
restore from the local feed. This is a local build artifact; no remote
feed, repository or version tag is involved.
