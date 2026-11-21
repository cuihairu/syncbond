# syncbond (Go)

Go bindings for [syncbond](../../../README.md) — accountless, embeddable,
end-to-end encrypted device pairing and data synchronization.

The bindings are a thin cgo layer over the shared `syncbond-ffi` handle API:
they serialize, manage resources, and forward to the core. No protocol logic
lives here, so merge semantics, key epoch rotation and tombstone GC behave
identically to every other language.

```go
package main

import (
	"fmt"

	"syncbond"
)

func main() {
	pair, err := syncbond.PairMemory("")
	if err != nil {
		panic(err)
	}
	defer pair.Close()

	left, _ := syncbond.NewReplicator("left", syncbond.StrategyLwwHLC)
	right, _ := syncbond.NewReplicator("right", syncbond.StrategyLwwHLC)
	defer left.Close()
	defer right.Close()

	_ = left.Put("greeting", []byte("hello from go"))
	if _, _, err := syncbond.SyncPair(left, right, pair.Initiator(), pair.Responder()); err != nil {
		panic(err)
	}
	greeting, _ := right.Get("greeting")
	fmt.Println(string(greeting))
}
```

`SyncPair` runs the blocking responder half on a worker goroutine while the
caller drives the initiator; the two halves use distinct handles, matching the
ABI's single-thread-per-handle rule.

## Relay sync

`syncbond.RelayDriver` owns one device's session against a relay channel and
syncs it in the background: the driver runs its own worker thread, so the host
only writes, reads, starts and stops. Two devices that import the same group
key converge through the relay; an exported state snapshot resumes a device
exactly where it left off.

```go
driver, err := syncbond.NewRelayDriver(
	relayURL, channelID, channelToken,
	"relay-1", "ch", "group-1", 1, groupKey, "device-a", 5000,
	syncbond.TLSValidate, nil, nil, // nil CA, no state: a fresh device
)
if err != nil {
	panic(err)
}
defer driver.Close()

_ = driver.Config(32, 16, 500, 2000, 8, 1000) // page limit, pages, backoff, attempts, idle
if err := driver.Start(); err != nil {
	panic(err)
}
_ = driver.Write("greeting", []byte("hello"))

state, _ := driver.ExportState() // snapshot for a later resume
if err := driver.Stop(); err != nil { // idempotent; joins the worker
	panic(err)
}
if driver.StopReason() != syncbond.DriverStopCancelled {
	panic("unexpected stop reason")
}
```

`driver.Progress()` reports the worker's monotonic counters (`Cycles`,
`SentBatches`, `SentEnvelopes`, `PagesPulled`, `Applied`), `driver.Error()`
the text that ended the loop, and `driver.ExportState()` the snapshot a later
`NewRelayDriver` call restores from.

## Build

The binding links the release static library, so build the FFI crate first:

```sh
cargo build --release -p syncbond-ffi
```

## Test

```sh
cd crates/syncbond-ffi/go
go test ./...
```

The binding requires cgo. `CGO_ENABLED=0 go test ./...` must still pass and
report `ErrCgoDisabled` from every entry point instead of silently returning
empty state.

The relay e2e (`TestRelayDriverTwoProcessesSyncAndRecover`) needs
`SYNCBOND_TEST_RELAY` (an http relay URL) and `SYNCBOND_TEST_ADMIN` (its admin
token); without them it skips, so the suite above stays green standalone.

`fixtures/consistency` plus `ConformanceRun` give the byte-for-byte
cross-language checks; every binding drives the same fixture through the same
runner.
