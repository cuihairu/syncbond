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

`fixtures/consistency` plus `ConformanceRun` give the byte-for-byte
cross-language checks; every binding drives the same fixture through the same
runner.
