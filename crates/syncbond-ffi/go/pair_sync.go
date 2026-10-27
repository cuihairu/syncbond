//go:build ignore

// pair_sync.go is a Go consumer of the syncbond C ABI, mirroring the C and
// Python examples. Build a release staticlib first:
//
//	cargo build --release -p syncbond-ffi
//	cd crates/syncbond-ffi/go && go run pair_sync.go
//
// The full flow: pair two devices, run a concurrent oplog sync, verify both
// sides converge, seal/open an envelope after a key rotation, and drive the
// cross-language conformance runner.
package main

import (
	"fmt"
	"os"
	"strings"

	"syncbond"
)

// The canonical cross-language fixture, shared by every binding
// (crates/syncbond-ffi/fixtures/conformance.json), read relative to this
// package directory so the same on-disk file drives every language.
func readFixture() string {
	bytes, err := os.ReadFile("../fixtures/conformance.json")
	if err != nil {
		fail(fmt.Errorf("read canonical fixture: %w", err))
	}
	return string(bytes)
}

func main() {
	if abi := syncbond.ABIVersion(); abi != 1 {
		fail(fmt.Errorf("ABI version = %d, want 1", abi))
	}

	pair, err := syncbond.PairMemory("")
	check("pair", err)
	defer pair.Close()
	fmt.Println("pairing code:", pair.Code())
	init, resp := pair.Initiator(), pair.Responder()
	if init.GroupID() != resp.GroupID() {
		fail(fmt.Errorf("group ids differ: %q vs %q", init.GroupID(), resp.GroupID()))
	}

	left, err := syncbond.NewReplicatorFixedClock("left", syncbond.StrategyLwwHLC, 1000)
	check("left replicator", err)
	defer left.Close()
	right, err := syncbond.NewReplicatorFixedClock("right", syncbond.StrategyLwwHLC, 2000)
	check("right replicator", err)
	defer right.Close()

	check("put greeting", left.Put("greeting", []byte("hello from go")))
	check("put counter", right.Put("counter", []byte("42")))
	check("put doomed", left.Put("doomed", []byte("x")))
	check("delete doomed", left.Delete("doomed"))

	leftOps, rightOps, err := syncbond.SyncPair(left, right, init, resp)
	check("sync", err)
	if leftOps != 3 || rightOps != 1 {
		fail(fmt.Errorf("sent ops = (%d,%d), want (3,1)", leftOps, rightOps))
	}

	greeting, err := right.Get("greeting")
	check("get greeting on right", err)
	fmt.Println("greeting:", string(greeting))
	if _, err := right.Get("doomed"); err == nil {
		fail(fmt.Errorf("doomed key still live after sync"))
	}
	if dumpL, dumpR := left.RecordsJSON(), right.RecordsJSON(); dumpL != dumpR {
		fail(fmt.Errorf("canonical dumps differ:\nleft=%s\nright=%s", dumpL, dumpR))
	} else {
		fmt.Println("converged state:", dumpL)
	}

	ring := syncbond.NewKeyring("group-a")
	defer ring.Close()
	epoch, key := ring.Rotate()
	check("keyring rotate", nil)
	_ = key
	envelope := ring.SealJSON("device-1", []byte("secret"))
	plain, err := ring.OpenJSON(envelope)
	check("keyring open", err)
	if string(plain) != "secret" {
		fail(fmt.Errorf("opened payload = %q, want secret", plain))
	}
	fmt.Println("rotated epoch:", epoch, "payload round-trips")

	report, err := syncbond.ConformanceRun(readFixture())
	check("conformance", err)
	if !strings.Contains(report, `"ok":true`) {
		fail(fmt.Errorf("conformance report not ok: %s", report))
	}
	for _, name := range []string{
		"left_sees_newer_write",
		"old_write_cannot_resurrect_after_gc",
		"removed_device_cannot_open_envelope_sealed_after_rotation",
	} {
		if !strings.Contains(report, name) {
			fail(fmt.Errorf("conformance report missing check %q", name))
		}
	}
	expected, err := os.ReadFile("../fixtures/conformance.expected.json")
	if err != nil {
		fail(fmt.Errorf("read canonical expected report: %w", err))
	} else if report != string(expected) {
		fail(fmt.Errorf("conformance report must match the canonical bytes"))
	}
	fmt.Println("conformance ok:", report)

	fmt.Println("pair_sync: all checks passed")
}

func check(what string, err error) {
	if err != nil {
		fail(fmt.Errorf("%s: %w", what, err))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "FAIL:", err)
	os.Exit(1)
}
