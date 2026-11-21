//go:build cgo

package syncbond

import (
	"testing"
)

// groupKey is the shared 32 bytes of 0x07 every binding's relay test uses:
// two devices in one group import the identical group key material.
func groupKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 7
	}
	return k
}

func freshDriver(t *testing.T, url, channel, token, node string) *RelayDriver {
	t.Helper()
	d, err := NewRelayDriver(url, channel, token, "relay-1", "ch", "group-1", 1,
		groupKey(), node, 5000, TLSValidate, nil, nil)
	if err != nil {
		t.Fatalf("NewRelayDriver: %v", err)
	}
	return d
}

func fastConfig(t *testing.T, d *RelayDriver) {
	t.Helper()
	if err := d.Config(2, 8, 1, 2, 1000, 1); err != nil {
		t.Fatalf("Config: %v", err)
	}
}

func TestRelayDriverBadArguments(t *testing.T) {
	// A short group key is refused before any native call.
	_, err := NewRelayDriver("http://127.0.0.1:1", "ch", "tok", "s", "c", "g", 1,
		[]byte{1, 2, 3}, "n", 100, TLSValidate, nil, nil)
	if err == nil {
		t.Fatal("a short group key must be refused")
	}
	if se, ok := err.(*Error); !ok || se.Code != ErrInput {
		t.Fatalf("short group key error = %v, want ErrInput", err)
	}

	// An unknown tls mode is refused by the handle layer.
	_, err = NewRelayDriver("http://127.0.0.1:1", "ch", "tok", "s", "c", "g", 1,
		groupKey(), "n", 100, 7, nil, nil)
	if err == nil {
		t.Fatal("an unknown tls mode must be refused")
	}

	// A zero timeout is refused too.
	_, err = NewRelayDriver("http://127.0.0.1:1", "ch", "tok", "s", "c", "g", 1,
		groupKey(), "n", 0, TLSValidate, nil, nil)
	if err == nil {
		t.Fatal("a zero timeout must be refused")
	}
}

func TestRelayDriverDeadEndpointLifecycleAndState(t *testing.T) {
	d := freshDriver(t, "http://127.0.0.1:1", "ch", "tok", "go-dead")
	defer d.Close()
	fastConfig(t, d)

	if d.Running() {
		t.Fatal("not running yet")
	}
	if d.StopReason() != DriverStopNone {
		t.Fatalf("stop reason = %d, want DriverStopNone", d.StopReason())
	}
	if err := d.Error(); err != nil {
		t.Fatalf("no error text yet: %v", err)
	}
	if p := d.Progress(); p.Running {
		t.Fatal("progress reports running before start")
	}

	// Start spawns the worker, which retries the dead endpoint in a loop.
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !d.Running() {
		t.Fatal("the worker is up")
	}
	if p := d.Progress(); !p.Running {
		t.Fatal("progress reports running")
	}

	// The host writes and reads through the marshaling layer.
	if err := d.Write("k", []byte("v")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := d.Get("k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("Get = %q, want v", got)
	}
	if _, err := d.Get("absent"); err == nil {
		t.Fatal("an absent key must report an error (ResultAbsent)")
	} else if se, ok := err.(*Error); !ok || se.Code != ResultAbsent {
		t.Fatalf("absent Get error = %v, want ResultAbsent", err)
	}

	// The committed state exports and re-imports with the write intact.
	blob, err := d.ExportState()
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("the snapshot is not empty")
	}

	// A delete stages a tombstone that survives the snapshot too.
	if err := d.Delete("k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.Get("k"); err == nil {
		t.Fatal("the tombstone wins")
	}

	// Stop cancels and joins; the reason is cancellation, not an error.
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if d.Running() {
		t.Fatal("the worker joined")
	}
	if d.StopReason() != DriverStopCancelled {
		t.Fatalf("stop reason = %d, want DriverStopCancelled", d.StopReason())
	}
	if err := d.Error(); err != nil {
		t.Fatalf("a clean stop has no error: %v", err)
	}
}

func TestRelayDriverRestoreFromState(t *testing.T) {
	d := freshDriver(t, "http://127.0.0.1:1", "ch", "tok", "go-first")
	fastConfig(t, d)
	if err := d.Write("persist", []byte("p")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	blob, err := d.ExportState()
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}

	// A second driver rebuilt from the snapshot alone (a fresh node id,
	// which the state overrides) sees the committed write.
	restored, err := NewRelayDriver("http://127.0.0.1:1", "ch", "tok", "relay-1", "ch",
		"group-1", 1, groupKey(), "different-node", 5000, TLSValidate, nil, blob)
	if err != nil {
		t.Fatalf("restored driver: %v", err)
	}
	defer restored.Close()
	got, err := restored.Get("persist")
	if err != nil {
		t.Fatalf("restored Get: %v", err)
	}
	if string(got) != "p" {
		t.Fatalf("restored Get = %q, want p", got)
	}
}

func TestRelayDriverCloseIsIdempotentAndStopsWorker(t *testing.T) {
	// Double Close is safe and a driver closed while running joins its
	// worker instead of leaking the thread.
	d := freshDriver(t, "http://127.0.0.1:1", "ch", "tok", "go-idle")
	fastConfig(t, d)
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	d.Close()
	d.Close() // idempotent
	if d.ptr != nil {
		t.Fatal("Close must nil the handle")
	}

	// Closing a nil receiver and a never-started driver are no-ops.
	var nilDriver *RelayDriver
	nilDriver.Close()
	fresh := freshDriver(t, "http://127.0.0.1:1", "ch", "tok", "go-fresh")
	fresh.Close()

	// A started driver stopped once may start again after the stop.
	d2 := freshDriver(t, "http://127.0.0.1:1", "ch", "tok", "go-restart")
	fastConfig(t, d2)
	if err := d2.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := d2.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := d2.Start(); err != nil {
		t.Fatalf("restart after stop: %v", err)
	}
	if err := d2.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	d2.Close()
}
