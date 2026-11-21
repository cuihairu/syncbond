//go:build ignore

// Relay driver child process (todo.md DSR-39): one Go process runs one device
// against a relay channel and reports how the run went. The parent test
// spawns two of these (the "two Go processes" of the acceptance) and a second
// pair after a restart, so recovery from exported state is exercised through
// real child processes, not one process juggling two devices.
//
// Usage: go run relay_child.go <phase> <config.json> <out.json>
//
//	phase  "live"    - a fresh device that writes and syncs.
//	       "restart" - a device restored from an exported state snapshot.
//	config { relayUrl, channelId, token, groupKeyB64, nodeId, stateB64?,
//	         writes: [[key, value], ...], expect: [[key, value], ...],
//	         expectBeforeStart?: [[key, value], ...], waitMs }
//
// The child asserts its own invariants and exits non-zero on failure; the
// parent checks the exit code and the reported output. A 1ms ticker goroutine
// runs for the whole sync wait: the native driver does its blocking work on a
// separate OS thread (a cgo call), so the ticker goroutine must never stall
// for long - the acceptance "blocking work does not occupy the process".
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"syncbond"
)

type relayConfig struct {
	RelayURL          string      `json:"relayUrl"`
	ChannelID         string      `json:"channelId"`
	Token             string      `json:"token"`
	GroupKeyB64       string      `json:"groupKeyB64"`
	Node              string      `json:"node"`
	StateB64          string      `json:"stateB64,omitempty"`
	Writes            [][2]string `json:"writes"`
	Expect            [][2]string `json:"expect"`
	ExpectBeforeStart [][2]string `json:"expectBeforeStart,omitempty"`
	WaitMS            int         `json:"waitMs"`
}

type relayOutput struct {
	Phase      string            `json:"phase"`
	Node       string            `json:"node"`
	MaxStallMS int64             `json:"maxStallMs"`
	Converged  bool              `json:"converged"`
	Progress   relayProgress     `json:"progress"`
	StopReason int32             `json:"stopReason"`
	Error      *string           `json:"error"`
	Got        map[string]string `json:"got"`
	StateB64   string            `json:"stateB64"`
}

type relayProgress struct {
	Running       bool   `json:"running"`
	Cycles        uint64 `json:"cycles"`
	SentBatches   uint64 `json:"sentBatches"`
	SentEnvelopes uint64 `json:"sentEnvelopes"`
	PagesPulled   uint64 `json:"pagesPulled"`
	Applied       uint64 `json:"applied"`
}

func fail(phase, message string) {
	fmt.Fprintf(os.Stderr, "relay-child %s: %s\n", phase, message)
	os.Exit(1)
}

func check(phase, what string, err error) {
	if err != nil {
		fail(phase, fmt.Sprintf("%s: %v", what, err))
	}
}

func main() {
	if len(os.Args) != 4 {
		fail("", "usage: relay_child.go <phase> <config.json> <out.json>")
	}
	phase, configPath, outPath := os.Args[1], os.Args[2], os.Args[3]
	raw, err := os.ReadFile(configPath)
	check(phase, "read config", err)
	var config relayConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		fail(phase, fmt.Sprintf("parse config: %v", err))
	}
	groupKey, err := base64.StdEncoding.DecodeString(config.GroupKeyB64)
	check(phase, "decode group key", err)
	var state []byte
	if config.StateB64 != "" {
		state, err = base64.StdEncoding.DecodeString(config.StateB64)
		check(phase, "decode state", err)
	}

	driver, err := syncbond.NewRelayDriver(
		config.RelayURL, config.ChannelID, config.Token,
		"relay-1", "ch", "group-1", 1, groupKey, config.Node, 5000,
		syncbond.TLSValidate, nil, state)
	check(phase, "new driver", err)
	defer driver.Close()

	value := func(key string) (string, bool) {
		bytes, err := driver.Get(key)
		if err != nil {
			return "", false
		}
		return string(bytes), true
	}

	// A restored device must already hold what it committed before the
	// restart.
	for _, kv := range config.ExpectBeforeStart {
		got, ok := value(kv[0])
		if !ok || got != kv[1] {
			fail(phase, fmt.Sprintf("restored state lost %s: got %q, want %q", kv[0], got, kv[1]))
		}
	}

	check(phase, "config", driver.Config(2, 8, 1, 2, 1000, 1))

	// The responsiveness probe: if the native driver's blocking calls ran on
	// the process's only thread this ticker goroutine would stall while they
	// run. What matters is the longest gap between fires.
	//
	// A second reference goroutine separates the two causes of a long gap:
	// OS-level CPU starvation stalls both goroutines together, so the
	// relative gap stays near zero and a loaded box does not trip the probe,
	// while a ticker genuinely starved of scheduling next to a freely running
	// reference is a real process stall. The stall reported and checked is
	// the relative one.
	var lastTick atomic.Int64
	var maxStall atomic.Int64
	lastTick.Store(time.Now().UnixMilli())
	go func() {
		for {
			time.Sleep(time.Millisecond)
			now := time.Now().UnixMilli()
			prev := lastTick.Swap(now)
			if gap := now - prev; gap > maxStall.Load() {
				maxStall.Store(gap)
			}
		}
	}()
	var refLast atomic.Int64
	var refMax atomic.Int64
	refLast.Store(time.Now().UnixMilli())
	go func() {
		for {
			time.Sleep(time.Millisecond)
			now := time.Now().UnixMilli()
			prev := refLast.Swap(now)
			if gap := now - prev; gap > refMax.Load() {
				refMax.Store(gap)
			}
		}
	}()

	check(phase, "start", driver.Start())
	for _, kv := range config.Writes {
		check(phase, "write "+kv[0], driver.Write(kv[0], []byte(kv[1])))
	}

	deadline := time.Now().Add(time.Duration(config.WaitMS) * time.Millisecond)
	converged := false
	for time.Now().Before(deadline) {
		all := true
		for _, kv := range config.Expect {
			if _, ok := value(kv[0]); !ok {
				all = false
				break
			}
		}
		if all {
			converged = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The push must have left the process before stop, or a restarted peer
	// never sees the write: a device converges on its own staged write
	// before the worker actually sends it.
	pushDeadline := time.Now().Add(5 * time.Second)
	for driver.Progress().SentBatches == 0 && time.Now().Before(pushDeadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if driver.Progress().SentBatches == 0 {
		fail(phase, "the worker never pushed a batch")
	}

	got := make(map[string]string, len(config.Expect))
	for _, kv := range config.Expect {
		got[kv[0]], _ = value(kv[0])
	}
	for _, kv := range config.Expect {
		if got[kv[0]] != kv[1] {
			fail(phase, fmt.Sprintf("expected %s=%q, got %q", kv[0], kv[1], got[kv[0]]))
		}
	}
	if !converged {
		fail(phase, "did not converge on the expected keys")
	}
	stall := maxStall.Load() - refMax.Load()
	if stall < 0 {
		stall = 0
	}
	if stall >= 250 {
		fail(phase, fmt.Sprintf("the process stalled %dms during the sync (reference %dms)",
			stall, refMax.Load()))
	}

	// Cancel the loop and join the worker before reading the outcome, so the
	// stop reason is the deterministic "cancelled" (1) a clean host stop
	// yields.
	check(phase, "stop", driver.Stop())
	if driver.Running() {
		fail(phase, "driver still running after a clean stop")
	}
	if driver.StopReason() != syncbond.DriverStopCancelled {
		fail(phase, fmt.Sprintf("stop reason is %d, want 1 (cancelled)", driver.StopReason()))
	}
	if err := driver.Error(); err != nil {
		fail(phase, fmt.Sprintf("clean stop must have no error: %v", err))
	}
	progress := driver.Progress()
	state, err = driver.ExportState()
	check(phase, "export state", err)
	stateB64 := base64.StdEncoding.EncodeToString(state)

	output := relayOutput{
		Phase:      phase,
		Node:       config.Node,
		MaxStallMS: stall,
		Converged:  converged,
		Progress: relayProgress{
			Running:       progress.Running,
			Cycles:        progress.Cycles,
			SentBatches:   progress.SentBatches,
			SentEnvelopes: progress.SentEnvelopes,
			PagesPulled:   progress.PagesPulled,
			Applied:       progress.Applied,
		},
		StopReason: driver.StopReason(),
		Got:        got,
		StateB64:   stateB64,
	}
	out, err := json.MarshalIndent(output, "", "  ")
	check(phase, "marshal output", err)
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		fail(phase, fmt.Sprintf("write output: %v", err))
	}
}
