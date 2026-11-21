//go:build cgo

// Relay driver e2e (todo.md DSR-39): two Go processes sync through a real
// relay channel and recover after a restart. The Rust harness boots the relay
// in-process and exports SYNCBOND_TEST_RELAY (http URL) and SYNCBOND_TEST_ADMIN
// (bearer token); without those the test skips so a plain `go test ./...`
// stays green. Each device runs in its own child process (the acceptance's
// "two Go processes") and asserts process responsiveness and a clean stop
// itself.
package syncbond

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// groupKeyB64 is the same 32 bytes of 0x07 the Rust driver test uses: two
// devices in one group import the identical group key material.
var groupKeyB64 = base64.StdEncoding.EncodeToString(groupKey())

func relayEnv(t *testing.T) (url, admin string) {
	t.Helper()
	url, admin = os.Getenv("SYNCBOND_TEST_RELAY"), os.Getenv("SYNCBOND_TEST_ADMIN")
	if url == "" || admin == "" {
		t.Skip("SYNCBOND_TEST_RELAY / SYNCBOND_TEST_ADMIN not set; skipping relay e2e")
	}
	return url, admin
}

// relayPOST posts one JSON body to a relay admin endpoint with the bearer
// token and returns the decoded JSON object.
func relayPOST(t *testing.T, url, admin, path string, body any) map[string]any {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	req, err := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request %s: %v", path, err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+admin)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST %s: status %d", path, res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

// runRelayChild spawns one `go run relay_child.go` process for one device and
// returns its decoded output. Failures are returned as errors rather than
// t.Fatalf'd so the caller can fail the (single) test goroutine after both
// concurrent children have finished.
func runRelayChild(phase string, config map[string]any, tmp string) (map[string]any, error) {
	base := fmt.Sprintf("%s-%v", phase, config["node"])
	configPath := filepath.Join(tmp, base+"-config.json")
	outPath := filepath.Join(tmp, base+"-out.json")
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal child config: %w", err)
	}
	if err := os.WriteFile(configPath, raw, 0o644); err != nil {
		return nil, fmt.Errorf("write child config: %w", err)
	}

	// `go run` needs the package directory; `go test ./...` runs with the
	// go/ directory as its working directory.
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("getwd: %w", err)
	}
	cmd := exec.Command("go", "run", "relay_child.go", phase, configPath, outPath)
	cmd.Dir = wd
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("child %s %v exited: %w\n%s", phase, config["node"], err, stderr.String())
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read child output: %w", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		return nil, fmt.Errorf("parse child output: %w", err)
	}
	return decoded, nil
}

func assertChildOK(t *testing.T, phase string, run map[string]any, pulled bool) {
	t.Helper()
	if run["stopReason"].(float64) != float64(DriverStopCancelled) {
		t.Fatalf("%s: stop reason = %v, want 1 (cancelled)", phase, run["stopReason"])
	}
	if run["error"] != nil {
		t.Fatalf("%s: must stop with no error, got %v", phase, run["error"])
	}
	if stall, ok := run["maxStallMs"].(float64); !ok || stall >= 250 {
		t.Fatalf("%s: process stalled %vms (>= 250ms longest gap)", phase, run["maxStallMs"])
	}
	if run["converged"] != true {
		t.Fatalf("%s: did not report convergence", phase)
	}
	if pulled {
		progress := run["progress"].(map[string]any)
		if applied, ok := progress["applied"].(float64); !ok || applied == 0 {
			t.Fatalf("%s: must have applied pulled ops, got %v", phase, progress["applied"])
		}
	}
}

// TestRelayDriverTwoProcessesSyncAndRecover is the DSR-39 acceptance: two Go
// processes converge through a real relay and recover from exported state.
func TestRelayDriverTwoProcessesSyncAndRecover(t *testing.T) {
	url, admin := relayEnv(t)

	tmp := t.TempDir()
	channel := relayPOST(t, url, admin, "/v1/channels", map[string]any{
		"protocolVersion": 1,
		"requestId":       "go-channel-1",
	})
	channelID, _ := channel["channelId"].(string)
	if channelID == "" {
		t.Fatalf("create channel returned no channelId: %v", channel)
	}
	issue := func(label string) string {
		cred := relayPOST(t, url, admin, "/v1/channels/"+channelID+"/credentials", map[string]any{
			"protocolVersion": 1,
			"requestId":       "go-cred-" + label,
			"scopes":          []string{"append", "pull"},
			"label":           label,
		})
		token, _ := cred["token"].(string)
		if token == "" {
			t.Fatalf("issue %s returned no token: %v", label, cred)
		}
		return token
	}
	tokenA, tokenB := issue("go-a"), issue("go-b")

	// Phase 1: two fresh devices write concurrently and converge both ways.
	// They must run at the same time: each waits on a key only the other
	// writes, so running them sequentially would deadlock.
	type result struct {
		run map[string]any
		err error
	}
	chA := make(chan result, 1)
	chB := make(chan result, 1)
	go func() {
		run, err := runRelayChild("live", map[string]any{
			"relayUrl": url, "channelId": channelID, "token": tokenA,
			"groupKeyB64": groupKeyB64, "node": "go-a",
			"writes": [][2]string{{"a/0", "a0"}},
			"expect": [][2]string{{"a/0", "a0"}, {"b/1", "b1"}},
			"waitMs": 15000,
		}, tmp)
		chA <- result{run, err}
	}()
	go func() {
		run, err := runRelayChild("live", map[string]any{
			"relayUrl": url, "channelId": channelID, "token": tokenB,
			"groupKeyB64": groupKeyB64, "node": "go-b",
			"writes": [][2]string{{"b/0", "b0"}, {"b/1", "b1"}},
			"expect": [][2]string{{"a/0", "a0"}, {"b/1", "b1"}},
			"waitMs": 15000,
		}, tmp)
		chB <- result{run, err}
	}()
	ra, rb := <-chA, <-chB
	if ra.err != nil {
		t.Fatal(ra.err)
	}
	if rb.err != nil {
		t.Fatal(rb.err)
	}
	liveA, liveB := ra.run, rb.run

	// Phase 2, sequential restarts: B resumes from its snapshot and writes
	// b/2 while A is already down (A's phase-1 child exited), then A
	// resumes and must pull what it missed while down. The restored state of
	// each device is verified by the child before it starts the worker.
	restartedB, err := runRelayChild("restart", map[string]any{
		"relayUrl": url, "channelId": channelID, "token": tokenB,
		"groupKeyB64": groupKeyB64, "node": "go-b",
		"stateB64":          liveB["stateB64"],
		"expectBeforeStart": [][2]string{{"b/0", "b0"}, {"b/1", "b1"}},
		"writes":            [][2]string{{"b/2", "b2"}},
		"expect":            [][2]string{{"b/0", "b0"}, {"b/1", "b1"}, {"b/2", "b2"}},
		"waitMs":            15000,
	}, tmp)
	if err != nil {
		t.Fatal(err)
	}
	restartedA, err := runRelayChild("restart", map[string]any{
		"relayUrl": url, "channelId": channelID, "token": tokenA,
		"groupKeyB64": groupKeyB64, "node": "go-a",
		"stateB64":          liveA["stateB64"],
		"expectBeforeStart": [][2]string{{"a/0", "a0"}},
		"writes":            [][2]string{{"a/1", "a1"}},
		"expect":            [][2]string{{"a/0", "a0"}, {"a/1", "a1"}, {"b/1", "b1"}, {"b/2", "b2"}},
		"waitMs":            15000,
	}, tmp)
	if err != nil {
		t.Fatal(err)
	}

	// `pulled` marks the devices that must have applied an op pulled from the
	// relay: a restarted device that only writes its own key has nothing to
	// pull and legitimately reports zero.
	for _, tc := range []struct {
		phase string
		run   map[string]any
	}{
		{"live-a", liveA},
		{"live-b", liveB},
		{"restart-b", restartedB},
		{"restart-a", restartedA},
	} {
		assertChildOK(t, tc.phase, tc.run, tc.phase != "restart-b")
	}
	got := restartedA["got"].(map[string]any)
	if got["b/2"] != "b2" {
		t.Fatalf("A must catch what B wrote while A was down, got %v", got["b/2"])
	}
}
