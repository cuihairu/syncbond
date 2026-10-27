//go:build cgo

package syncbond

import (
	"strings"
	"testing"
)

const fixture = `{
  "version":1,
  "scenarios":[
    {"type":"replication","name":"lww","strategy":"lww",
     "nodes":{"left":1000,"right":2000},
     "steps":[
       {"put":{"node":"left","key":"k","payload":"bGVmdA"}},
       {"put":{"node":"right","key":"k","payload":"cmlnaHQ","name":"left_sees_newer_write"}},
       {"sync":["left","right"]},
       {"check":{"node":"left","key":"k","state":"live","payload":"cmlnaHQ","name":"left_sees_newer_write"}},
       {"check":{"node":"right","key":"k","state":"live","payload":"cmlnaHQ","name":"right_keeps_newer_write"}}
     ]},
    {"type":"key_epoch","name":"rotation","group":"g","epoch":1,"next_epoch":2,
     "key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
     "next_key":"__________________________________________8",
     "survivors":["s1"],"removed":["gone"],
     "plaintext":"cGF5bG9hZA"}
  ]
}`

func TestVersions(t *testing.T) {
	if got := ABIVersion(); got != 1 {
		t.Fatalf("ABI version = %d, want 1", got)
	}
	if got := ProtocolVersion(); got != 1 {
		t.Fatalf("protocol version = %d, want 1", got)
	}
}

func TestIdentityImportRoundTrip(t *testing.T) {
	id := GenerateIdentity()
	secret := id.SecretKey()
	if len(secret) != 64 {
		t.Fatalf("secret key length = %d, want 64", len(secret))
	}
	pub := id.PublicKey()
	if len(pub) != 32 {
		t.Fatalf("public key length = %d, want 32", len(pub))
	}
	deviceID := id.DeviceID()
	if deviceID == "" {
		t.Fatal("device id is empty")
	}
	id.Close()

	rebuilt, err := ImportIdentity(secret)
	if err != nil {
		t.Fatalf("ImportIdentity: %v", err)
	}
	defer rebuilt.Close()
	if rebuilt.DeviceID() != deviceID {
		t.Fatalf("rebuilt device id = %q, want %q", rebuilt.DeviceID(), deviceID)
	}
}

func TestPairAndSyncConverge(t *testing.T) {
	pair, err := PairMemory("")
	if err != nil {
		t.Fatalf("PairMemory: %v", err)
	}
	defer pair.Close()

	init, resp := pair.Initiator(), pair.Responder()
	if pair.Code() == "" || len(pair.Code()) != 6 {
		t.Fatalf("pairing code = %q, want 6 chars", pair.Code())
	}
	if init.GroupID() == "" || init.GroupID() != resp.GroupID() {
		t.Fatalf("group ids differ: init=%q resp=%q", init.GroupID(), resp.GroupID())
	}
	if init.PeerDeviceID() == "" || resp.PeerDeviceID() == "" {
		t.Fatal("one or both peer device ids are empty")
	}

	left, err := NewReplicatorFixedClock("left", StrategyLwwHLC, 1000)
	if err != nil {
		t.Fatalf("left replicator: %v", err)
	}
	defer left.Close()
	right, err := NewReplicatorFixedClock("right", StrategyLwwHLC, 2000)
	if err != nil {
		t.Fatalf("right replicator: %v", err)
	}
	defer right.Close()

	if err := left.Put("greeting", []byte("hello from go")); err != nil {
		t.Fatalf("put greeting: %v", err)
	}
	if err := right.Put("counter", []byte("42")); err != nil {
		t.Fatalf("put counter: %v", err)
	}
	if err := left.Put("doomed", []byte("x")); err != nil {
		t.Fatalf("put doomed: %v", err)
	}
	if err := left.Delete("doomed"); err != nil {
		t.Fatalf("delete doomed: %v", err)
	}

	sentInit, sentResp, err := SyncPair(left, right, init, resp)
	if err != nil {
		t.Fatalf("SyncPair: %v", err)
	}
	if sentInit != 3 || sentResp != 1 {
		t.Fatalf("sent ops = (%d,%d), want (3,1)", sentInit, sentResp)
	}

	greeting, err := right.Get("greeting")
	if err != nil {
		t.Fatalf("get greeting on right: %v", err)
	}
	if string(greeting) != "hello from go" {
		t.Fatalf("greeting = %q, want %q", greeting, "hello from go")
	}
	counter, err := left.Get("counter")
	if err != nil {
		t.Fatalf("get counter on left: %v", err)
	}
	if string(counter) != "42" {
		t.Fatalf("counter = %q, want 42", counter)
	}
	if _, err := right.Get("doomed"); err == nil {
		t.Fatal("doomed key still live after sync")
	} else if se, ok := err.(*Error); !ok || se.Code != ResultAbsent {
		t.Fatalf("doomed Get error = %v, want ResultAbsent", err)
	}

	dumpL, dumpR := left.RecordsJSON(), right.RecordsJSON()
	if dumpL == "" || dumpL != dumpR {
		t.Fatalf("canonical dumps differ:\nleft=%s\nright=%s", dumpL, dumpR)
	}
}

func TestSessionInvalidation(t *testing.T) {
	pair, err := PairMemory("")
	if err != nil {
		t.Fatalf("PairMemory: %v", err)
	}
	defer pair.Close()
	init := pair.Initiator()
	if init.Invalidated() {
		t.Fatal("session reports invalidated before invalidation")
	}
	init.Invalidate()
	if !init.Invalidated() {
		t.Fatal("session does not report invalidated after Invalidate")
	}
}

func TestKeyringRotateSealOpen(t *testing.T) {
	ring := NewKeyring("group-a")
	defer ring.Close()
	if ring.Epoch() != 1 {
		t.Fatalf("initial epoch = %d, want 1", ring.Epoch())
	}
	epoch, key := ring.Rotate()
	if len(key) != 32 {
		t.Fatalf("rotated key length = %d, want 32", len(key))
	}
	if epoch != 2 || ring.Epoch() != 2 {
		t.Fatalf("rotated epoch = %d/%d, want 2", epoch, ring.Epoch())
	}
	envelope := ring.SealJSON("device-1", []byte("secret"))
	if envelope == "" {
		t.Fatal("seal returned empty envelope")
	}
	plain, err := ring.OpenJSON(envelope)
	if err != nil {
		t.Fatalf("OpenJSON: %v", err)
	}
	if string(plain) != "secret" {
		t.Fatalf("opened payload = %q, want secret", plain)
	}
}

func TestKeyringImportAndCrossEpochReject(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	ring, err := ImportKeyring("g", 7, key)
	if err != nil {
		t.Fatalf("ImportKeyring: %v", err)
	}
	defer ring.Close()
	if ring.Epoch() != 7 {
		t.Fatalf("imported epoch = %d, want 7", ring.Epoch())
	}

	// A ring at a different epoch must reject opening the sealed envelope.
	other, err := ImportKeyring("g", 8, key)
	if err != nil {
		t.Fatalf("ImportKeyring other: %v", err)
	}
	defer other.Close()
	envelope := ring.SealJSON("s1", []byte("x"))
	if _, err := other.OpenJSON(envelope); err == nil {
		t.Fatal("cross-epoch open should fail")
	} else if se, ok := err.(*Error); !ok || se.Code != ErrKeyEpochMismatch {
		t.Fatalf("cross-epoch error = %v, want ErrKeyEpochMismatch", err)
	}
}

func TestSessionSendRecv(t *testing.T) {
	pair, err := PairMemory("")
	if err != nil {
		t.Fatalf("PairMemory: %v", err)
	}
	defer pair.Close()
	init, resp := pair.Initiator(), pair.Responder()
	// Both sides send, each receives the other's payload.
	if err := init.Send([]byte("ping")); err != nil {
		t.Fatalf("init send: %v", err)
	}
	if err := resp.Send([]byte("pong")); err != nil {
		t.Fatalf("resp send: %v", err)
	}
	got, err := init.Recv()
	if err != nil {
		t.Fatalf("init recv: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("init received %q, want pong", got)
	}
	got, err = resp.Recv()
	if err != nil {
		t.Fatalf("resp recv: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("resp received %q, want ping", got)
	}
}

func TestConformanceRun(t *testing.T) {
	report, err := ConformanceRun(fixture)
	if err != nil {
		t.Fatalf("ConformanceRun: %v", err)
	}
	if !strings.Contains(report, `"ok":true`) {
		t.Fatalf("conformance report not ok: %s", report)
	}
}
