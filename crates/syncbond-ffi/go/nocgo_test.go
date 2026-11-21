//go:build !cgo

package syncbond

import "testing"

// CGO_ENABLED=0 must fail loudly, never silently produce empty state: the
// binding consumes the C ABI, so every entry point reports ErrCgoDisabled.
func TestCgoDisabledFailsLoudly(t *testing.T) {
	cases := []struct {
		name string
		call func() error
	}{
		{"ImportIdentity", func() error { _, err := ImportIdentity(make([]byte, 64)); return err }},
		{"PairMemory", func() error { _, err := PairMemory(""); return err }},
		{"NewReplicator", func() error { _, err := NewReplicator("n", 0); return err }},
		{"NewReplicatorFixedClock", func() error { _, err := NewReplicatorFixedClock("n", 0, 1); return err }},
		{"ImportKeyring", func() error { _, err := ImportKeyring("g", 1, make([]byte, 32)); return err }},
		{"ConformanceRun", func() error { _, err := ConformanceRun("{}"); return err }},
		{"SyncPair", func() error { _, _, err := SyncPair(nil, nil, nil, nil); return err }},
		{"NewRelayDriver", func() error {
			_, err := NewRelayDriver("http://127.0.0.1:1", "ch", "tok", "s", "c", "g", 1,
				make([]byte, 32), "n", 100, TLSValidate, nil, nil)
			return err
		}},
		{"RelayDriverGet", func() error {
			var d *RelayDriver
			_, err := d.Get("k")
			return err
		}},
		{"RelayDriverStart", func() error {
			var d *RelayDriver
			return d.Start()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("expected an error under CGO_ENABLED=0")
			}
			se, ok := err.(*Error)
			if !ok || se.Code != ErrInternal || se.Message == "" {
				t.Fatalf("error = %v, want ErrCgoDisabled", err)
			}
		})
	}
}
