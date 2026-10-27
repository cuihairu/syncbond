//go:build !cgo

// Stubs for CGO_ENABLED=0. The binding must consume the C ABI through cgo;
// when that is impossible every entry point fails loudly with ErrCgoDisabled
// instead of silently returning empty state.
package syncbond

func cgoErr() error { return ErrCgoDisabled }
func mustCgo()      { panic(ErrCgoDisabled) }

// --------------------------------------------------------------- version

func ABIVersion() uint32      { mustCgo(); return 0 }
func ProtocolVersion() uint32 { mustCgo(); return 0 }
func LastErrorCode() int32    { mustCgo(); return 0 }
func LastError() string       { mustCgo(); return "" }

// --------------------------------------------------------------- identity

func GenerateIdentity() *Identity { mustCgo(); return nil }

func ImportIdentity(_ []byte) (*Identity, error) { return nil, cgoErr() }

func (_ *Identity) Close()            {}
func (_ *Identity) DeviceID() string  { mustCgo(); return "" }
func (_ *Identity) PublicKey() []byte { mustCgo(); return nil }
func (_ *Identity) SecretKey() []byte { mustCgo(); return nil }

// --------------------------------------------------------------- pairing

func PairMemory(_ string) (*PairResult, error) { return nil, cgoErr() }

func (_ *PairResult) Code() string        { mustCgo(); return "" }
func (_ *PairResult) Initiator() *Session { mustCgo(); return nil }
func (_ *PairResult) Responder() *Session { mustCgo(); return nil }
func (p *PairResult) Close()              { p.initiator, p.responder = nil, nil }

// ---------------------------------------------------------------- session

func (_ *Session) Close()                {}
func (_ *Session) GroupID() string       { mustCgo(); return "" }
func (_ *Session) PeerDeviceID() string  { mustCgo(); return "" }
func (_ *Session) Invalidated() bool     { mustCgo(); return false }
func (_ *Session) Send(_ []byte) error   { return cgoErr() }
func (_ *Session) Recv() ([]byte, error) { return nil, cgoErr() }
func (_ *Session) Invalidate()           { mustCgo() }

// ------------------------------------------------------------ replicator

func NewReplicator(_ string, _ uint32) (*Replicator, error)                     { return nil, cgoErr() }
func NewReplicatorFixedClock(_ string, _ uint32, _ uint64) (*Replicator, error) { return nil, cgoErr() }

func (_ *Replicator) Close()                                   {}
func (_ *Replicator) NodeID() string                           { mustCgo(); return "" }
func (_ *Replicator) RecordCount() uint32                      { mustCgo(); return 0 }
func (_ *Replicator) OplogLen() uint32                         { mustCgo(); return 0 }
func (_ *Replicator) Put(_ string, _ []byte) error             { return cgoErr() }
func (_ *Replicator) Delete(_ string) error                    { return cgoErr() }
func (_ *Replicator) Get(_ string) ([]byte, error)             { return nil, cgoErr() }
func (_ *Replicator) LiveKeysJSON() string                     { mustCgo(); return "" }
func (_ *Replicator) OpJSON(_ uint32) (string, error)          { return "", cgoErr() }
func (_ *Replicator) ApplyRemoteJSON(_ string) (bool, error)   { return false, cgoErr() }
func (_ *Replicator) Sync(_ *Session, _ bool) (uint32, error)  { return 0, cgoErr() }
func (_ *Replicator) RecordsJSON() string                      { mustCgo(); return "" }
func (_ *Replicator) GCBarriersJSON() string                   { mustCgo(); return "" }
func (_ *Replicator) GCTombstones(_, _ uint64) (uint32, error) { return 0, cgoErr() }

// ------------------------------------------------------------ key material

func NewKeyring(_ string) *Keyring                                 { mustCgo(); return nil }
func ImportKeyring(_ string, _ uint64, _ []byte) (*Keyring, error) { return nil, cgoErr() }

func (_ *Keyring) Close()                             {}
func (_ *Keyring) Epoch() uint64                      { mustCgo(); return 0 }
func (_ *Keyring) Rotate() (uint64, []byte)           { mustCgo(); return 0, nil }
func (_ *Keyring) SealJSON(_ string, _ []byte) string { mustCgo(); return "" }
func (_ *Keyring) OpenJSON(_ string) ([]byte, error)  { return nil, cgoErr() }

// ---------------------------------------------------------- conformance

func ConformanceRun(_ string) (string, error) { return "", cgoErr() }

// SyncPair cannot run without the C ABI.
func SyncPair(_, _ *Replicator, _, _ *Session) (uint32, uint32, error) { return 0, 0, cgoErr() }
