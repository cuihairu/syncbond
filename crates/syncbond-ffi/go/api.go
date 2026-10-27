// Package syncbond is a thin Go cgo binding over the syncbond C ABI.
//
// It contains no protocol logic: every call forwards to syncbond-ffi, which
// owns all merge, encryption and pairing semantics. The binding only adds Go
// types, byte conversions and resource management, exactly as the header in
// crates/syncbond-ffi/include/syncbond.h requires.
package syncbond

import (
	"fmt"
	"unsafe"
)

// Result/error codes, mirroring the SB_ERR_* and SB_RESULT_* constants.
const (
	ErrNone             int32 = 0
	ErrProtocol         int32 = -1
	ErrInput            int32 = -2
	ErrVersionMismatch  int32 = -3
	ErrCrossGroup       int32 = -4
	ErrKeyEpochMismatch int32 = -5
	ErrReplay           int32 = -6
	ErrAuthFailed       int32 = -7
	ErrInternal         int32 = -8
	ResultAbsent        int32 = 1
)

// Merge strategies accepted by NewReplicator/NewReplicatorFixedClock.
const (
	StrategyLwwHLC    uint32 = 0
	StrategyOrSet     uint32 = 1
	StrategyPnCounter uint32 = 2
)

// Error is one syncbond failure carrying a stable SB_ERR_* code and the
// human-readable text the library set for the calling thread.
type Error struct {
	Code    int32
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("syncbond: error %d", e.Code)
	}
	return fmt.Sprintf("syncbond: %s (code %d)", e.Message, e.Code)
}

// Is lets callers use errors.Is to match a stable SB_ERR_* code.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && e.Code == other.Code
}

// ErrCgoDisabled is returned by every entry point when the package is built
// with CGO_ENABLED=0. The binding needs cgo because it consumes the C ABI;
// failing loudly avoids a silent no-op SDK.
var ErrCgoDisabled = &Error{Code: ErrInternal, Message: "syncbond requires cgo: build with CGO_ENABLED=1"}

// handle is an opaque C pointer. The same struct layout works with and
// without cgo; the stubs never dereference it.
type handle = unsafe.Pointer

// Identity is one device's Ed25519 key material.
type Identity struct {
	ptr handle
}

// Session is one authenticated, encrypted end of a pairing.
type Session struct {
	ptr handle
}

// PairResult holds the two sessions minted by one in-memory pairing.
type PairResult struct {
	initiator *Session
	responder *Session
	code      string
}

// Replicator is one synchronizing device.
type Replicator struct {
	ptr handle
}

// Keyring holds group key material with replay tracking.
type Keyring struct {
	ptr handle
}
