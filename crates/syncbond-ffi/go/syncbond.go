//go:build cgo

// cgo implementation: forwards every call to the syncbond C ABI. See api.go
// for the shared type surface and nocgo.go for the CGO_ENABLED=0 stubs.
package syncbond

/*
#cgo CFLAGS: -I${SRCDIR}/../include
#cgo LDFLAGS: ${SRCDIR}/../../../target/release/libsyncbond_ffi.a -lpthread -ldl -lm
#include <stdlib.h>
#include <string.h>
#include "syncbond.h"

// Read both the thread-local error code and its text in one cgo call, so a
// goroutine that migrates OS threads after a failed call still sees a
// coherent pair.
typedef struct sb_take_last_s {
    int code;
    char message[256];
} sb_take_last_t;

static void sb_take_last(sb_take_last_t *out) {
    out->code = sb_last_error_code();
    out->message[0] = 0;
    const char *m = sb_last_error();
    if (m) {
        strncpy(out->message, m, sizeof(out->message) - 1);
    }
}
*/
import "C"

import (
	"runtime"
	"unsafe"
)

func takeError(code C.int) error {
	if int32(code) == ErrNone {
		return nil
	}
	var last C.sb_take_last_t
	C.sb_take_last(&last)
	// The ABI reports success/failure via the return value but stores the
	// precise SB_ERR_* code in the thread-local slot; prefer that code so the
	// SDK surfaces e.g. SB_ERR_KEY_EPOCH_MISMATCH instead of the generic
	// fallback. Fall back to the return code if the slot is unset.
	codeNum := int32(last.code)
	if codeNum == ErrNone {
		codeNum = int32(code)
	}
	return &Error{Code: codeNum, Message: C.GoString((*C.char)(unsafe.Pointer(&last.message[0])))}
}

func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// copyBuffer copies a caller-owned sb_buffer_t into a Go byte slice and
// releases it.
func copyBuffer(buf *C.sb_buffer_t) []byte {
	out := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	C.sb_free_buffer(buf)
	return out
}

func cstring(s string) *C.char { return C.CString(s) }

// --------------------------------------------------------------- version

// ABIVersion reports the ABI version of the linked library.
func ABIVersion() uint32 { return uint32(C.sb_abi_version()) }

// ProtocolVersion reports the wire protocol version of the linked library.
func ProtocolVersion() uint32 { return uint32(C.sb_protocol_version()) }

// LastErrorCode mirrors SB_ERR_* for the calling thread.
func LastErrorCode() int32 { return int32(C.sb_last_error_code()) }

// LastError returns the last error text for the calling thread, or "" when
// no error is pending.
func LastError() string { return C.GoString(C.sb_last_error()) }

// --------------------------------------------------------------- identity

// GenerateIdentity creates a fresh Ed25519 identity.
func GenerateIdentity() *Identity {
	id := &Identity{ptr: unsafe.Pointer(C.sb_identity_generate())}
	runtime.SetFinalizer(id, (*Identity).Close)
	return id
}

// ImportIdentity rebuilds an identity from a persisted 64-byte keypair.
func ImportIdentity(secret []byte) (*Identity, error) {
	c := C.sb_identity_import(bytesPtr(secret), C.size_t(len(secret)))
	if c == nil {
		return nil, takeError(C.sb_last_error_code())
	}
	id := &Identity{ptr: unsafe.Pointer(c)}
	runtime.SetFinalizer(id, (*Identity).Close)
	return id, nil
}

// Close releases the identity handle. It is safe to call more than once.
func (id *Identity) Close() {
	if id == nil || id.ptr == nil {
		return
	}
	C.sb_identity_free((*C.sb_identity)(id.ptr))
	id.ptr = nil
}

// DeviceID returns the stable device identifier.
func (id *Identity) DeviceID() string {
	text := C.sb_identity_device_id((*C.sb_identity)(id.ptr))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// PublicKey returns the 32-byte Ed25519 public key.
func (id *Identity) PublicKey() []byte {
	out := make([]byte, 32)
	C.sb_identity_public_key((*C.sb_identity)(id.ptr), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// SecretKey returns the 64-byte Ed25519 keypair.
func (id *Identity) SecretKey() []byte {
	out := make([]byte, 64)
	C.sb_identity_secret_key((*C.sb_identity)(id.ptr), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// --------------------------------------------------------------- pairing

// PairMemory pairs two freshly generated devices over an in-memory loopback.
// A nil or empty code generates one.
func PairMemory(code string) (*PairResult, error) {
	var cpass *C.char
	if code != "" {
		cpass = cstring(code)
		defer C.free(unsafe.Pointer(cpass))
	}
	res := C.sb_pair_memory(cpass)
	if res == nil {
		return nil, takeError(C.sb_last_error_code())
	}
	init := &Session{ptr: unsafe.Pointer(C.sb_pair_result_initiator(res))}
	resp := &Session{ptr: unsafe.Pointer(C.sb_pair_result_responder(res))}
	codeText := C.GoString(C.sb_pair_result_code(res))
	C.sb_pair_result_free(res)
	runtime.SetFinalizer(init, (*Session).Close)
	runtime.SetFinalizer(resp, (*Session).Close)
	return &PairResult{initiator: init, responder: resp, code: codeText}, nil
}

// Code returns the six-character pairing code.
func (p *PairResult) Code() string { return p.code }

// Initiator returns the initiator session; the caller owns it.
func (p *PairResult) Initiator() *Session { return p.initiator }

// Responder returns the responder session; the caller owns it.
func (p *PairResult) Responder() *Session { return p.responder }

// Close frees both sessions.
func (p *PairResult) Close() {
	if p.initiator != nil {
		p.initiator.Close()
	}
	if p.responder != nil {
		p.responder.Close()
	}
	p.initiator, p.responder = nil, nil
}

// ---------------------------------------------------------------- session

// Close releases the session handle.
func (s *Session) Close() {
	if s == nil || s.ptr == nil {
		return
	}
	C.sb_session_free((*C.sb_session)(s.ptr))
	s.ptr = nil
}

// GroupID returns the derived group identifier.
func (s *Session) GroupID() string {
	text := C.sb_session_group_id((*C.sb_session)(s.ptr))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// PeerDeviceID returns the paired peer's device id.
func (s *Session) PeerDeviceID() string {
	text := C.sb_session_peer_device_id((*C.sb_session)(s.ptr))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// Invalidated reports whether the session has been invalidated.
func (s *Session) Invalidated() bool {
	return C.sb_session_invalidated((*C.sb_session)(s.ptr)) != 0
}

// Send encrypts and enqueues one application payload.
func (s *Session) Send(payload []byte) error {
	return takeError(C.sb_session_send((*C.sb_session)(s.ptr), bytesPtr(payload), C.size_t(len(payload))))
}

// Recv blocks until the next application payload arrives and decrypts it.
func (s *Session) Recv() ([]byte, error) {
	var buf C.sb_buffer_t
	code := C.sb_session_recv((*C.sb_session)(s.ptr), &buf)
	if code != C.SB_ERR_NONE {
		return nil, takeError(code)
	}
	return copyBuffer(&buf), nil
}

// Invalidate marks the session as invalid, blocking further traffic.
func (s *Session) Invalidate() {
	C.sb_session_invalidate((*C.sb_session)(s.ptr))
}

// ------------------------------------------------------------ replicator

// NewReplicator creates a replicator with the wall clock.
func NewReplicator(nodeID string, strategy uint32) (*Replicator, error) {
	return newReplicator(nodeID, strategy, 0)
}

// NewReplicatorFixedClock is NewReplicator with a frozen `nowMs` for
// reproducible runs; 0 falls back to the wall clock.
func NewReplicatorFixedClock(nodeID string, strategy uint32, nowMs uint64) (*Replicator, error) {
	return newReplicator(nodeID, strategy, nowMs)
}

func newReplicator(nodeID string, strategy uint32, nowMs uint64) (*Replicator, error) {
	cnode := cstring(nodeID)
	defer C.free(unsafe.Pointer(cnode))
	var r *C.sb_replicator
	if nowMs == 0 {
		r = C.sb_replicator_new(cnode, C.uint32_t(strategy))
	} else {
		r = C.sb_replicator_new_fixed_clock(cnode, C.uint32_t(strategy), C.uint64_t(nowMs))
	}
	if r == nil {
		return nil, takeError(C.sb_last_error_code())
	}
	rep := &Replicator{ptr: unsafe.Pointer(r)}
	runtime.SetFinalizer(rep, (*Replicator).Close)
	return rep, nil
}

// Close releases the replicator handle.
func (r *Replicator) Close() {
	if r == nil || r.ptr == nil {
		return
	}
	C.sb_replicator_free((*C.sb_replicator)(r.ptr))
	r.ptr = nil
}

// NodeID returns the replicator's node identifier.
func (r *Replicator) NodeID() string {
	text := C.sb_replicator_node_id((*C.sb_replicator)(r.ptr))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// RecordCount returns the number of live records.
func (r *Replicator) RecordCount() uint32 {
	return uint32(C.sb_replicator_record_count((*C.sb_replicator)(r.ptr)))
}

// OplogLen returns the number of wire operations logged.
func (r *Replicator) OplogLen() uint32 {
	return uint32(C.sb_replicator_oplog_len((*C.sb_replicator)(r.ptr)))
}

// Put stores a payload under key.
func (r *Replicator) Put(key string, payload []byte) error {
	ckey := cstring(key)
	defer C.free(unsafe.Pointer(ckey))
	return takeError(C.sb_replicator_put((*C.sb_replicator)(r.ptr), ckey, bytesPtr(payload), C.size_t(len(payload))))
}

// Delete tombstones key.
func (r *Replicator) Delete(key string) error {
	ckey := cstring(key)
	defer C.free(unsafe.Pointer(ckey))
	return takeError(C.sb_replicator_delete((*C.sb_replicator)(r.ptr), ckey))
}

// Get returns the live payload, or (nil, ResultAbsent) when the key is absent
// or tombstoned.
func (r *Replicator) Get(key string) ([]byte, error) {
	ckey := cstring(key)
	defer C.free(unsafe.Pointer(ckey))
	var buf C.sb_buffer_t
	code := C.sb_replicator_get((*C.sb_replicator)(r.ptr), ckey, &buf)
	if code == C.SB_RESULT_ABSENT {
		return nil, &Error{Code: ResultAbsent, Message: "key absent"}
	}
	if code != C.SB_ERR_NONE {
		return nil, takeError(code)
	}
	return copyBuffer(&buf), nil
}

// LiveKeysJSON returns a JSON array of live keys.
func (r *Replicator) LiveKeysJSON() string {
	text := C.sb_replicator_live_keys_json((*C.sb_replicator)(r.ptr))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// OpJSON returns one wire op as JSON, or an error when the index is out of
// range.
func (r *Replicator) OpJSON(index uint32) (string, error) {
	text := C.sb_replicator_op_json((*C.sb_replicator)(r.ptr), C.uint32_t(index))
	if text == nil {
		return "", takeError(C.sb_last_error_code())
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out, nil
}

// ApplyRemoteJSON applies one wire op. It reports false when the op was a
// duplicate or was rejected because it would resurrect a GC'd delete.
func (r *Replicator) ApplyRemoteJSON(opJSON string) (bool, error) {
	cop := cstring(opJSON)
	defer C.free(unsafe.Pointer(cop))
	code := C.sb_replicator_apply_remote_json((*C.sb_replicator)(r.ptr), cop)
	if code < 0 {
		return false, takeError(code)
	}
	return code != 0, nil
}

// Sync runs one direction of a full-duplex oplog exchange. `sendFirst` is the
// initiator. It blocks, so run the two directions concurrently with SyncPair.
func (r *Replicator) Sync(s *Session, sendFirst bool) (uint32, error) {
	var sent C.uint32_t
	sf := C.int(0)
	if sendFirst {
		sf = 1
	}
	code := C.sb_replicator_sync((*C.sb_replicator)(r.ptr), (*C.sb_session)(s.ptr), sf, &sent)
	if code != C.SB_ERR_NONE {
		return 0, takeError(code)
	}
	return uint32(sent), nil
}

// RecordsJSON returns the canonical, fully sorted node dump.
func (r *Replicator) RecordsJSON() string {
	text := C.sb_replicator_records_json((*C.sb_replicator)(r.ptr))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// GCBarriersJSON returns the canonical dump of collected tombstone barriers.
func (r *Replicator) GCBarriersJSON() string {
	text := C.sb_replicator_gc_barriers_json((*C.sb_replicator)(r.ptr))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// GCTombstones collects tombstones older than `olderThanMs` relative to
// `nowMs` that are causally dominated by every known replica.
func (r *Replicator) GCTombstones(nowMs, olderThanMs uint64) (uint32, error) {
	code := C.sb_replicator_gc_tombstones((*C.sb_replicator)(r.ptr), C.uint64_t(nowMs), C.uint64_t(olderThanMs))
	if code < 0 {
		return 0, takeError(code)
	}
	return uint32(code), nil
}

// ------------------------------------------------------------ key material

// NewKeyring creates a keyring for a group.
func NewKeyring(groupID string) *Keyring {
	cgroup := cstring(groupID)
	defer C.free(unsafe.Pointer(cgroup))
	k := &Keyring{ptr: unsafe.Pointer(C.sb_keyring_new(cgroup))}
	runtime.SetFinalizer(k, (*Keyring).Close)
	return k
}

// ImportKeyring rebuilds a keyring from explicit key material.
func ImportKeyring(groupID string, epoch uint64, key []byte) (*Keyring, error) {
	cgroup := cstring(groupID)
	defer C.free(unsafe.Pointer(cgroup))
	k := C.sb_keyring_import(cgroup, C.uint64_t(epoch), bytesPtr(key))
	if k == nil {
		return nil, takeError(C.sb_last_error_code())
	}
	ring := &Keyring{ptr: unsafe.Pointer(k)}
	runtime.SetFinalizer(ring, (*Keyring).Close)
	return ring, nil
}

// Close releases the keyring handle.
func (k *Keyring) Close() {
	if k == nil || k.ptr == nil {
		return
	}
	C.sb_keyring_free((*C.sb_keyring)(k.ptr))
	k.ptr = nil
}

// Epoch returns the current key epoch.
func (k *Keyring) Epoch() uint64 { return uint64(C.sb_keyring_epoch((*C.sb_keyring)(k.ptr))) }

// Rotate mints the next epoch and returns (epoch, key) for distribution.
func (k *Keyring) Rotate() (uint64, []byte) {
	var epoch C.uint64_t
	key := make([]byte, 32)
	C.sb_keyring_rotate((*C.sb_keyring)(k.ptr), &epoch, (*C.uint8_t)(unsafe.Pointer(&key[0])))
	return uint64(epoch), key
}

// SealJSON seals plaintext under the current epoch and returns envelope JSON.
func (k *Keyring) SealJSON(senderDeviceID string, plaintext []byte) string {
	csender := cstring(senderDeviceID)
	defer C.free(unsafe.Pointer(csender))
	text := C.sb_keyring_seal_json((*C.sb_keyring)(k.ptr), csender, bytesPtr(plaintext), C.size_t(len(plaintext)))
	if text == nil {
		return ""
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out
}

// OpenJSON opens an envelope with the current key and epoch.
func (k *Keyring) OpenJSON(envelopeJSON string) ([]byte, error) {
	cenvelope := cstring(envelopeJSON)
	defer C.free(unsafe.Pointer(cenvelope))
	var buf C.sb_buffer_t
	code := C.sb_keyring_open_json((*C.sb_keyring)(k.ptr), cenvelope, &buf)
	if code != C.SB_ERR_NONE {
		return nil, takeError(code)
	}
	return copyBuffer(&buf), nil
}

// ---------------------------------------------------------- conformance

// ConformanceRun runs a cross-language conformance fixture and returns the
// canonical JSON report.
func ConformanceRun(fixtureJSON string) (string, error) {
	cfixture := cstring(fixtureJSON)
	defer C.free(unsafe.Pointer(cfixture))
	text := C.sb_conformance_run(cfixture)
	if text == nil {
		return "", takeError(C.sb_last_error_code())
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return out, nil
}
