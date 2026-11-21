//go:build cgo

// Relay driver over the syncbond-ffi handle layer (todo.md DSR-39): one
// native driver owns the whole network session — the relay client, the tokio
// runtime and one worker thread that runs the core driver loop — plus the
// device state. The host only configures, starts, stops and interleaves
// writes; the relay protocol never has to be rewritten in Go. See api.go for
// the shared type surface and nocgo.go for the CGO_ENABLED=0 stubs.
package syncbond

/*
// cgo compiles this file's preamble as its own translation unit, so the
// header is included here again rather than shared from syncbond.go.
#include <stdlib.h>
#include "syncbond.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// NewRelayDriver builds a driver over one live relay channel. `groupKey` is
// the shared 32-byte group key material (two devices in one group import the
// same bytes); `nodeID` names a fresh replicator and is ignored when `state`
// restores one. `caDER` pins a CA when tlsMode is TLSValidateCA. `state` is
// an exported snapshot to resume from. The four native handles the driver
// needs are built here and their ownership transfers to the driver on
// success AND on failure, matching the ABI contract.
func NewRelayDriver(relayURL, channelID, channelToken, serverID, cursorChannel, groupID string, keyEpoch uint64, groupKey []byte, nodeID string, timeoutMS uint64, tlsMode uint32, caDER, state []byte) (*RelayDriver, error) {
	if len(groupKey) != 32 {
		return nil, &Error{Code: ErrInput, Message: "group key must be exactly 32 bytes"}
	}
	curl := cstring(relayURL)
	defer C.free(unsafe.Pointer(curl))
	cchan := cstring(channelID)
	defer C.free(unsafe.Pointer(cchan))
	ctok := cstring(channelToken)
	defer C.free(unsafe.Pointer(ctok))
	csrv := cstring(serverID)
	defer C.free(unsafe.Pointer(csrv))
	ccur := cstring(cursorChannel)
	defer C.free(unsafe.Pointer(ccur))
	cgroup := cstring(groupID)
	defer C.free(unsafe.Pointer(cgroup))
	cnode := cstring(nodeID)
	defer C.free(unsafe.Pointer(cnode))

	// Fresh handles per attempt; if any of them fails, free the ones already
	// created before returning. Once sb_relay_driver_new is called it owns
	// all four on success AND on failure, so neither path frees them here.
	identity := C.sb_identity_generate()
	keyring := C.sb_keyring_import(cgroup, C.uint64_t(keyEpoch), bytesPtr(groupKey))
	replicator := (*C.sb_replicator)(nil)
	receive := (*C.sb_receive_state)(nil)
	if keyring == nil {
		C.sb_identity_free(identity)
		return nil, takeError(C.sb_last_error_code())
	}
	if state != nil {
		if code := C.sb_state_import(bytesPtr(state), C.size_t(len(state)), C.SB_STRATEGY_LWW_HLC, &replicator, &receive); code != C.SB_ERR_NONE {
			C.sb_identity_free(identity)
			C.sb_keyring_free(keyring)
			return nil, takeError(code)
		}
	} else {
		replicator = C.sb_replicator_new(cnode, C.SB_STRATEGY_LWW_HLC)
		if replicator == nil {
			C.sb_identity_free(identity)
			C.sb_keyring_free(keyring)
			return nil, takeError(C.sb_last_error_code())
		}
		receive = C.sb_receive_state_new()
	}

	driver := C.sb_relay_driver_new(
		curl, cchan, ctok, csrv, ccur, cgroup, C.uint64_t(keyEpoch),
		identity, keyring, replicator, receive, C.uint64_t(timeoutMS),
		C.uint32_t(tlsMode), bytesPtr(caDER), C.size_t(len(caDER)))
	if driver == nil {
		// The library freed identity, keyring, replicator and receive
		// already; nothing to release on this side.
		return nil, takeError(C.sb_last_error_code())
	}
	d := &RelayDriver{ptr: unsafe.Pointer(driver)}
	runtime.SetFinalizer(d, (*RelayDriver).Close)
	return d, nil
}

// Close stops the worker (joining it) and frees the driver. It is safe to
// call more than once, and a driver left to the garbage collector closes
// itself through the finalizer.
func (d *RelayDriver) Close() {
	if d == nil || d.ptr == nil {
		return
	}
	C.sb_relay_driver_free((*C.sb_relay_driver)(d.ptr))
	d.ptr = nil
}

// Config replaces the loop's pacing knobs; only effective before Start. All
// the count bounds must be positive and maxBackoffMS >= initialBackoffMS.
func (d *RelayDriver) Config(pageLimit uint16, maxPagesPerCycle int, initialBackoffMS, maxBackoffMS uint64, maxAttempts uint32, idleIntervalMS uint64) error {
	return takeError(C.sb_relay_driver_config((*C.sb_relay_driver)(d.ptr), C.uint16_t(pageLimit),
		C.size_t(maxPagesPerCycle), C.uint64_t(initialBackoffMS), C.uint64_t(maxBackoffMS),
		C.uint32_t(maxAttempts), C.uint64_t(idleIntervalMS)))
}

// Start spawns the worker thread. A second Start while running is an input
// error; after Stop the driver may be started again.
func (d *RelayDriver) Start() error {
	return takeError(C.sb_relay_driver_start((*C.sb_relay_driver)(d.ptr)))
}

// Stop cancels the loop and joins the worker; idempotent, and also the
// resource-close path (Close does the same join). The stop reason and any
// error text stay queryable.
func (d *RelayDriver) Stop() error {
	return takeError(C.sb_relay_driver_stop((*C.sb_relay_driver)(d.ptr)))
}

// Write stages a local write; the worker sends it on its next cycle. It
// waits only until the current cycle finishes.
func (d *RelayDriver) Write(key string, payload []byte) error {
	ckey := cstring(key)
	defer C.free(unsafe.Pointer(ckey))
	return takeError(C.sb_relay_driver_write((*C.sb_relay_driver)(d.ptr), ckey, bytesPtr(payload), C.size_t(len(payload))))
}

// Delete stages a local delete (a causal tombstone), like Write.
func (d *RelayDriver) Delete(key string) error {
	ckey := cstring(key)
	defer C.free(unsafe.Pointer(ckey))
	return takeError(C.sb_relay_driver_delete((*C.sb_relay_driver)(d.ptr), ckey))
}

// Get returns the live payload, or (nil, ResultAbsent) when the key is
// absent or tombstoned.
func (d *RelayDriver) Get(key string) ([]byte, error) {
	ckey := cstring(key)
	defer C.free(unsafe.Pointer(ckey))
	var buf C.sb_buffer_t
	code := C.sb_relay_driver_get((*C.sb_relay_driver)(d.ptr), ckey, &buf)
	if code == C.SB_RESULT_ABSENT {
		return nil, &Error{Code: ResultAbsent, Message: "key absent"}
	}
	if code != C.SB_ERR_NONE {
		return nil, takeError(code)
	}
	return copyBuffer(&buf), nil
}

// Running reports whether the worker thread is up.
func (d *RelayDriver) Running() bool {
	return C.sb_relay_driver_running((*C.sb_relay_driver)(d.ptr)) != 0
}

// Progress fills the monotonic counters (and the running flag).
func (d *RelayDriver) Progress() RelayProgress {
	var p C.sb_relay_progress_t
	if C.sb_relay_driver_progress((*C.sb_relay_driver)(d.ptr), &p) != C.SB_ERR_NONE {
		return RelayProgress{}
	}
	return RelayProgress{
		Running:       p.running != 0,
		Cycles:        uint64(p.cycles),
		SentBatches:   uint64(p.sent_batches),
		SentEnvelopes: uint64(p.sent_envelopes),
		PagesPulled:   uint64(p.pages_pulled),
		Applied:       uint64(p.applied),
	}
}

// StopReason is one of the DriverStop* constants; DriverStopNone while
// running or never started.
func (d *RelayDriver) StopReason() int32 {
	return int32(C.sb_relay_driver_stop_reason((*C.sb_relay_driver)(d.ptr)))
}

// Error returns the text of the error that ended the loop, or nil when it
// ended cleanly (or is still running).
func (d *RelayDriver) Error() error {
	text := C.sb_relay_driver_error((*C.sb_relay_driver)(d.ptr))
	if text == nil {
		return nil
	}
	out := C.GoString(text)
	C.sb_free_string(text)
	return errors.New(out)
}

// ExportState returns the device state plus the receive cursors as one
// versioned snapshot, the blob a later `state` argument restores from. The
// blob is private (it embeds the device identity); guard it accordingly.
func (d *RelayDriver) ExportState() ([]byte, error) {
	var buf C.sb_buffer_t
	code := C.sb_relay_driver_export_state((*C.sb_relay_driver)(d.ptr), &buf)
	if code != C.SB_ERR_NONE {
		return nil, takeError(code)
	}
	return copyBuffer(&buf), nil
}
