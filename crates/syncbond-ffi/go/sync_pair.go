//go:build cgo

package syncbond

// SyncPair runs both directions of one oplog exchange concurrently.
//
// `sb_replicator_sync` blocks in one direction, so the responder half runs on
// a worker goroutine; the two halves use distinct handles, matching the ABI's
// single-thread-per-handle rule. It returns (initiator ops, responder ops).
func SyncPair(left, right *Replicator, initiator, responder *Session) (uint32, uint32, error) {
	type result struct {
		ops uint32
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ops, err := right.Sync(responder, false)
		ch <- result{ops, err}
	}()
	leftOps, leftErr := left.Sync(initiator, true)
	r := <-ch
	if leftErr != nil {
		return 0, 0, leftErr
	}
	if r.err != nil {
		return 0, 0, r.err
	}
	return leftOps, r.ops, nil
}
