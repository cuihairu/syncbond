"""pair_sync.py - Python consumer of syncbond over the shared ABI.

Same flow as examples/pair_sync.c and examples/pair_sync.cpp: pair, run a
full-duplex oplog sync, verify convergence, rotate a key epoch, and drive the
cross-language conformance runner. Run with:

    python examples/pair_sync.py
"""

import json

import syncbond

FIXTURE = {
    "version": 1,
    "scenarios": [
        {
            "type": "replication",
            "name": "lww",
            "strategy": "lww",
            "nodes": {"left": 1000, "right": 2000},
            "steps": [
                {"put": {"node": "left", "key": "k", "payload": "bGVmdA"}},
                {
                    "put": {
                        "node": "right",
                        "key": "k",
                        "payload": "cmlnaHQ",
                        "name": "left_sees_newer_write",
                    }
                },
                {"sync": ["left", "right"]},
                {
                    "check": {
                        "node": "left",
                        "key": "k",
                        "state": "live",
                        "payload": "cmlnaHQ",
                        "name": "left_sees_newer_write",
                    }
                },
                {
                    "check": {
                        "node": "right",
                        "key": "k",
                        "state": "live",
                        "payload": "cmlnaHQ",
                        "name": "right_keeps_newer_write",
                    }
                },
            ],
        },
        {
            "type": "key_epoch",
            "name": "rotation",
            "group": "g",
            "epoch": 1,
            "next_epoch": 2,
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "next_key": "__________________________________________8",
            "survivors": ["s1"],
            "removed": ["gone"],
            "plaintext": "cGF5bG9hZA",
        },
    ],
}


def main():
    failures = 0

    def expect(condition, what):
        nonlocal failures
        if not condition:
            print(f"FAIL: {what}")
            failures += 1

    try:
        # Pair two freshly generated devices over the in-memory loopback.
        pair = syncbond.pair_memory()
        expect(len(pair.code) == 6, "pairing code has six characters")
        expect(pair.initiator.group_id == pair.responder.group_id,
               "both sides derive the same group id")
        expect(bool(pair.initiator.peer_device_id), "peer device id is present")

        # Deterministic replicators on both ends of the paired session.
        left = syncbond.Replicator("left", syncbond.LWW_HLC, 1000)
        right = syncbond.Replicator("right", syncbond.LWW_HLC, 2000)

        left.put("greeting", b"hello from python")
        right.put("counter", b"42")
        left.put("doomed", b"x")
        left.delete("doomed")

        left_ops, right_ops = syncbond.sync_pair(
            left, pair.initiator, right, pair.responder
        )
        expect(left_ops == 3, f"initiator sent three ops, got {left_ops}")
        expect(right_ops == 1, f"responder sent one op, got {right_ops}")

        expect(right.get("greeting") == b"hello from python", "payload survived the sync")
        expect(left.get("counter") == b"42", "counter arrived")
        expect(right.get("doomed") is None, "deleted key stays deleted after sync")

        dump_left, dump_right = left.records_json(), right.records_json()
        expect(dump_left == dump_right, "canonical dumps of both sides are identical")
        print(f"converged state: {dump_left}")

        # Session invalidation blocks further traffic.
        expect(not pair.initiator.invalidated, "session is live before invalidation")
        pair.initiator.invalidate()
        expect(pair.initiator.invalidated, "session reports invalidated")
        try:
            pair.initiator.send(b"late")
            expect(False, "send after invalidation should fail")
        except syncbond.Error:
            pass

        # Key epoch rotation: seal under the new epoch, open with the same ring.
        ring = syncbond.Keyring("group-a")
        epoch, key = ring.rotate()
        expect(epoch == 2 and len(key) == 32, "rotation mints epoch 2 and 32 bytes")

        envelope = ring.seal("device-1", b"secret")
        expect(ring.open(envelope) == b"secret", "sealed payload round trips")

        stale = syncbond.Keyring("group-a")
        try:
            stale.open(envelope)
            expect(False, "stale epoch keyring should fail")
        except syncbond.Error:
            expect(syncbond.last_error_code() < 0, "stale epoch failure reports an SB_ERR code")

        # Cross-language conformance: same runner, same fixture, every language.
        report = json.loads(syncbond.conformance_run(json.dumps(FIXTURE)))
        expect(report["ok"] is True, "conformance report is ok")
        print(f"conformance: {json.dumps(report)}")
    except syncbond.Error as error:
        print(f"FAIL: unexpected error: {error}")
        failures += 1

    if failures:
        print(f"{failures} check(s) failed")
        return 1
    print("pair_sync: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
