"""Acceptance tests for the Python bindings.

The bindings must not contain protocol logic: they serialize, manage
resources, and forward to the shared handle layer. The interesting
assertions here are cross-language behaviors — merge convergence, key epoch
rotation, replay rejection, tombstone GC — driven through the same code every
language runs.
"""

import json
from pathlib import Path

import pytest

import syncbond

# The canonical cross-language fixture, shared by every binding
# (crates/syncbond-ffi/fixtures/conformance.json). Loading the same on-disk
# file keeps the merge / tombstone-GC / key-epoch scenarios byte-identical
# across languages.
FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "syncbond-ffi"
    / "fixtures"
    / "conformance.json"
)
EXPECTED_PATH = FIXTURE_PATH.with_name("conformance.expected.json")
# The raw file bytes: the runner must see exactly the canonical fixture, not a
# re-serialized copy, so the report stays byte-identical across languages.
FIXTURE = FIXTURE_PATH.read_text(encoding="utf-8")


def test_pair_produces_matching_group_ids():
    pair = syncbond.pair_memory()
    assert len(pair.code) == 6
    assert pair.initiator.group_id == pair.responder.group_id
    assert pair.initiator.peer_device_id
    assert not pair.initiator.invalidated


def test_pair_with_explicit_code():
    pair = syncbond.pair_memory("7HJKMP")
    assert pair.code == "7HJKMP"


def test_sync_converges_both_sides():
    pair = syncbond.pair_memory()
    left = syncbond.Replicator("left", syncbond.LWW_HLC, 1000)
    right = syncbond.Replicator("right", syncbond.LWW_HLC, 2000)

    left.put("greeting", b"hello from python")
    right.put("counter", b"42")

    left_ops, right_ops = syncbond.sync_pair(
        left, pair.initiator, right, pair.responder
    )
    assert (left_ops, right_ops) == (1, 1)
    assert right.get("greeting") == b"hello from python"
    assert left.get("counter") == b"42"
    assert left.records_json() == right.records_json()


def test_deleted_key_stays_deleted_after_sync():
    pair = syncbond.pair_memory()
    left = syncbond.Replicator("left", syncbond.LWW_HLC, 1000)
    right = syncbond.Replicator("right", syncbond.LWW_HLC, 2000)

    left.put("doomed", b"x")
    left.delete("doomed")
    syncbond.sync_pair(left, pair.initiator, right, pair.responder)

    assert right.get("doomed") is None
    assert "doomed" not in json.loads(right.live_keys_json())
    assert json.loads(right.records_json())["records"]["doomed"]["deleted"] is True


def test_later_write_wins_over_earlier_concurrent_write():
    pair = syncbond.pair_memory()
    left = syncbond.Replicator("left", syncbond.LWW_HLC, 1000)
    right = syncbond.Replicator("right", syncbond.LWW_HLC, 2000)

    left.put("k", b"left")
    right.put("k", b"right")
    syncbond.sync_pair(left, pair.initiator, right, pair.responder)

    assert left.get("k") == b"right"
    assert right.get("k") == b"right"


def test_or_set_strategy_adds_and_removes():
    pair = syncbond.pair_memory()
    left = syncbond.Replicator("left", syncbond.OR_SET, 1000)
    right = syncbond.Replicator("right", syncbond.OR_SET, 2000)

    left.put("s", b'{"adds":{"x":["t1"]},"rems":[]}')
    right.put("s", b'{"adds":{"y":["t2"]},"rems":[]}')
    syncbond.sync_pair(left, pair.initiator, right, pair.responder)
    assert left.records_json() == right.records_json()


def test_malformed_strategy_payload_rejected_not_panicked():
    # A malformed OR-Set / PN-Counter payload must surface as a normal error
    # (the same explicit failure every language binding reports), not a panic
    # that would crash the interpreter.
    for strategy in (syncbond.OR_SET, syncbond.PN_COUNTER):
        replicator = syncbond.Replicator("malformed", strategy, 1000)
        with pytest.raises(syncbond.Error):
            replicator.put("k", b"not-a-strategy-payload")
        assert replicator.record_count == 0


def test_gc_collects_and_survives_sync():
    pair = syncbond.pair_memory()
    left = syncbond.Replicator("left", syncbond.LWW_HLC, 1000)
    right = syncbond.Replicator("right", syncbond.LWW_HLC, 2000)

    left.put("old", b"v")
    left.delete("old")
    right.put("keep", b"k")
    syncbond.sync_pair(left, pair.initiator, right, pair.responder)

    collected = right.gc_tombstones(now_ms=2000, older_than_ms=0)
    assert collected == 1
    assert right.get("old") is None
    assert right.get("keep") == b"k"


def test_gc_rejects_before_the_time_threshold():
    pair = syncbond.pair_memory()
    left = syncbond.Replicator("left", syncbond.LWW_HLC, 1000)
    right = syncbond.Replicator("right", syncbond.LWW_HLC, 2000)

    left.put("old", b"v")
    left.delete("old")
    syncbond.sync_pair(left, pair.initiator, right, pair.responder)

    assert right.gc_tombstones(now_ms=2000, older_than_ms=5000) == 0


def test_invalidated_session_rejects_send():
    pair = syncbond.pair_memory()
    pair.initiator.invalidate()
    assert pair.initiator.invalidated
    with pytest.raises(syncbond.Error):
        pair.initiator.send(b"late")


def test_key_epoch_rotation_blocks_a_removed_device():
    pre_key = b"\x01" * 32
    next_key = b"\x02" * 32
    survivor = syncbond.Keyring("g", 2, next_key)
    removed = syncbond.Keyring("g", 1, pre_key)

    assert survivor.epoch == 2 and removed.epoch == 1

    envelope = survivor.seal("s1", b"payload after rotation")
    assert survivor.open(envelope) == b"payload after rotation"

    with pytest.raises(syncbond.Error):
        removed.open(envelope)
    assert syncbond.last_error_code() == -5  # SB_ERR_KEY_EPOCH_MISMATCH


def test_removed_device_keeps_pre_rotation_access():
    pre_key = b"\x01" * 32
    survivor = syncbond.Keyring("g", 1, pre_key)
    removed = syncbond.Keyring("g", 1, pre_key)

    envelope = survivor.seal("s1", b"before rotation")
    assert removed.open(envelope) == b"before rotation"


def test_envelope_replay_is_rejected():
    key = b"\x03" * 32
    ring = syncbond.Keyring("g", 1, key)
    envelope = ring.seal("s1", b"once")

    assert ring.open(envelope) == b"once"
    with pytest.raises(syncbond.Error):
        ring.open(envelope)
    assert syncbond.last_error_code() == -6  # SB_ERR_REPLAY


def test_conformance_runner_report_is_ok():
    report = json.loads(syncbond.conformance_run(FIXTURE))
    assert report["version"] == 1
    assert report["ok"] is True
    assert {scenario["type"] for scenario in report["scenarios"]} == {
        "replication",
        "key_epoch",
    }


def test_conformance_rotation_check_reports_the_rejected_device():
    report = json.loads(syncbond.conformance_run(FIXTURE))
    rotation = next(
        scenario
        for scenario in report["scenarios"]
        if scenario["type"] == "key_epoch"
    )
    check = next(
        row
        for row in rotation["checks"]
        if row["name"] == "removed_device_cannot_open_envelope_sealed_after_rotation"
    )
    assert check["ok"] is True
    assert check["actual"] == [False]
    rejected = next(
        row for row in rotation["rotations"] if row["device"] == "gone"
    )
    assert rejected["rotated_error"] == -5


def test_conformance_named_checks_all_pass():
    report = json.loads(syncbond.conformance_run(FIXTURE))
    assert report["ok"] is True
    by_name = {scenario["name"]: scenario for scenario in report["scenarios"]}
    assert set(by_name) == {
        "merge_lww",
        "tombstone_gc_blocks_resurrection",
        "malformed_strategy_payload_is_rejected",
        "malformed_pn_counter_payload_is_rejected",
        "rotation",
    }
    assert {c["name"] for c in by_name["merge_lww"]["checks"]} == {
        "left_sees_newer_write",
        "right_keeps_newer_write",
    }
    assert {c["name"] for c in by_name["tombstone_gc_blocks_resurrection"]["checks"]} == {
        "old_write_cannot_resurrect_after_gc",
        "barrier_keeps_tombstone",
        "peer_stays_tombstoned",
    }
    malformed = by_name["malformed_strategy_payload_is_rejected"]
    assert malformed["checks"][0] == {
        "actual": "true",
        "expected": "true",
        "name": "malformed_or_set_payload_rejected",
        "ok": True,
        "reason": "explicit error",
    }
    pn = by_name["malformed_pn_counter_payload_is_rejected"]
    assert pn["checks"][0]["name"] == "malformed_pn_counter_payload_rejected"
    assert pn["checks"][0]["actual"] == "true"
    for scenario in report["scenarios"]:
        assert scenario["ok"] is True
        for check in scenario["checks"]:
            assert check["ok"] is True


def test_conformance_report_matches_canonical_bytes():
    # The runner output is deterministic: byte-for-byte equality against the
    # canonical report pins any language drift (mangled fixture or report).
    report = syncbond.conformance_run(FIXTURE)
    expected = EXPECTED_PATH.read_text(encoding="utf-8")
    assert report == expected, "conformance report must match the canonical bytes"


def test_abi_constants_are_exported():
    assert syncbond.LWW_HLC == 0
    assert syncbond.OR_SET == 1
    assert syncbond.PN_COUNTER == 2
    assert syncbond.err_none() == 0
