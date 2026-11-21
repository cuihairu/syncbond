"""Relay driver e2e (todo.md DSR-38): two Python processes sync through a real
relay channel and recover after a restart, and a blocking stop releases the
GIL. The Rust harness boots the relay in-process and exports
SYNCBOND_TEST_RELAY (http URL) and SYNCBOND_TEST_ADMIN (bearer token); without
those the two-process test skips so a bare pytest run stays green. The GIL
test needs no relay: a dead endpoint keeps the worker in a backoff wait, and
the ticker thread proves the interpreter is free while `stop()` joins it.
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

import syncbond

RELAY_URL = os.environ.get("SYNCBOND_TEST_RELAY")
ADMIN = os.environ.get("SYNCBOND_TEST_ADMIN")
CHILD = Path(__file__).with_name("relay_child.py")
# The same 32 bytes of 0x07 the other bindings' driver tests use: two devices
# in one group import the identical group key material.
GROUP_KEY_HEX = "07" * 32


def provision():
    def post(url, body, token):
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            assert response.status == 201, response.status
            return json.loads(response.read())

    channel = post(
        f"{RELAY_URL}/v1/channels",
        {"protocolVersion": 1, "requestId": "py-channel-1"},
        ADMIN,
    )
    assert channel["channelId"]

    def issue(label):
        credential = post(
            f"{RELAY_URL}/v1/channels/{channel['channelId']}/credentials",
            {
                "protocolVersion": 1,
                "requestId": f"py-cred-{label}",
                "scopes": ["append", "pull"],
                "label": label,
            },
            ADMIN,
        )
        assert credential["token"], credential
        return credential["token"]

    return channel["channelId"], issue("py-a"), issue("py-b")


def run_child(phase, config, tmp):
    config_path = os.path.join(tmp, f"{phase}-{config['node']}-config.json")
    out_path = os.path.join(tmp, f"{phase}-{config['node']}-out.json")
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle)
    proc = subprocess.run(
        [sys.executable, str(CHILD), phase, config_path, out_path],
        capture_output=True,
        text=True,
        env=os.environ,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"child {phase} {config['node']} exited {proc.returncode}: {proc.stderr}"
        )
    with open(out_path, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.mark.skipif(
    not RELAY_URL or not ADMIN,
    reason="SYNCBOND_TEST_RELAY/SYNCBOND_TEST_ADMIN not set (relay not booted)",
)
def test_two_python_processes_sync_and_recover(tmp_path):
    channel_id, token_a, token_b = provision()

    # Phase 1: two fresh devices write concurrently and converge both ways.
    # They must run at the same time: each waits on a key only the other writes.
    live = {}

    def run_one(node, token, writes):
        live[node] = run_child(
            "live",
            {
                "relayUrl": RELAY_URL,
                "channelId": channel_id,
                "token": token,
                "groupKeyHex": GROUP_KEY_HEX,
                "node": node,
                "writes": writes,
                "expect": [["a/0", "a0"], ["b/1", "b1"]],
                "waitMs": 15000,
            },
            str(tmp_path),
        )

    workers = [
        threading.Thread(target=run_one, args=("py-a", token_a, [["a/0", "a0"]])),
        threading.Thread(target=run_one, args=("py-b", token_b, [["b/0", "b0"], ["b/1", "b1"]])),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    live_a, live_b = live["py-a"], live["py-b"]

    # Phase 2, sequential restarts: B resumes from its snapshot and writes b/2
    # while A is already down (A's phase-1 child exited), then A resumes and
    # must pull what it missed while down.
    restarted_b = run_child(
        "restart",
        {
            "relayUrl": RELAY_URL,
            "channelId": channel_id,
            "token": token_b,
            "groupKeyHex": GROUP_KEY_HEX,
            "node": "py-b",
            "stateHex": live_b["stateHex"],
            "expectBeforeStart": [["b/0", "b0"], ["b/1", "b1"]],
            "writes": [["b/2", "b2"]],
            "expect": [["b/0", "b0"], ["b/1", "b1"], ["b/2", "b2"]],
            "waitMs": 15000,
        },
        str(tmp_path),
    )
    restarted_a = run_child(
        "restart",
        {
            "relayUrl": RELAY_URL,
            "channelId": channel_id,
            "token": token_a,
            "groupKeyHex": GROUP_KEY_HEX,
            "node": "py-a",
            "stateHex": live_a["stateHex"],
            "expectBeforeStart": [["a/0", "a0"]],
            "writes": [["a/1", "a1"]],
            "expect": [["a/0", "a0"], ["a/1", "a1"], ["b/1", "b1"], ["b/2", "b2"]],
            "waitMs": 15000,
        },
        str(tmp_path),
    )

    # `pulled` marks the devices that must have applied an op pulled from the
    # relay: a restarted device that only writes its own key has nothing to
    # pull and legitimately reports zero.
    for phase, run, pulled in [
        ("live-a", live_a, True),
        ("live-b", live_b, True),
        ("restart-b", restarted_b, False),
        ("restart-a", restarted_a, True),
    ]:
        assert run["stopReason"] == 1, f"{phase} must stop cancelled"
        assert run["error"] is None, f"{phase} must stop with no error"
        assert (
            run["maxStallMs"] < 250
        ), f"{phase} held the interpreter: {run['maxStallMs']}ms longest stall"
        if pulled:
            assert run["progress"]["applied"] > 0, f"{phase} must apply pulled ops"
        assert run["converged"], f"{phase} reported convergence"
    assert restarted_a["got"]["b/2"] == "b2", "A must catch what B wrote while A was down"


def test_relay_stop_releases_the_gil():
    # The worker sits in a backoff wait against a dead endpoint, so `stop()`
    # blocks for up to one cancel-poll window (25ms). A Python ticker thread
    # only makes progress while the GIL is free: if `stop()` held it, the
    # counter would not move during the call.
    driver = syncbond.RelayDriver(
        "http://127.0.0.1:1",
        "ch",
        "tok",
        "relay-1",
        "ch",
        "group-1",
        1,
        bytes.fromhex(GROUP_KEY_HEX),
        "gil-node",
        5000,
        0,
        None,
        None,
    )
    driver.config(2, 8, 500, 2000, 8, 500)
    driver.start()
    time.sleep(0.02)  # let the worker settle into its backoff wait

    ticks = [0]
    stop_flag = [False]

    def ticker():
        while not stop_flag[0]:
            time.sleep(0.001)
            ticks[0] += 1

    thread = threading.Thread(target=ticker, daemon=True)
    thread.start()
    time.sleep(0.02)
    before = ticks[0]

    driver.stop()
    stop_flag[0] = True
    thread.join(timeout=2)

    assert ticks[0] > before, f"the GIL was held across stop: {before} -> {ticks[0]}"
    assert driver.stop_reason == 1
    assert driver.error is None
