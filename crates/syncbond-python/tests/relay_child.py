"""Relay driver child process (todo.md DSR-38): one Python process runs one
device against a relay channel and reports how the run went. The parent test
spawns two of these (the acceptance's "two Python processes") and a second
pair after a restart, so recovery from exported state is exercised through
real child processes. Usage:

    python relay_child.py <phase> <config.json> <out.json>

The child asserts its own invariants and exits non-zero on failure; the
parent checks the exit code and the reported output. A 1ms ticker thread runs
for the whole sync: a Python thread only makes progress while the native
driver calls release the GIL, so a long stall means the interpreter was
blocked (the acceptance "network waits release the GIL").
"""

import json
import sys
import threading
import time

import syncbond


def fail(message):
    print(f"relay-child {sys.argv[1]}: {message}", file=sys.stderr)
    sys.exit(1)


_, phase, config_path, out_path = sys.argv
with open(config_path, encoding="utf-8") as handle:
    config = json.load(handle)

group_key = bytes.fromhex(config["groupKeyHex"])
state = bytes.fromhex(config["stateHex"]) if config.get("stateHex") else None

driver = syncbond.RelayDriver(
    config["relayUrl"],
    config["channelId"],
    config["token"],
    "relay-1",
    "ch",
    "group-1",
    1,
    group_key,
    config["node"],
    5000,
    0,
    None,
    state,
)


def value(key):
    payload = driver.get(key)
    return None if payload is None else payload.decode("utf-8")


# A restored device must already hold what it committed before the restart.
for key, expected in config.get("expectBeforeStart", []):
    got = value(key)
    if got != expected:
        fail(f"restored state lost {key}: got {got!r}, want {expected!r}")

driver.config(2, 8, 1, 2, 1000, 1)

# The responsiveness probe: a Python thread only runs while the native driver
# calls release the GIL, so the longest gap between ticks is the longest any
# one call held the interpreter. Node coalesces short timers; Python does not,
# so a 1ms sleep ticks at ~1ms whenever the GIL is free.
ticks = [0]
last = [time.monotonic()]
max_stall = [0.0]
stop_flag = [False]


def ticker():
    while not stop_flag[0]:
        time.sleep(0.001)
        now = time.monotonic()
        max_stall[0] = max(max_stall[0], now - last[0])
        last[0] = now
        ticks[0] += 1


threading.Thread(target=ticker, daemon=True).start()

driver.start()
for key, payload in config["writes"]:
    driver.write(key, payload.encode("utf-8"))

# Every write must reach the relay before this device may report success,
# or a peer can wait forever: a device converges on its own staged write
# (it is visible locally) before the worker ships it, so `sent_batches > 0`
# alone would let b/1 look delivered while it sits unsent in the outbox.
# Each write seals exactly one envelope, so the relay must ack one per write.
expected_envelopes = len(config["writes"])
send_deadline = time.monotonic() + 5
while (driver.progress().sent_envelopes < expected_envelopes
       and time.monotonic() < send_deadline):
    time.sleep(0.005)
if driver.progress().sent_envelopes < expected_envelopes:
    fail(
        f"only {driver.progress().sent_envelopes} of {expected_envelopes} "
        f"write envelopes reached the relay"
    )

deadline = time.monotonic() + config.get("waitMs", 15000) / 1000.0
converged = False
while time.monotonic() < deadline:
    if all(value(key) is not None for key, _ in config["expect"]):
        converged = True
        break
    time.sleep(0.005)

got = {key: value(key) for key, _ in config["expect"]}
for key, expected in config["expect"]:
    if got[key] != expected:
        fail(f"expected {key}={expected}, got {got[key]!r}")
if not converged:
    fail(f"did not converge on {', '.join(key for key, _ in config['expect'])}")

driver.stop()
stop_flag[0] = True

if driver.running:
    fail("driver still running after a clean stop")
if driver.stop_reason != 1:
    fail(f"stop reason is {driver.stop_reason}, want 1 (cancelled)")
if driver.error is not None:
    fail(f"clean stop must have no error, got {driver.error!r}")
if max_stall[0] >= 0.25:
    fail(f"the interpreter stalled {max_stall[0] * 1000:.0f}ms during the run")

progress = driver.progress()
state_blob = driver.export_state()
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "phase": phase,
            "node": config["node"],
            "maxStallMs": round(max_stall[0] * 1000, 1),
            "converged": converged,
            "progress": {
                "running": progress.running,
                "cycles": progress.cycles,
                "sentBatches": progress.sent_batches,
                "sentEnvelopes": progress.sent_envelopes,
                "pagesPulled": progress.pages_pulled,
                "applied": progress.applied,
            },
            "stopReason": driver.stop_reason,
            "error": driver.error,
            "got": got,
            "stateHex": state_blob.hex(),
        },
        handle,
    )
