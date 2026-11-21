# syncbond (Python)

Python bindings for [syncbond](../../README.md) — accountless, embeddable,
end-to-end encrypted device pairing and data synchronization.

The bindings are a thin layer over the shared `syncbond-ffi` handle API: they
serialize, manage resources, and forward to the core. No protocol logic lives
here, so merge semantics, key epoch rotation and tombstone GC behave
identically to every other language.

```python
import syncbond

pair = syncbond.pair_memory()            # code printed for both devices
left = syncbond.Replicator("left")
right = syncbond.Replicator("right")
left.put("greeting", b"hello")
syncbond.sync_pair(left, pair.initiator, right, pair.responder)
assert right.get("greeting") == b"hello"
```

`syncbond.sync_pair` runs the blocking responder half on a worker thread while
the caller drives the initiator; the GIL is released for the exchange, and the
two halves use distinct handles.

A device is removed from a group by key epoch rotation: the removed device
keeps the previous key and cannot open envelopes sealed under the new epoch.

```python
ring = syncbond.Keyring("g")
epoch, key = ring.rotate()               # hand `key` to the survivors
envelope = ring.seal("device-1", b"secret")
ring.open(envelope)                      # -> b"secret"
```

## Relay sync

`syncbond.RelayDriver` owns one device's session against a relay channel and
syncs it in the background: the driver runs its own worker thread, so the host
only writes, reads, starts and stops, and the blocking calls release the GIL
(`write`, `delete`, `get`, `export_state`, `stop`) — network waits never block
other Python threads. Two devices that import the same group key converge
through the relay; an exported state snapshot resumes a device exactly where
it left off.

```python
driver = syncbond.RelayDriver(
    relay_url, channel_id, channel_token,
    server_id="relay-1", cursor_channel="ch", group_id="group-1",
    key_epoch=1, group_key=key, node_id="device-a",
    timeout_ms=5000, tls_mode=syncbond.TLS_VALIDATE,
)
driver.config(page_limit=32, max_pages_per_cycle=16,
              initial_backoff_ms=500, max_backoff_ms=2000,
              max_attempts=8, idle_interval_ms=1000)
driver.start()
driver.write("greeting", b"hello")
state = driver.export_state()            # snapshot for a later resume
driver.stop()                            # idempotent; joins the worker
assert driver.stop_reason == syncbond.DRIVER_STOP_CANCELLED
```

## Install

```sh
maturin build -m crates/syncbond-python
pip install target/wheels/syncbond-*.whl
```

The module is built with the stable ABI (`abi3-py39`), so one wheel covers
Python 3.9 and later and no per-interpreter rebuild is needed.

## Tests

```sh
pytest crates/syncbond-python/tests
```

`fixtures/consistency` plus `syncbond.conformance_run` give the byte-for-byte
cross-language checks; every binding drives the same fixture through the same
runner.
