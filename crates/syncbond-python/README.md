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
