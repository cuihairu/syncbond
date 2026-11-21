# syncbond Java SDK (JNI)

A Java binding over the syncbond C ABI (`libsyncbond_ffi`). The JNI shim
(`native/syncbond_jni.c`) only converts JNI types and forwards to the C ABI;
no protocol logic lives in the binding. Failures surface as
`syncbond.SyncbondException` carrying the stable `SB_ERR_*` code from the
thread-local error slot.

## Requirements

- JDK 21+ (`javac`), `cc` (gcc), and the syncbond C ABI shared library built
  at `target/release/libsyncbond_ffi.so` (`cargo build --release -p
  syncbond-ffi`).

## Build and test

```sh
cargo build --release -p syncbond-ffi
gradle test
```

`gradle test` compiles the Java classes, runs `javac -h` to emit
`native/syncbond_Native.h`, builds `build/libs/libsyncbond_java.so` (linked
against the C ABI library copied beside it, with an `$ORIGIN` rpath), and
runs the JUnit suite (18 tests: versions, identity round-trip, pairing,
convergence, delete, LWW, session send/recv and invalidation, key-epoch
rotation, replay rejection, conformance report, closed-handle safety, the
relay driver lifecycle and the two-JVM relay e2e).

The suite mirrors the Go and Python suites so the same behaviors are
verified in every language.

## Example

```sh
javac -cp build/classes/java/main -d build/classes/java/example examples/PairSync.java
java -Dsyncbond.lib=build/libs/libsyncbond_java.so \
     -cp build/classes/java/main:build/classes/java/example PairSync
```

Prints `pair_sync: all checks passed`.

## Handle lifecycle

Every native handle is owned by a `NativeHandle` that has an explicit
`close()` and a `java.lang.ref.Cleaner` backstop. The cleaner action captures
only the free function, the raw handle and a local closed flag — never the
owner object — so an un-closed handle is released when the wrapper becomes
unreachable without retaining it. All public wrappers implement
`AutoCloseable` and should be closed in `try`-with-resources.

## Relay sync

`syncbond.RelayDriver` owns one device's session against a relay channel and
syncs it in the background: the driver runs its own worker thread, so the host
only writes, reads, starts and stops. Two devices that import the same group
key converge through the relay; an exported state snapshot resumes a device
exactly where it left off.

```java
RelayDriver.Config config = new RelayDriver.Config();
config.relayUrl = relayURL;
config.channelId = channelID;
config.channelToken = channelToken;
config.serverId = "relay-1";
config.cursorChannel = "ch";
config.groupId = "group-1";
config.keyEpoch = 1;
config.groupKey = groupKey;          // exactly 32 shared bytes
config.nodeId = "device-a";
config.timeoutMs = 5000;
config.tlsMode = RelayDriver.TLS_VALIDATE;

try (RelayDriver driver = RelayDriver.open(config)) {
    driver.config(32, 16, 500, 2000, 8, 1000); // page limit, pages, backoff, attempts, idle
    driver.start();
    driver.write("greeting", "hello".getBytes(StandardCharsets.UTF_8));

    byte[] state = driver.exportState(); // snapshot for a later resume
    driver.stop();                       // idempotent; joins the worker
    if (driver.stopReason() != RelayDriver.DRIVER_STOP_CANCELLED) {
        throw new IllegalStateException("unexpected stop reason");
    }
}
```

`driver.progress()` reports the worker's monotonic counters (`cycles`,
`sentBatches`, `sentEnvelopes`, `pagesPulled`, `applied`), `driver.error()`
the text that ended the loop, and `driver.exportState()` the snapshot a later
`RelayDriver.open` restores from (`config.state`). The four native handles
the driver needs (identity, keyring, replicator, receive state) are built
inside `RelayDriver.open` and their ownership transfers to the driver, so
none of them is a separate `AutoCloseable`.

The relay e2e (`RelaySyncTest.twoJvmProcessesSyncAndRecover`) needs
`SYNCBOND_TEST_RELAY` (an http relay URL) and `SYNCBOND_TEST_ADMIN` (its admin
token); without them it skips, so the suite above stays green standalone.

## Local publication

`gradle publishToMavenLocal` publishes the `io.github.syncbond:syncbond-java`
artifact to the local Maven repository so downstream builds can pull it.
This is a local-only build artifact; no remote repository or version tag is
involved.
