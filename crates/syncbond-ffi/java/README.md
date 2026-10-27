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
runs the JUnit suite (13 tests: versions, identity round-trip, pairing,
convergence, delete, LWW, session send/recv and invalidation, key-epoch
rotation, replay rejection, conformance report, closed-handle safety).

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

## Local publication

`gradle publishToMavenLocal` publishes the `io.github.syncbond:syncbond-java`
artifact to the local Maven repository so downstream builds can pull it.
This is a local-only build artifact; no remote repository or version tag is
involved.
