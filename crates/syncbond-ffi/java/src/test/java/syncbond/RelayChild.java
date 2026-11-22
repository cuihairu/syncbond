package syncbond;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Relay driver child process (todo.md DSR-40): one JVM runs one device against
 * a relay channel and reports how the run went. The parent test spawns two of
 * these (the "two JVM processes" of the acceptance) and a second pair after a
 * restart, so recovery from exported state is exercised through real child
 * processes, not one process juggling two devices.
 *
 * <p>Usage: {@code java -cp build/classes/java/test:build/classes/java/main
 * syncbond.RelayChild} with the config in system properties (see
 * {@link RelaySyncTest} for the keys): {@code sb.phase}, {@code sb.relayUrl},
 * {@code sb.channelId}, {@code sb.token}, {@code sb.groupKeyB64},
 * {@code sb.node}, {@code sb.stateB64}, {@code sb.writes}, {@code sb.expect},
 * {@code sb.expectBeforeStart} and {@code sb.waitMs}. The child asserts its
 * own invariants and exits non-zero on failure; the parent checks the exit
 * code and the reported lines. The test sources carry no JSON dependency, so
 * the config crosses the process boundary as system properties and the report
 * leaves as one {@code KEY=VALUE} line per result on standard output.
 *
 * <p>A 1ms ticker thread runs for the whole sync wait: the native driver does
 * its blocking work on its own worker thread, so the JVM must keep scheduling
 * a concurrent thread the whole time (the acceptance "blocking work does not
 * occupy the process").
 */
public final class RelayChild {
    private RelayChild() {}

    /** One key/value pair of a {@code a=b,c=d} list property. */
    private static final class Pair {
        final String key;
        final String value;

        Pair(String key, String value) {
            this.key = key;
            this.value = value;
        }
    }

    public static void main(String[] args) {
        String phase = System.getProperty("sb.phase", "live");
        List<Pair> writes = pairs(System.getProperty("sb.writes", ""));
        List<Pair> expect = pairs(System.getProperty("sb.expect", ""));
        List<Pair> expectBeforeStart = pairs(System.getProperty("sb.expectBeforeStart", ""));
        long waitMs = Long.parseLong(System.getProperty("sb.waitMs", "15000"));
        byte[] groupKey = Base64.getDecoder().decode(System.getProperty("sb.groupKeyB64", ""));
        byte[] state = state();

        try (RelayDriver driver = open(phase, groupKey, state)) {
            // A restored device must already hold what it committed before
            // the restart.
            for (Pair pair : expectBeforeStart) {
                String got = value(driver, pair.key);
                if (!pair.value.equals(got)) {
                    fail(phase, "restored state lost " + pair.key
                            + ": got " + got + ", want " + pair.value);
                }
            }

            driver.config(2, 8, 1, 2, 1000, 1);

            // The responsiveness probe: if the native driver's blocking
            // calls stopped the JVM (a held lock, a stop-the-world), this
            // ticker would stall while they run. What matters is the longest
            // gap between fires.
            Probes probes = new Probes();
            probes.start();

            driver.start();
            for (Pair pair : writes) {
                driver.write(pair.key, pair.value.getBytes(StandardCharsets.UTF_8));
            }

            long deadline = System.currentTimeMillis() + waitMs;
            boolean converged = false;
            while (System.currentTimeMillis() < deadline) {
                boolean all = true;
                for (Pair pair : expect) {
                    if (driver.get(pair.key) == null) {
                        all = false;
                        break;
                    }
                }
                if (all) {
                    converged = true;
                    break;
                }
                sleep(5);
            }
            long[] gaps = probes.stop();
            long mainGapMs = gaps[0];
            long referenceGapMs = gaps[1];

            // Every write must reach the relay before this device may report
            // success, or a peer can wait forever: a device converges on its
            // own staged write (it is visible locally) before the worker
            // ships it, so `sentBatches > 0` alone would let b/1 look
            // delivered while it sits unsent in the outbox. Each write seals
            // exactly one envelope, so the relay must ack one per write. The
            // C++ child guards the same way (relay_child.cpp).
            long expected = writes.size();
            long pushDeadline = System.currentTimeMillis() + 5000;
            while (driver.progress().sentEnvelopes < expected
                    && System.currentTimeMillis() < pushDeadline) {
                sleep(2);
            }
            if (driver.progress().sentEnvelopes < expected) {
                fail(phase, "only " + driver.progress().sentEnvelopes + " of " + expected
                        + " write envelopes reached the relay");
            }

            StringBuilder got = new StringBuilder();
            for (Pair pair : expect) {
                String value = value(driver, pair.key);
                if (!pair.value.equals(value)) {
                    fail(phase, "expected " + pair.key + "=" + pair.value + ", got " + value);
                }
                got.append("got.").append(pair.key).append('=').append(value).append('\n');
            }
            if (!converged) {
                fail(phase, "did not converge on " + expect.get(0).key);
            }

            // The relative stall: the ticker's gap minus the reference
            // thread's own gap. OS starvation drives both up together so a
            // loaded box does not trip the probe; a JVM blocked inside a
            // native call leaves the reference ticking, so the relative one
            // is the block.
            long stallMs = Math.max(0, mainGapMs - referenceGapMs);
            if (stallMs >= 250) {
                fail(phase, "the JVM stalled " + stallMs + "ms during the sync "
                        + "(reference " + referenceGapMs + "ms)");
            }

            // Cancel the loop and join the worker before reading the
            // outcome, so the stop reason is the deterministic "cancelled"
            // (1) a clean host stop yields.
            driver.stop();
            if (driver.running()) {
                fail(phase, "driver still running after a clean stop");
            }
            if (driver.stopReason() != RelayDriver.DRIVER_STOP_CANCELLED) {
                fail(phase, "stop reason is " + driver.stopReason() + ", want 1 (cancelled)");
            }
            if (driver.error() != null) {
                fail(phase, "clean stop must have no error, got " + driver.error());
            }
            RelayDriver.Progress progress = driver.progress();
            String stateB64 = Base64.getEncoder().encodeToString(driver.exportState());
            got.append("stateB64=").append(stateB64).append('\n');

            System.out.println("phase=" + phase);
            System.out.println("node=" + System.getProperty("sb.node"));
            System.out.println("maxStallMs=" + stallMs);
            System.out.println("referenceGapMs=" + referenceGapMs);
            System.out.println("converged=" + converged);
            System.out.println("progressRunning=" + (progress.running ? 1 : 0));
            System.out.println("progressCycles=" + progress.cycles);
            System.out.println("progressSentBatches=" + progress.sentBatches);
            System.out.println("progressSentEnvelopes=" + progress.sentEnvelopes);
            System.out.println("progressPagesPulled=" + progress.pagesPulled);
            System.out.println("progressApplied=" + progress.applied);
            System.out.println("stopReason=" + driver.stopReason());
            String error = driver.error();
            System.out.println("error=" + (error == null ? "" : error));
            System.out.print(got);
        }
    }

    /** One device per child; the four native handles are built by the wrapper. */
    private static RelayDriver open(String phase, byte[] groupKey, byte[] state) {
        try {
            RelayDriver.Config config = new RelayDriver.Config();
            config.relayUrl = System.getProperty("sb.relayUrl");
            config.channelId = System.getProperty("sb.channelId");
            config.channelToken = System.getProperty("sb.token");
            config.serverId = "relay-1";
            config.cursorChannel = "ch";
            config.groupId = "group-1";
            config.keyEpoch = 1;
            config.groupKey = groupKey;
            config.nodeId = System.getProperty("sb.node");
            config.timeoutMs = 5000;
            config.tlsMode = RelayDriver.TLS_VALIDATE;
            config.state = state;
            return RelayDriver.open(config);
        } catch (RuntimeException error) {
            fail(phase, "open driver: " + error);
            throw error;
        }
    }

    private static String value(RelayDriver driver, String key) {
        byte[] data = driver.get(key);
        return data == null ? null : new String(data, StandardCharsets.UTF_8);
    }

    private static byte[] state() {
        String state = System.getProperty("sb.stateB64", "");
        return state.isEmpty() ? null : Base64.getDecoder().decode(state);
    }

    /** Parses {@code a=b,c=d}; a value may not itself contain {@code ,} or {@code =}. */
    private static List<Pair> pairs(String list) {
        List<Pair> out = new ArrayList<>();
        if (list.isEmpty()) {
            return out;
        }
        for (String item : list.split(",")) {
            int cut = item.indexOf('=');
            out.add(new Pair(item.substring(0, cut), item.substring(cut + 1)));
        }
        return out;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void fail(String phase, String message) {
        System.err.println("relay-child " + phase + ": " + message);
        System.exit(1);
    }

    /**
     * Two 1ms-loop threads on their own OS threads. The first watches the
     * JVM; the second is the reference clock that separates OS-level CPU
     * starvation (both stall together, a pass) from a JVM genuinely blocked in
     * a native call (the reference keeps ticking, a fail).
     */
    private static final class Probes {
        private static final long STEP_MS = 1;

        private final long[] first = new long[1];
        private final long[] second = new long[1];
        private Thread ticker;
        private Thread reference;
        private volatile boolean running;

        void start() {
            running = true;
            ticker = loop("ticker", first);
            reference = loop("reference", second);
        }

        private Thread loop(String name, long[] outMax) {
            Thread thread = new Thread(() -> {
                long last = System.currentTimeMillis();
                while (running) {
                    sleep(STEP_MS);
                    long now = System.currentTimeMillis();
                    if (now - last > outMax[0]) {
                        outMax[0] = now - last;
                    }
                    last = now;
                }
            }, name);
            thread.setDaemon(true);
            thread.start();
            return thread;
        }

        /** {@code {ticker max gap, reference max gap}} in milliseconds. */
        long[] stop() {
            running = false;
            try {
                ticker.join();
                reference.join();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return new long[] {first[0], second[0]};
        }
    }
}
