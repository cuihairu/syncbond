import java.nio.charset.StandardCharsets;
import syncbond.PairResult;
import syncbond.Replicator;
import syncbond.Syncbond;

/**
 * Pairs two replicators over an in-memory loopback and converges one op.
 *
 * Run from the java/ directory after {@code gradle classes}:
 * <pre>
 *   javac -cp build/classes/java/main -d build/classes/java/example examples/PairSync.java
 *   java -Dsyncbond.lib=build/libs/libsyncbond_java.so \
 *        -cp build/classes/java/main:build/classes/java/example PairSync
 * </pre>
 */
public final class PairSync {
    public static void main(String[] args) throws Exception {
        byte[] payload = "hello from java".getBytes(StandardCharsets.UTF_8);
        try (PairResult pair = Syncbond.pairMemory(null)) {
            System.out.println("pairing code: " + pair.code());
            try (Replicator left = new Replicator("left", Syncbond.STRATEGY_LWW_HLC, 1000);
                 Replicator right = new Replicator("right", Syncbond.STRATEGY_LWW_HLC, 2000)) {
                left.put("greeting", payload);
                int[] sent = Replicator.syncPair(left, right, pair.initiator(), pair.responder());
                byte[] got = right.get("greeting");
                boolean ok = sent[0] >= 1 && java.util.Arrays.equals(payload, got);
                System.out.println("right sees: " + new String(got, StandardCharsets.UTF_8));
                System.out.println(ok ? "pair_sync: all checks passed" : "pair_sync: FAILED");
                if (!ok) {
                    System.exit(1);
                }
            }
        }
    }
}
