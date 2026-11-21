package syncbond;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** The JNI lifecycle over a dead endpoint, mirroring the Go / Python suites. */
final class RelayDriverTest {
    private static byte[] groupKey() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 7);
        return key;
    }

    private static String text(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    private static RelayDriver freshDriver(String url, String channel, String token, String node) {
        RelayDriver.Config config = new RelayDriver.Config();
        config.relayUrl = url;
        config.channelId = channel;
        config.channelToken = token;
        config.serverId = "relay-1";
        config.cursorChannel = "ch";
        config.groupId = "group-1";
        config.keyEpoch = 1;
        config.groupKey = groupKey();
        config.nodeId = node;
        config.timeoutMs = 5000;
        config.tlsMode = RelayDriver.TLS_VALIDATE;
        return RelayDriver.open(config);
    }

    private static void fastConfig(RelayDriver driver) {
        driver.config(2, 8, 1, 2, 1000, 1);
    }

    @Test
    void badArguments() {
        // A short group key is refused before any native call.
        RelayDriver.Config shortKey = new RelayDriver.Config();
        shortKey.relayUrl = "http://127.0.0.1:1";
        shortKey.channelId = "ch";
        shortKey.channelToken = "tok";
        shortKey.groupId = "g";
        shortKey.groupKey = new byte[] {1, 2, 3};
        shortKey.nodeId = "n";
        SyncbondException shortKeyError =
                assertThrows(SyncbondException.class, () -> RelayDriver.open(shortKey));
        assertEquals(Syncbond.ERR_INPUT, shortKeyError.getCode());

        // An unknown tls mode is refused by the handle layer.
        RelayDriver.Config badTls = new RelayDriver.Config();
        badTls.relayUrl = "http://127.0.0.1:1";
        badTls.channelId = "ch";
        badTls.channelToken = "tok";
        badTls.groupId = "g";
        badTls.groupKey = groupKey();
        badTls.nodeId = "n";
        badTls.tlsMode = 7;
        assertThrows(SyncbondException.class, () -> RelayDriver.open(badTls));

        // A zero timeout is refused too.
        RelayDriver.Config zeroTimeout = new RelayDriver.Config();
        zeroTimeout.relayUrl = "http://127.0.0.1:1";
        zeroTimeout.channelId = "ch";
        zeroTimeout.channelToken = "tok";
        zeroTimeout.groupId = "g";
        zeroTimeout.groupKey = groupKey();
        zeroTimeout.nodeId = "n";
        zeroTimeout.timeoutMs = 0;
        assertThrows(SyncbondException.class, () -> RelayDriver.open(zeroTimeout));
    }

    @Test
    void deadEndpointLifecycleAndState() {
        try (RelayDriver driver = freshDriver("http://127.0.0.1:1", "ch", "tok", "java-dead")) {
            fastConfig(driver);

            assertFalse(driver.running(), "not running yet");
            assertEquals(RelayDriver.DRIVER_STOP_NONE, driver.stopReason());
            assertNull(driver.error(), "no error text yet");
            assertFalse(driver.progress().running, "progress reports running before start");

            // Start spawns the worker, which retries the dead endpoint in a loop.
            driver.start();
            assertTrue(driver.running(), "the worker is up");
            assertTrue(driver.progress().running, "progress reports running");

            // The host writes and reads through the marshaling layer.
            driver.write("k", "v".getBytes(StandardCharsets.UTF_8));
            assertArrayEquals("v".getBytes(StandardCharsets.UTF_8), driver.get("k"));
            assertNull(driver.get("absent"), "an absent key is null (not an error)");

            // The committed state exports with the write intact.
            byte[] blob = driver.exportState();
            assertNotNull(blob);
            assertTrue(blob.length > 0, "the snapshot is not empty");

            // A delete stages a tombstone.
            driver.delete("k");
            assertNull(driver.get("k"), "the tombstone wins");

            // Stop cancels and joins; the reason is cancellation, not an error.
            driver.stop();
            assertFalse(driver.running(), "the worker joined");
            assertEquals(RelayDriver.DRIVER_STOP_CANCELLED, driver.stopReason());
            assertNull(driver.error(), "a clean stop has no error");
        }
    }

    @Test
    void restoreFromState() {
        byte[] blob;
        try (RelayDriver driver = freshDriver("http://127.0.0.1:1", "ch", "tok", "java-first")) {
            fastConfig(driver);
            driver.write("persist", "p".getBytes(StandardCharsets.UTF_8));
            blob = driver.exportState();
        }

        // A second driver rebuilt from the snapshot alone (a fresh node id,
        // which the state overrides) sees the committed write.
        RelayDriver.Config config = new RelayDriver.Config();
        config.relayUrl = "http://127.0.0.1:1";
        config.channelId = "ch";
        config.channelToken = "tok";
        config.serverId = "relay-1";
        config.cursorChannel = "ch";
        config.groupId = "group-1";
        config.keyEpoch = 1;
        config.groupKey = groupKey();
        config.nodeId = "different-node";
        config.timeoutMs = 5000;
        config.tlsMode = RelayDriver.TLS_VALIDATE;
        config.state = blob;
        try (RelayDriver restored = RelayDriver.open(config)) {
            assertEquals("p", text(restored.get("persist")));
        }
    }

    @Test
    void closeIsIdempotentAndStopsWorker() {
        // Double close is safe and a driver closed while running joins its
        // worker instead of leaking the thread.
        RelayDriver driver = freshDriver("http://127.0.0.1:1", "ch", "tok", "java-idle");
        fastConfig(driver);
        driver.start();
        driver.close();
        driver.close(); // idempotent

        // A started driver stopped once may start again after the stop.
        try (RelayDriver restarted = freshDriver("http://127.0.0.1:1", "ch", "tok", "java-restart")) {
            fastConfig(restarted);
            restarted.start();
            restarted.stop();
            restarted.start();
            restarted.stop();
        }
    }
}
