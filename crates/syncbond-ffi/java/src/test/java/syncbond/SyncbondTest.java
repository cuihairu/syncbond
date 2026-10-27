package syncbond;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Mirrors the Go / Python suites over the same C ABI. */
final class SyncbondTest {
    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String text(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    // The canonical cross-language fixture, shared by every binding
    // (crates/syncbond-ffi/fixtures/conformance.json), read relative to this
    // module directory. The same on-disk file drives the merge /
    // tombstone-GC / key-epoch scenarios byte-identically across languages.
    private static final String FIXTURE = readFixture();

    private static String readFixture() {
        try {
            return Files.readString(Path.of("..", "fixtures", "conformance.json"));
        } catch (Exception error) {
            throw new IllegalStateException("read canonical conformance fixture", error);
        }
    }

    @Test
    void abiAndProtocolVersions() {
        assertEquals(1, Syncbond.abiVersion());
        assertEquals(1, Syncbond.protocolVersion());
    }

    @Test
    void identityRoundTrip() {
        Identity generated = Identity.generate();
        byte[] secret = generated.secretKey();
        assertEquals(64, secret.length);
        String deviceId = generated.deviceId();
        byte[] publicKey = generated.publicKey();
        assertEquals(32, publicKey.length);

        Identity rebuilt = Identity.importSecret(secret);
        assertEquals(deviceId, rebuilt.deviceId());
        assertArrayEquals(publicKey, rebuilt.publicKey());
        assertArrayEquals(secret, rebuilt.secretKey());

        generated.close();
        rebuilt.close();
    }

    @Test
    void pairProducesMatchingGroupIds() {
        try (PairResult pair = Syncbond.pairMemory(null)) {
            assertEquals(6, pair.code().length());
            assertEquals(pair.initiator().groupId(), pair.responder().groupId());
            assertNotNull(pair.initiator().peerDeviceId());
            assertFalse(pair.initiator().peerDeviceId().isEmpty());
            assertFalse(pair.initiator().invalidated());
            assertFalse(pair.responder().invalidated());
        }
    }

    @Test
    void replicatedPutConverges() {
        try (PairResult pair = Syncbond.pairMemory(null)) {
            try (Replicator left = new Replicator("left", Syncbond.STRATEGY_LWW_HLC, 1000);
                 Replicator right = new Replicator("right", Syncbond.STRATEGY_LWW_HLC, 2000)) {
                left.put("k", bytes("hello"));
                int[] sent = Replicator.syncPair(left, right, pair.initiator(), pair.responder());
                assertTrue(sent[0] >= 1, "initiator should send the op");
                assertArrayEquals(bytes("hello"), right.get("k"));
                assertEquals(left.recordsJson(), right.recordsJson(),
                        "both sides should converge to identical records");
            }
        }
    }

    @Test
    void deleteReplicates() {
        try (PairResult pair = Syncbond.pairMemory(null)) {
            try (Replicator left = new Replicator("left", Syncbond.STRATEGY_LWW_HLC, 1000);
                 Replicator right = new Replicator("right", Syncbond.STRATEGY_LWW_HLC, 2000)) {
                left.put("old", bytes("v"));
                left.delete("old");
                Replicator.syncPair(left, right, pair.initiator(), pair.responder());
                assertNull(right.get("old"), "a replicated delete must stay deleted");
                assertNull(left.get("old"));
                assertEquals(0, right.gcTombstones(3000, 5000),
                        "tombstones are not causally dominated yet");
            }
        }
    }

    @Test
    void laterWriteWins() {
        try (PairResult pair = Syncbond.pairMemory(null)) {
            try (Replicator left = new Replicator("left", Syncbond.STRATEGY_LWW_HLC, 1000);
                 Replicator right = new Replicator("right", Syncbond.STRATEGY_LWW_HLC, 2000)) {
                left.put("k", bytes("first"));
                right.put("k", bytes("second"));
                Replicator.syncPair(left, right, pair.initiator(), pair.responder());
                assertArrayEquals(bytes("second"), left.get("k"),
                        "the later wall-clock write wins on both sides");
                assertArrayEquals(bytes("second"), right.get("k"));
            }
        }
    }

    @Test
    void invalidatedSessionRejectsSend() {
        try (PairResult pair = Syncbond.pairMemory(null)) {
            pair.initiator().invalidate();
            assertTrue(pair.initiator().invalidated());
            assertThrows(SyncbondException.class, () -> pair.initiator().send(bytes("late")));
            assertTrue(Syncbond.lastErrorCode() != Syncbond.ERR_NONE);
        }
    }

    @Test
    void sessionSendRecv() {
        try (PairResult pair = Syncbond.pairMemory(null)) {
            pair.initiator().send(bytes("ping"));
            pair.responder().send(bytes("pong"));
            assertEquals("pong", text(pair.initiator().recv()));
            assertEquals("ping", text(pair.responder().recv()));
        }
    }

    @Test
    void keyEpochRotationBlocksRemovedDevice() {
        byte[] preKey = new byte[32];
        java.util.Arrays.fill(preKey, (byte) 1);
        byte[] nextKey = new byte[32];
        java.util.Arrays.fill(nextKey, (byte) 2);

        try (Keyring survivor = new Keyring("g", 2, nextKey);
             Keyring removed = new Keyring("g", 1, preKey)) {
            assertEquals(2, survivor.epoch());
            assertEquals(1, removed.epoch());

            String envelope = survivor.sealJson("s1", bytes("payload after rotation"));
            assertArrayEquals(bytes("payload after rotation"), survivor.openJson(envelope));

            assertThrows(SyncbondException.class, () -> removed.openJson(envelope));
            assertEquals(Syncbond.ERR_KEY_EPOCH_MISMATCH, Syncbond.lastErrorCode(),
                    "a removed device must be rejected with the key epoch code");
        }
    }

    @Test
    void envelopeReplayRejected() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 3);
        try (Keyring ring = new Keyring("g", 1, key)) {
            String envelope = ring.sealJson("s1", bytes("once"));
            assertArrayEquals(bytes("once"), ring.openJson(envelope));
            assertThrows(SyncbondException.class, () -> ring.openJson(envelope));
            assertEquals(Syncbond.ERR_REPLAY, Syncbond.lastErrorCode());
        }
    }

    @Test
    void conformanceReportOk() {
        String report = Syncbond.conformanceRun(FIXTURE);
        assertTrue(report.contains("\"ok\":true"), "conformance report must be ok: " + report);
        assertTrue(report.contains("\"type\":\"replication\""), report);
        assertTrue(report.contains("\"type\":\"key_epoch\""), report);
        for (String check : new String[] {
                "left_sees_newer_write",
                "old_write_cannot_resurrect_after_gc",
                "barrier_keeps_tombstone",
                "peer_stays_tombstoned",
                "removed_device_cannot_open_envelope_sealed_after_rotation",
        }) {
            assertTrue(report.contains("\"name\":\"" + check + "\""),
                    "conformance report must run check " + check + ": " + report);
        }
        // The runner output is deterministic: byte-for-byte equality against
        // the canonical report pins any language drift (mangled fixture or
        // report).
        assertEquals(readFile("..", "fixtures", "conformance.expected.json"), report,
                "conformance report must match the canonical bytes");
    }

    private static String readFile(String first, String... rest) {
        try {
            return Files.readString(Path.of(first, rest));
        } catch (Exception error) {
            throw new IllegalStateException("read fixture file", error);
        }
    }

    @Test
    void conformanceRotationCheckRejectedDevice() {
        String report = Syncbond.conformanceRun(FIXTURE);
        assertTrue(report.contains(
                        "\"name\":\"removed_device_cannot_open_envelope_sealed_after_rotation\""),
                report);
        assertTrue(report.contains("\"rotated_error\":-5"),
                "the removed device row must carry the key epoch mismatch code: " + report);
    }

    @Test
    void closedHandleThrows() {
        Identity identity = Identity.generate();
        identity.close();
        SyncbondException error =
                assertThrows(SyncbondException.class, identity::deviceId);
        assertEquals(Syncbond.ERR_INPUT, error.getCode());
    }
}
