package syncbond;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Relay driver e2e (todo.md DSR-40): two JVM processes sync through a real
 * relay channel and recover after a restart. The Rust harness boots the relay
 * in-process and exports {@code SYNCBOND_TEST_RELAY} (http URL) and
 * {@code SYNCBOND_TEST_ADMIN} (bearer token); without those the test skips so
 * a plain {@code gradle test} stays green. Each device runs in its own child
 * JVM (the acceptance's "two JVM processes") and asserts process
 * responsiveness and a clean stop itself.
 */
final class RelaySyncTest {
    /** The same 32 bytes of 0x07 the other bindings' driver tests use. */
    private static final byte[] GROUP_KEY = groupKey();
    private static final String GROUP_KEY_B64 = Base64.getEncoder().encodeToString(GROUP_KEY);

    private static byte[] groupKey() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 7);
        return key;
    }

    private static String relayUrl() {
        return System.getenv("SYNCBOND_TEST_RELAY");
    }

    private static String admin() {
        return System.getenv("SYNCBOND_TEST_ADMIN");
    }

    private static Map<String, Object> post(HttpClient client, String url, String token,
                                            String path, Map<String, Object> body)
            throws IOException, InterruptedException {
        String payload = json(body);
        HttpRequest request = HttpRequest.newBuilder(URI.create(url + path))
                .header("content-type", "application/json")
                .header("authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();
        HttpResponse<String> response = client.send(request,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, response.statusCode(), "POST " + path + ": " + response.body());
        return parseJson(response.body());
    }

    /** Minimal JSON encoding for the flat admin bodies (no escaping needed here). */
    private static String json(Map<String, Object> body) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : body.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append('"').append(entry.getKey()).append("\":");
            Object value = entry.getValue();
            if (value instanceof String) {
                out.append('"').append(value).append('"');
            } else if (value instanceof List<?>) {
                out.append('[');
                boolean inner = true;
                for (Object item : (List<?>) value) {
                    if (!inner) {
                        out.append(',');
                    }
                    inner = false;
                    out.append('"').append(item).append('"');
                }
                out.append(']');
            } else {
                out.append(value);
            }
        }
        return out.append('}').toString();
    }

    /** Minimal JSON decode for the flat admin responses ({@code {"channelId": "..."}}). */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseJson(String text) {
        Map<String, Object> out = new HashMap<>();
        String trimmed = text.trim();
        int start = trimmed.indexOf('{') + 1;
        int end = trimmed.lastIndexOf('}');
        if (start <= 0 || end < start) {
            return out;
        }
        for (String field : trimmed.substring(start, end).split(",")) {
            int colon = field.indexOf(':');
            if (colon < 0) {
                continue;
            }
            String key = field.substring(0, colon).replace("\"", "").trim();
            String value = field.substring(colon + 1).replace("\"", "").trim();
            out.put(key, value);
        }
        return out;
    }

    private static String childJava() {
        return Path.of(System.getProperty("java.home"), "bin", "java").toString();
    }

    private static Path moduleDir() {
        return Path.of("").toAbsolutePath();
    }

    private static String childClasspath() {
        Path module = moduleDir();
        return module.resolve("build/classes/java/test") + java.io.File.pathSeparator
                + module.resolve("build/classes/java/main");
    }

    /** One {@code syncbond.RelayChild} process; returns its report as key/value lines. */
    private static Map<String, String> runChild(String phase, String node, Map<String, String> config)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(childJava());
        command.add("-Dsyncbond.lib=" + moduleDir().resolve("build/libs/libsyncbond_java.so"));
        command.add("-Dsb.phase=" + phase);
        for (Map.Entry<String, String> entry : config.entrySet()) {
            command.add("-Dsb." + entry.getKey() + "=" + entry.getValue());
        }
        // -D options must precede the main class; after it they are program
        // arguments and the child would read empty system properties.
        command.add("-cp");
        command.add(childClasspath());
        command.add("syncbond.RelayChild");
        Process process = new ProcessBuilder(command)
                .directory(moduleDir().toFile())
                .start();
        StringBuilder stderr = new StringBuilder();
        Thread drain = new Thread(() -> readAll(process.getErrorStream(), stderr));
        drain.setDaemon(true);
        drain.start();
        StringBuilder stdout = new StringBuilder();
        readAll(process.getInputStream(), stdout);
        int exit = process.waitFor();
        drain.join(2000);
        if (exit != 0) {
            throw new AssertionError("child " + phase + " " + node + " exited " + exit
                    + ": " + stderr);
        }
        Map<String, String> report = new HashMap<>();
        for (String line : stdout.toString().split("\n")) {
            int cut = line.indexOf('=');
            if (cut > 0) {
                report.put(line.substring(0, cut), line.substring(cut + 1));
            }
        }
        return report;
    }

    private static void readAll(InputStream stream, StringBuilder into) {
        try (BufferedReader reader =
                     new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                into.append(line).append('\n');
            }
        } catch (IOException error) {
            // Best effort; the report is on stdout, this is diagnostics.
        }
    }

    private static void assertChildOK(String phase, Map<String, String> run, boolean pulled) {
        assertEquals("1", run.get("stopReason"), phase + " must stop cancelled");
        String error = run.get("error");
        assertNull(error == null || error.isEmpty() ? null : error,
                phase + " must stop with no error");
        long stall = Long.parseLong(run.get("maxStallMs"));
        assertTrue(stall < 250, phase + " stalled " + stall + "ms (>= 250ms)");
        assertEquals("true", run.get("converged"), phase + " reported convergence");
        if (pulled) {
            long applied = Long.parseLong(run.get("progressApplied"));
            assertTrue(applied > 0, phase + " must apply pulled ops");
        }
    }

    @Test
    void twoJvmProcessesSyncAndRecover() throws Exception {
        String relayUrl = relayUrl();
        String admin = admin();
        Assumptions.assumeTrue(relayUrl != null && !relayUrl.isEmpty() && admin != null
                && !admin.isEmpty(),
                "SYNCBOND_TEST_RELAY / SYNCBOND_TEST_ADMIN not set; skipping relay e2e");

        HttpClient client = HttpClient.newHttpClient();
        Map<String, Object> channel = post(client, relayUrl, admin, "/v1/channels",
                Map.of("protocolVersion", 1, "requestId", "java-channel-1"));
        String channelId = (String) channel.get("channelId");
        assertTrue(channelId != null && !channelId.isEmpty(), "channel: " + channel);
        String tokenA = issueCredential(client, relayUrl, admin, channelId, "java-a");
        String tokenB = issueCredential(client, relayUrl, admin, channelId, "java-b");

        // Phase 1: two fresh devices write concurrently and converge both ways.
        // They must run at the same time: each waits on a key only the other
        // writes, so running them sequentially would deadlock. A pool future
        // surfaces any child failure instead of swallowing it.
        String expect = "a/0=a0,b/1=b1";
        Map<String, String> configA = baseConfig(relayUrl, channelId, tokenA, "java-a");
        configA.put("writes", "a/0=a0");
        configA.put("expect", expect);
        Map<String, String> configB = baseConfig(relayUrl, channelId, tokenB, "java-b");
        configB.put("writes", "b/0=b0,b/1=b1");
        configB.put("expect", expect);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        Map<String, String> liveA;
        Map<String, String> liveB;
        try {
            Future<Map<String, String>> futureA =
                    pool.submit(() -> runChild("live", "java-a", configA));
            Future<Map<String, String>> futureB =
                    pool.submit(() -> runChild("live", "java-b", configB));
            liveA = futureA.get(90, TimeUnit.SECONDS);
            liveB = futureB.get(90, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        // Phase 2, sequential restarts: B resumes from its snapshot and writes
        // b/2 while A is already down (A's phase-1 child exited), then A
        // resumes and must pull what it missed while down. The restored state
        // of each device is verified by the child before it starts the worker.
        Map<String, String> restartB = baseConfig(relayUrl, channelId, tokenB, "java-b");
        restartB.put("stateB64", liveB.get("stateB64"));
        restartB.put("expectBeforeStart", "b/0=b0,b/1=b1");
        restartB.put("writes", "b/2=b2");
        restartB.put("expect", "b/0=b0,b/1=b1,b/2=b2");
        Map<String, String> restartedB = runChild("restart", "java-b", restartB);

        Map<String, String> restartA = baseConfig(relayUrl, channelId, tokenA, "java-a");
        restartA.put("stateB64", liveA.get("stateB64"));
        restartA.put("expectBeforeStart", "a/0=a0");
        restartA.put("writes", "a/1=a1");
        restartA.put("expect", "a/0=a0,a/1=a1,b/1=b1,b/2=b2");
        Map<String, String> restartedA = runChild("restart", "java-a", restartA);

        // `pulled` marks the devices that must have applied an op pulled from
        // the relay: a restarted device that only writes its own key has
        // nothing to pull and legitimately reports zero.
        assertChildOK("live-a", liveA, true);
        assertChildOK("live-b", liveB, true);
        assertChildOK("restart-b", restartedB, false);
        assertChildOK("restart-a", restartedA, true);
        assertEquals("b2", restartedA.get("got.b/2"),
                "A must catch what B wrote while A was down");
    }

    private static Map<String, String> baseConfig(String relayUrl, String channelId,
                                                  String token, String node) {
        Map<String, String> config = new HashMap<>();
        config.put("relayUrl", relayUrl);
        config.put("channelId", channelId);
        config.put("token", token);
        config.put("groupKeyB64", GROUP_KEY_B64);
        config.put("node", node);
        config.put("waitMs", "15000");
        return config;
    }

    private static String issueCredential(HttpClient client, String relayUrl, String admin,
                                          String channelId, String label)
            throws IOException, InterruptedException {
        Map<String, Object> credential = post(client, relayUrl, admin,
                "/v1/channels/" + channelId + "/credentials",
                Map.of("protocolVersion", 1, "requestId", "java-cred-" + label,
                        "scopes", List.of("append", "pull"), "label", label));
        String token = (String) credential.get("token");
        assertTrue(token != null && !token.isEmpty(), "credential " + label + ": " + credential);
        return token;
    }

}
