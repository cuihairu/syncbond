/* pair_sync.c - pure C consumer of the syncbond ABI.
 *
 * Complete flow: pair two devices, run a concurrent oplog sync between two
 * replicators, verify both sides converge to identical state, seal and open
 * an envelope after a key epoch rotation, and drive the cross-language
 * conformance runner. Build with the flags used by tests/ffi_c.rs:
 *   gcc -Wall -Werror -o pair_sync examples/pair_sync.c \
 *       -I include -L <libdir> -lsyncbond_ffi -Wl,-rpath,<libdir> -lpthread
 */

#include "syncbond.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void fail(const char *what)
{
    const char *error = sb_last_error();
    fprintf(stderr, "FAIL: %s%s%s\n", what, error && *error ? ": " : "", error && *error ? error : "");
    failures++;
}

static void expect(int condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

typedef struct {
    sb_replicator *replicator;
    sb_session *session;
    int send_first;
    int status;
    uint32_t sent_ops;
} sync_args;

static void *run_sync(void *raw)
{
    sync_args *args = raw;
    args->status = sb_replicator_sync(args->replicator, args->session, args->send_first, &args->sent_ops);
    return NULL;
}

static const char *FIXTURE =
    "{"
    "\"version\":1,"
    "\"scenarios\":["
    "{\"type\":\"replication\",\"name\":\"lww\",\"strategy\":\"lww\","
    "\"nodes\":{\"left\":1000,\"right\":2000},"
    "\"steps\":["
    "{\"put\":{\"node\":\"left\",\"key\":\"k\",\"payload\":\"bGVmdA\"}},"
    "{\"put\":{\"node\":\"right\",\"key\":\"k\",\"payload\":\"cmlnaHQ\",\"name\":\"left_sees_newer_write\"}},"
    "{\"sync\":[\"left\",\"right\"]},"
    "{\"check\":{\"node\":\"left\",\"key\":\"k\",\"state\":\"live\",\"payload\":\"cmlnaHQ\",\"name\":\"left_sees_newer_write\"}},"
    "{\"check\":{\"node\":\"right\",\"key\":\"k\",\"state\":\"live\",\"payload\":\"cmlnaHQ\",\"name\":\"right_keeps_newer_write\"}}"
    "]},"
    "{\"type\":\"key_epoch\",\"name\":\"rotation\",\"group\":\"g\",\"epoch\":1,\"next_epoch\":2,"
    "\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
    "\"next_key\":\"__________________________________________8\","
    "\"survivors\":[\"s1\"],\"removed\":[\"gone\"],"
    "\"plaintext\":\"cGF5bG9hZA\"}"
    "]}";

int main(void)
{
    expect(sb_abi_version() == SYNCBOND_ABI_VERSION, "abi version matches header");
    expect(sb_protocol_version() == 1, "protocol version is 1");

    /* Pair two freshly generated devices; both handshake sides run inside. */
    sb_pair_result *pair = sb_pair_memory(NULL);
    if (!pair) {
        fail("pair");
        return 1;
    }
    const char *code = sb_pair_result_code(pair);
    expect(code && strlen(code) == 6, "pairing code has six characters");
    sb_session *initiator = sb_pair_result_initiator(pair);
    sb_session *responder = sb_pair_result_responder(pair);
    sb_pair_result_free(pair);
    if (!initiator || !responder) {
        fail("extract sessions");
        return 1;
    }

    const char *group_a = sb_session_group_id(initiator);
    const char *group_b = sb_session_group_id(responder);
    expect(group_a && group_b && strcmp(group_a, group_b) == 0, "both sides derive the same group id");
    sb_free_string(group_a);
    sb_free_string(group_b);

    /* Deterministic replicators on both ends of the paired session. */
    sb_replicator *left = sb_replicator_new_fixed_clock("left", SB_STRATEGY_LWW_HLC, 1000);
    sb_replicator *right = sb_replicator_new_fixed_clock("right", SB_STRATEGY_LWW_HLC, 2000);
    if (!left || !right) {
        fail("replicator_new");
        return 1;
    }

    if (sb_replicator_put(left, "greeting", (const uint8_t *)"hello from c", 12) != SB_ERR_NONE)
        fail("put greeting");
    if (sb_replicator_put(right, "counter", (const uint8_t *)"42", 2) != SB_ERR_NONE)
        fail("put counter");
    if (sb_replicator_put(left, "doomed", (const uint8_t *)"x", 1) != SB_ERR_NONE)
        fail("put doomed");
    if (sb_replicator_delete(left, "doomed") != SB_ERR_NONE)
        fail("delete doomed");

    /* Full-duplex sync: the responder blocks on receive, so run it in a thread. */
    sync_args responder_args = { right, responder, 0, -1, 0 };
    pthread_t thread;
    if (pthread_create(&thread, NULL, run_sync, &responder_args) != 0) {
        fail("pthread_create");
        return 1;
    }
    uint32_t sent = 0;
    int status = sb_replicator_sync(left, initiator, 1, &sent);
    pthread_join(thread, NULL);
    expect(status == SB_ERR_NONE, "initiator sync succeeds");
    expect(responder_args.status == SB_ERR_NONE, "responder sync succeeds");
    expect(sent == 3 && responder_args.sent_ops == 1, "both sides sent their oplogs");

    /* Convergence: the canonical dumps of both sides must be identical. */
    sb_buffer_t greeting = { NULL, 0, 0 };
    if (sb_replicator_get(right, "greeting", &greeting) != SB_ERR_NONE)
        fail("get greeting on right");
    else {
        expect(greeting.len == 12 && memcmp(greeting.data, "hello from c", 12) == 0,
               "payload survived the sync");
        sb_free_buffer(&greeting);
    }
    if (sb_replicator_get(left, "counter", &greeting) != SB_ERR_NONE)
        fail("get counter on left");
    else {
        expect(greeting.len == 2 && memcmp(greeting.data, "42", 2) == 0, "counter arrived");
        sb_free_buffer(&greeting);
    }
    expect(sb_replicator_get(right, "doomed", &greeting) == SB_RESULT_ABSENT,
           "deleted key stays deleted after sync");

    const char *dump_left = sb_replicator_records_json(left);
    const char *dump_right = sb_replicator_records_json(right);
    expect(dump_left && dump_right && strcmp(dump_left, dump_right) == 0,
           "canonical dumps of both sides are identical");
    printf("converged state: %s\n", dump_left ? dump_left : "(null)");
    sb_free_string(dump_left);
    sb_free_string(dump_right);

    /* Session invalidation blocks further traffic. */
    expect(sb_session_invalidated(initiator) == 0, "session is live before invalidation");
    sb_session_invalidate(initiator);
    expect(sb_session_invalidated(initiator) == 1, "session reports invalidated");

    /* Key epoch rotation: seal under the new epoch, open with the same ring. */
    sb_keyring *ring = sb_keyring_new("group-a");
    uint64_t epoch = 0;
    uint8_t key[32];
    if (!ring) {
        fail("keyring_new");
        return 1;
    }
    if (sb_keyring_rotate(ring, &epoch, key) != SB_ERR_NONE)
        fail("keyring_rotate");
    else {
        const char *envelope = sb_keyring_seal_json(ring, "device-1", (const uint8_t *)"secret", 6);
        sb_buffer_t plain = { NULL, 0, 0 };
        if (sb_keyring_open_json(ring, envelope, &plain) != SB_ERR_NONE)
            fail("keyring_open_json");
        else {
            expect(plain.len == 6 && memcmp(plain.data, "secret", 6) == 0,
                   "sealed payload round trips");
            sb_free_buffer(&plain);
        }
        sb_free_string(envelope);
    }
    sb_keyring_free(ring);

    /* Cross-language conformance: same runner, same fixture, every language. */
    const char *report = sb_conformance_run(FIXTURE);
    if (!report) {
        fail("conformance run");
    } else {
        expect(strstr(report, "\"ok\":true") != NULL, "conformance report is ok");
        printf("conformance: %s\n", report);
        sb_free_string(report);
    }

    sb_replicator_free(left);
    sb_replicator_free(right);
    sb_session_free(initiator);
    sb_session_free(responder);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("pair_sync: all checks passed\n");
    return 0;
}
