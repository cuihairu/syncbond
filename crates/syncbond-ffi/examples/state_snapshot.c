/* state_snapshot.c - pure C consumer of the state snapshot interface
 * (todo.md DSR-35).
 *
 * One versioned blob moves a device's committed replication state together
 * with its receive cursors: a restart replays exactly what was committed and
 * never re-pulls what it already saw. Build with the flags used by
 * tests/ffi_c.rs:
 *   gcc -Wall -Werror -o state_snapshot examples/state_snapshot.c \
 *       -I include -L <libdir> -lsyncbond_ffi -Wl,-rpath,<libdir> -lpthread
 */

#include "syncbond.h"

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

static int same_text(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

static int bytes_contains(const uint8_t *haystack, size_t hay_len,
                          const char *needle, size_t needle_len)
{
    if (needle_len == 0 || needle_len > hay_len) {
        return 0;
    }
    for (size_t start = 0; start + needle_len <= hay_len; start++) {
        if (memcmp(haystack + start, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* One remote operation, handed across the replicator boundary as wire JSON. */
static int apply_all_ops(sb_replicator *source, sb_replicator *target, uint32_t count)
{
    for (uint32_t index = 0; index < count; index++) {
        const char *op = sb_replicator_op_json(source, index);
        if (op == NULL) {
            fail("sb_replicator_op_json");
            return 0;
        }
        int applied = sb_replicator_apply_remote_json(target, op);
        sb_free_string(op);
        if (applied != 1) {
            fail("the remote op applies once");
            return 0;
        }
    }
    return 1;
}

/* Two devices: the local one pulls two remote operations, then exports and
 * re-imports its committed state, and still holds both. */
static void scenario_restore_keeps_remote_data(void)
{
    sb_replicator *remote = sb_replicator_new("node-b", SB_STRATEGY_LWW_HLC);
    sb_replicator *local = sb_replicator_new("node-a", SB_STRATEGY_LWW_HLC);
    sb_identity *identity = sb_identity_generate();
    sb_receive_state *receive = sb_receive_state_new();
    expect(remote && local && identity && receive, "devices start");

    expect(sb_replicator_put(remote, "note/1", (const uint8_t *)"from b", 6) == SB_ERR_NONE,
           "remote writes one");
    expect(sb_replicator_put(remote, "note/2", (const uint8_t *)"also b", 6) == SB_ERR_NONE,
           "remote writes two");
    expect(apply_all_ops(remote, local, 2), "the local device pulled both ops");

    expect(sb_receive_state_server_cursor(receive, "relay-1", "channel-a", 2) == SB_ERR_NONE,
           "the pull position records where the channel stopped");
    expect(sb_receive_state_seen(receive, "msg-1") == SB_ERR_NONE, "the opened id is recorded");

    sb_buffer_t snapshot = { NULL, 0, 0 };
    expect(sb_state_export(local, identity, "group-9", 2, receive, &snapshot) == SB_ERR_NONE,
           "the committed state exports");
    expect(snapshot.len > 0, "the blob is not empty");

    sb_replicator *restored = NULL;
    sb_receive_state *restored_receive = NULL;
    expect(sb_state_import(snapshot.data, snapshot.len, SB_STRATEGY_LWW_HLC,
                           &restored, &restored_receive) == SB_ERR_NONE,
           "the blob imports");
    expect(restored && restored_receive, "both handles come back");

    /* Nothing that was committed before the snapshot was lost. */
    expect(sb_replicator_record_count(restored) == sb_replicator_record_count(local),
           "the record count survives");
    expect(sb_replicator_oplog_len(restored) == sb_replicator_oplog_len(local),
           "the oplog survives");
    const char *restored_json = sb_replicator_records_json(restored);
    const char *local_json = sb_replicator_records_json(local);
    expect(same_text(restored_json, local_json), "every record survives");
    sb_free_string(restored_json);
    sb_free_string(local_json);
    expect(same_text(sb_replicator_node_id(restored), "node-a"), "the node id survives");

    sb_buffer_t value = { NULL, 0, 0 };
    expect(sb_replicator_get(restored, "note/1", &value) == SB_ERR_NONE &&
               value.len == 6 && memcmp(value.data, "from b", 6) == 0,
           "the pulled record is still there");
    sb_free_buffer(&value);

    /* And the pull position still says the same thing. */
    uint64_t seq = 0;
    expect(sb_receive_state_server_seq(restored_receive, "relay-1", "channel-a", &seq) == SB_ERR_NONE &&
               seq == 2,
           "the server cursor survives");

    /* A redelivery of an already-seen op stays a no-op, so a restart does not
     * re-pull (and re-apply) the channel's history. */
    const char *again = sb_replicator_op_json(remote, 0);
    expect(again != NULL, "the remote op is readable");
    expect(again != NULL && sb_replicator_apply_remote_json(restored, again) == 0,
           "a redelivered op is deduplicated");
    sb_free_string(again);

    sb_free_buffer(&snapshot);
    sb_replicator_free(restored);
    sb_receive_state_free(restored_receive);
    sb_replicator_free(remote);
    sb_replicator_free(local);
    sb_receive_state_free(receive);
    sb_identity_free(identity);
}

/* The blob embeds the device's signing secret: the warning in the header is
 * not decorative, and a snapshot is private material to be guarded. */
static void scenario_the_snapshot_is_private_material(void)
{
    sb_replicator *replicator = sb_replicator_new("node-a", SB_STRATEGY_LWW_HLC);
    sb_identity *identity = sb_identity_generate();
    sb_receive_state *receive = sb_receive_state_new();
    sb_buffer_t snapshot = { NULL, 0, 0 };
    expect(sb_state_export(replicator, identity, "group-9", 1, receive, &snapshot) == SB_ERR_NONE,
           "a snapshot exports");

    uint8_t secret[64];
    expect(sb_identity_secret_key(identity, secret) == SB_ERR_NONE, "the identity exposes its key");
    char hex[129];
    for (int i = 0; i < 64; i++) {
        sprintf(hex + i * 2, "%02x", secret[i]);
    }
    expect(bytes_contains(snapshot.data, snapshot.len, hex, 128),
           "the snapshot really does carry the device secret");

    sb_free_buffer(&snapshot);
    sb_replicator_free(replicator);
    sb_receive_state_free(receive);
    sb_identity_free(identity);
}

/* Version and input validation: the wrong version and a malformed blob are
 * both refused, and the caller's out handles are left untouched. */
static void scenario_validation(void)
{
    sb_replicator *replicator = sb_replicator_new("node-a", SB_STRATEGY_LWW_HLC);
    sb_identity *identity = sb_identity_generate();
    sb_receive_state *receive = sb_receive_state_new();

    sb_replicator *out_replicator = NULL;
    sb_receive_state *out_receive = NULL;
    const char *wrong = "{\"version\":999,\"state\":{},\"receive\":{}}";
    expect(sb_state_import((const uint8_t *)wrong, strlen(wrong), SB_STRATEGY_LWW_HLC,
                           &out_replicator, &out_receive) == SB_ERR_INPUT &&
               sb_last_error_code() == SB_ERR_VERSION_MISMATCH,
           "a version from another format is refused");
    expect(out_replicator == NULL && out_receive == NULL, "a refused import writes no handle");

    const char *garbage = "not a snapshot";
    expect(sb_state_import((const uint8_t *)garbage, strlen(garbage), SB_STRATEGY_LWW_HLC,
                           &out_replicator, &out_receive) == SB_ERR_INPUT,
           "an unreadable blob is refused");
    expect(sb_state_import(NULL, 0, SB_STRATEGY_LWW_HLC, &out_replicator, &out_receive) == SB_ERR_INPUT,
           "a null blob is refused");

    sb_buffer_t snapshot = { NULL, 0, 0 };
    expect(sb_state_export(replicator, identity, "group-9", 0, receive, &snapshot) == SB_ERR_NONE,
           "a snapshot exports");
    expect(sb_state_export(NULL, identity, "group-9", 0, receive, &snapshot) == SB_ERR_INPUT,
           "a null replicator is refused");
    expect(sb_state_export(replicator, NULL, "group-9", 0, receive, &snapshot) == SB_ERR_INPUT,
           "a null identity is refused");
    expect(sb_state_export(replicator, identity, NULL, 0, receive, &snapshot) == SB_ERR_INPUT,
           "a null group id is refused");
    expect(sb_state_export(replicator, identity, "group-9", 0, NULL, &snapshot) == SB_ERR_INPUT,
           "a null receive state is refused");
    expect(sb_state_export(replicator, identity, "group-9", 0, receive, NULL) == SB_ERR_INPUT,
           "a null output buffer is refused");

    expect(sb_receive_state_server_cursor(NULL, "relay-1", "channel-a", 1) == SB_ERR_INPUT,
           "a null receive state is refused by the setters");
    expect(sb_receive_state_server_seq(receive, "relay-1", "channel-a", NULL) == SB_ERR_INPUT,
           "a null output sequence is refused");
    uint64_t absent = 0;
    expect(sb_receive_state_server_seq(receive, "relay-1", "channel-c", &absent) == SB_RESULT_ABSENT,
           "an unpulled channel reads absent");

    sb_free_buffer(&snapshot);
    sb_replicator_free(replicator);
    sb_receive_state_free(receive);
    sb_identity_free(identity);
}

int main(void)
{
    expect(sb_abi_version() == SYNCBOND_ABI_VERSION, "abi version matches header");
    scenario_restore_keeps_remote_data();
    scenario_the_snapshot_is_private_material();
    scenario_validation();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("state_snapshot: all checks passed\n");
    return 0;
}
