/* relay_driver.c - pure C consumer of the relay driver interface
 * (todo.md DSR-36).
 *
 * The driver owns the whole network session: URL, credential, the worker
 * thread and its runtime. A binding configures it, starts it, interleaves
 * writes while it runs, polls progress, and stops it - the relay protocol
 * never has to be rewritten in the binding. This program drives the
 * lifecycle against a deliberately dead endpoint (nothing listens on
 * 127.0.0.1:1), so it exercises construction, configuration, the worker
 * thread's start/stop lifecycle, progress and state export without needing
 * a live relay. Build with the flags used by tests/ffi_c.rs:
 *   gcc -Wall -Werror -o relay_driver examples/relay_driver.c \
 *       -I include -L <libdir> -lsyncbond_ffi -Wl,-rpath,<libdir> -lpthread
 */

#include "syncbond.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void expect(int condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

static void expect_status(int got, int want, const char *what)
{
    if (got != want) {
        fprintf(stderr, "FAIL: %s: got %d, want %d\n", what, got, want);
        failures++;
    }
}

static void scenario_configured_and_validated(void)
{
    /* Ownership transfers on failure too: fresh handles per attempt, freed
     * by the library when the call refuses them. */
    sb_identity *identity = sb_identity_generate();
    sb_keyring *keyring = sb_keyring_new("g");
    sb_replicator *replicator = sb_replicator_new("local", SB_STRATEGY_LWW_HLC);
    sb_receive_state *receive = sb_receive_state_new();

    sb_relay_driver *driver = sb_relay_driver_new(
        "http://127.0.0.1:1", "ch", "token", "relay-1", "c", "g", 1,
        identity, keyring, replicator, receive, 100, SB_TLS_VALIDATE, NULL, 0);
    expect(driver != NULL, "a dead endpoint still constructs");
    if (driver == NULL) {
        return;
    }

    expect_status(sb_relay_driver_config(driver, 0, 8, 1, 2, 1000, 1),
                  SB_ERR_INPUT, "a zero page limit is refused");
    expect_status(sb_relay_driver_config(driver, 2, 8, 1, 2, 1000, 1),
                  SB_ERR_NONE, "a fast config is accepted");

    /* Before the first start: quiet. */
    expect_status(sb_relay_driver_running(driver), 0, "not running yet");
    expect_status(sb_relay_driver_stop_reason(driver), SB_DRIVER_STOP_NONE,
                  "no stop reason yet");
    expect(sb_relay_driver_error(driver) == NULL, "no error text yet");

    sb_relay_driver_free(driver);
}

static void scenario_writes_and_state_export(void)
{
    sb_identity *identity = sb_identity_generate();
    sb_keyring *keyring = sb_keyring_new("g");
    sb_replicator *replicator = sb_replicator_new("local", SB_STRATEGY_LWW_HLC);
    sb_receive_state *receive = sb_receive_state_new();

    sb_relay_driver *driver = sb_relay_driver_new(
        "http://127.0.0.1:1", "ch", "token", "relay-1", "c", "g", 1,
        identity, keyring, replicator, receive, 100, SB_TLS_VALIDATE, NULL, 0);
    expect(driver != NULL, "driver for writes");
    if (driver == NULL) {
        return;
    }

    sb_buffer_t payload = {NULL, 0, 0};
    expect_status(sb_relay_driver_get(driver, "note/1", &payload),
                  SB_RESULT_ABSENT, "an absent key reads back ABSENT");
    expect_status(sb_relay_driver_write(driver, "note/1",
                                        (const uint8_t *)"one", 3),
                  SB_ERR_NONE, "write stages");
    expect_status(sb_relay_driver_get(driver, "note/1", &payload),
                  SB_ERR_NONE, "the staged write reads back");
    expect(payload.len == 3 && memcmp(payload.data, "one", 3) == 0,
           "the payload round-trips");
    sb_free_buffer(&payload);

    expect_status(sb_relay_driver_delete(driver, "note/1"), SB_ERR_NONE,
                  "delete stages");
    expect_status(sb_relay_driver_get(driver, "note/1", &payload),
                  SB_RESULT_ABSENT, "the tombstone wins");

    /* The same snapshot blob sb_state_export writes, from the driver's own
     * committed state. */
    sb_buffer_t snapshot = {NULL, 0, 0};
    expect_status(sb_relay_driver_export_state(driver, &snapshot),
                  SB_ERR_NONE, "state export");
    expect(snapshot.len > 0, "the snapshot is not empty");
    sb_replicator *restored = NULL;
    sb_receive_state *restored_receive = NULL;
    expect_status(sb_state_import(snapshot.data, snapshot.len,
                                  SB_STRATEGY_LWW_HLC, &restored,
                                  &restored_receive),
                  SB_ERR_NONE, "the snapshot re-imports");
    if (restored != NULL) {
        const char *node = sb_replicator_node_id(restored);
        expect(node != NULL && strcmp(node, "local") == 0,
               "the restored replicator is the same device");
    }
    sb_free_buffer(&snapshot);
    sb_replicator_free(restored);
    sb_receive_state_free(restored_receive);

    sb_relay_driver_free(driver);
}

static void scenario_start_progress_and_stop(void)
{
    sb_identity *identity = sb_identity_generate();
    sb_keyring *keyring = sb_keyring_new("g");
    sb_replicator *replicator = sb_replicator_new("local", SB_STRATEGY_LWW_HLC);
    sb_receive_state *receive = sb_receive_state_new();

    sb_relay_driver *driver = sb_relay_driver_new(
        "http://127.0.0.1:1", "ch", "token", "relay-1", "c", "g", 1,
        identity, keyring, replicator, receive, 100, SB_TLS_VALIDATE, NULL, 0);
    expect(driver != NULL, "driver for the lifecycle");
    if (driver == NULL) {
        return;
    }
    expect_status(sb_relay_driver_config(driver, 2, 8, 1, 2, 1000, 1),
                  SB_ERR_NONE, "a fast config is accepted");

    /* One worker thread starts once; a second start is refused. */
    expect_status(sb_relay_driver_start(driver), SB_ERR_NONE, "start");
    expect_status(sb_relay_driver_running(driver), 1, "the worker is up");
    expect_status(sb_relay_driver_start(driver), SB_ERR_INPUT,
                  "a second start is refused");

    /* Progress is queryable while the worker retries the dead endpoint. */
    sb_relay_progress_t progress = {9, 9, 9, 9, 9, 9};
    expect_status(sb_relay_driver_progress(driver, &progress), SB_ERR_NONE,
                  "progress fills");
    expect(progress.running == 1, "progress reports running");

    /* Writes interleave with the running worker: the cycle lock is released
     * between cycles, so this only waits out the current cycle. */
    expect_status(sb_relay_driver_write(driver, "mine/0",
                                        (const uint8_t *)"m0", 2),
                  SB_ERR_NONE, "write while running");
    sb_buffer_t payload = {NULL, 0, 0};
    expect_status(sb_relay_driver_get(driver, "mine/0", &payload), SB_ERR_NONE,
                  "the interleaved write reads back");
    sb_free_buffer(&payload);

    /* Stop cancels and joins the worker: the call returns only when the
     * thread is gone. */
    expect_status(sb_relay_driver_stop(driver), SB_ERR_NONE, "stop");
    expect_status(sb_relay_driver_running(driver), 0, "the worker joined");
    expect_status(sb_relay_driver_stop_reason(driver),
                  SB_DRIVER_STOP_CANCELLED, "the stop reason is cancellation");
    expect(sb_relay_driver_error(driver) == NULL,
           "a deliberate stop is clean: no error text");
    expect_status(sb_relay_driver_stop(driver), SB_ERR_NONE,
                  "stop is idempotent");

    /* The driver may start again after a stop. Freeing it while running
     * stops the worker first - the join must not hang. */
    expect_status(sb_relay_driver_start(driver), SB_ERR_NONE, "restart");
    expect_status(sb_relay_driver_running(driver), 1, "the worker is up again");
    sb_relay_driver_free(driver);
    sb_relay_driver_free(NULL);
}

int main(void)
{
    scenario_configured_and_validated();
    scenario_writes_and_state_export();
    scenario_start_progress_and_stop();

    if (failures == 0) {
        printf("relay_driver: all scenarios passed\n");
        return 0;
    }
    fprintf(stderr, "relay_driver: %d failure(s)\n", failures);
    return 1;
}
